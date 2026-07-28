//! Concurrent task runner that drives the extraction pipeline end-to-end.
//!
//! The runner enumerates initial archives and feeds them through a bounded task
//! scheduler. Completed extractions add any nested archives back to the pending
//! queue, while a single [`Reporter`] coordinates progress and aggregate stats.

use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use tokio::task::JoinSet;
use tracing::{debug, info};

use crate::error::AutoarcError;
use crate::extractors;
use crate::fs::{
    FileType, get_file_type, is_type_archive, is_type_document, is_type_video, relative_path,
    rename_video, video_rename_target,
};
use crate::progress::{Reporter, TaskReporter};

/// One archive extraction waiting to run.
#[derive(Debug, Clone)]
pub struct TaskParams {
    /// Path of the archive to extract.
    pub archive_path: PathBuf,
    /// Path of the *original* top-level archive that this work item descends from
    /// (used purely for human-readable labels in the progress UI).
    pub root: PathBuf,
}

impl TaskParams {
    /// Render a label like `foo.zip <- nested.7z` relative to `dir`.
    pub fn display(&self, dir: &Path) -> String {
        let rel_archive = relative_path(dir, &self.archive_path);
        let rel_root = relative_path(dir, &self.root);
        if rel_archive == rel_root {
            rel_archive.to_string_lossy().to_string()
        } else {
            format!(
                "{} <- {}",
                rel_archive.to_string_lossy(),
                rel_root.to_string_lossy()
            )
        }
    }
}

/// Top-level entry point invoked by the binary for the `autoarc autoarc <DIR>` subcommand.
///
/// `max_depth` controls how deep the initial directory scan walks. `1` only
/// inspects the immediate contents of `dir` (the historical behaviour);
/// `usize::MAX` means unlimited. Note that this only affects the **initial**
/// scan: any nested archives produced by extraction itself are always queued
/// recursively regardless of `max_depth`.
///
/// `dry_run` prints the planned work and exits without touching the filesystem.
/// `yes` skips the interactive `[y/N]` confirmation prompt (the prompt is also
/// skipped automatically when stdin is not a TTY, e.g. in CI).
///
/// `jobs` caps how many archives may be extracted in parallel. `0` means
/// "auto" — fall back to [`std::thread::available_parallelism`] (else `4`).
/// Use `1` for strictly sequential extraction.
///
/// `ignore_patterns` is a list of glob patterns compiled once into an
/// [`IgnoreFilter`]. Paths matching any pattern are pruned from the
/// **initial** scan (directories are pruned along with their entire
/// subtree). Invalid globs surface as [`AutoarcError::Other`] before any
/// extraction work begins.
pub async fn run(
    dir: PathBuf,
    max_depth: usize,
    dry_run: bool,
    yes: bool,
    jobs: usize,
    ignore_patterns: Vec<String>,
) -> Result<()> {
    use std::io::IsTerminal;

    // Compile the --ignore globs once; invalid patterns abort before any
    // async setup so the user gets a fast, clear error.
    let ignore = IgnoreFilter::new(&ignore_patterns)?;

    // Phase 1 — scan: pure read pass, classifies every file.
    let scan_result = scan(&dir, max_depth, &ignore)?;

    // Phase 2 — plan: fuse multi-volume parts into single logical entries.
    let plan = build_plan(scan_result.archives);

    if plan.is_empty() && scan_result.videos.is_empty() && scan_result.others.is_empty() {
        println!("No archives or media files found in {}", dir.display());
        return Ok(());
    }

    // Phase 3 — render: show the user what will happen.
    print_plan(
        &plan,
        &scan_result.videos,
        &scan_result.others,
        &dir,
        max_depth,
    );

    if dry_run {
        return Ok(());
    }

    if !yes && std::io::stdin().is_terminal() && !prompt_continue()? {
        println!("Aborted.");
        return Ok(());
    }

    // Phase 4 — execute: rename videos and emit one TaskParams per plan item.
    //
    // Archives are always extracted in place: each extractor writes into a
    // sibling `{complete_filename}_out/` directory (e.g. `foo.zip`
    // → `foo.zip_out/`, `foo.7z` → `foo.7z_out/`). We don't move or back up
    // the originals — that's the user's call.
    let initial_tasks = execute(plan, scan_result.videos)?;
    debug!("initial tasks: {initial_tasks:?}");

    if initial_tasks.is_empty() {
        // All work was video renames; nothing left to extract.
        return Ok(());
    }

    let reporter = Reporter::new(initial_tasks.len());
    crate::progress::init_tracing(&reporter);

    // Resolve the effective parallelism cap.
    let effective_jobs = resolve_jobs(jobs);
    info!("extracting with up to {effective_jobs} parallel job(s) (requested = {jobs}, 0 = auto)");
    run_task_queue(
        initial_tasks,
        &dir,
        effective_jobs,
        &reporter,
        |task, task_reporter| {
            let file_type = get_file_type(&task.archive_path);
            let result = extractors::run(file_type, task.archive_path, task.root, &task_reporter);
            if result.is_ok() {
                task_reporter.finish_ok();
            }
            result
        },
    )
    .await;
    info!("all tasks finished");

    let failed = reporter.finish_summary();

    if failed > 0 {
        return Err(AutoarcError::Other(format!("{failed} archive task(s) failed")).into());
    }
    Ok(())
}

/// Drive a dynamically growing work queue with at most `jobs` blocking tasks.
///
/// The scheduler owns both lifecycle states: `pending` contains work that has
/// not started, and `running` contains every spawned task. A completed task may
/// return more work, which is appended to `pending`. The queue is exhausted
/// exactly when both collections are empty, so no auxiliary counters or
/// shutdown notifications are needed.
async fn run_task_queue<F>(
    initial_tasks: Vec<TaskParams>,
    dir: &Path,
    jobs: NonZeroUsize,
    reporter: &Reporter,
    worker: F,
) where
    F: Fn(TaskParams, TaskReporter) -> Result<Vec<TaskParams>> + Send + Sync + 'static,
{
    let mut pending: VecDeque<_> = initial_tasks.into();
    let mut running = JoinSet::new();
    let mut labels = HashMap::new();
    let worker = Arc::new(worker);

    while !pending.is_empty() || !running.is_empty() {
        while running.len() < jobs.get() {
            let Some(task) = pending.pop_front() else {
                break;
            };

            let label = task.display(dir);
            let task_reporter = reporter.task(label.clone());
            let worker = Arc::clone(&worker);
            let handle = running.spawn_blocking(move || worker(task, task_reporter));
            let previous_label = labels.insert(handle.id(), label);
            debug_assert!(previous_label.is_none());
        }

        let completed = running
            .join_next_with_id()
            .await
            .expect("non-empty task set must yield a completion");
        let task_id = match &completed {
            Ok((task_id, _)) => *task_id,
            Err(error) => error.id(),
        };
        let label = labels
            .remove(&task_id)
            .unwrap_or_else(|| format!("archive task {task_id}"));

        match completed {
            Ok((_, Ok(new_tasks))) => {
                reporter.task_succeeded();
                if !new_tasks.is_empty() {
                    reporter.task_added(new_tasks.len());
                    pending.extend(new_tasks);
                }
            }
            Ok((_, Err(error))) => reporter.task_failed(&label, &error),
            Err(error) => reporter.task_failed(&label, &error),
        }
    }

    debug_assert!(labels.is_empty());
}

// ============================================================================
// Jobs resolution: CLI flag > available_parallelism > 4.
// ============================================================================

/// Resolve the effective `--jobs` value, following the precedence:
///
/// 1. If `cli_jobs > 0`, use it verbatim.
/// 2. Otherwise fall back to [`std::thread::available_parallelism`].
/// 3. If even that fails, use a hard-coded `4`.
///
/// The non-zero return type makes the scheduler's progress invariant explicit:
/// whenever pending work exists, at least one task can be spawned.
///
/// Parallelism is deliberately **not** configurable through an environment
/// variable: it's a per-invocation tuning knob (unlike persistent secrets
/// such as `AUTOARC_PASSWORDS`), so it lives on the CLI only.
fn resolve_jobs(cli_jobs: usize) -> NonZeroUsize {
    if let Some(jobs) = NonZeroUsize::new(cli_jobs) {
        return jobs;
    }
    std::thread::available_parallelism()
        .unwrap_or_else(|_| NonZeroUsize::new(4).expect("fallback parallelism is non-zero"))
}

// ============================================================================
// Phase 1: scan — pure read pass that classifies files without touching them.
// ============================================================================

/// Compiled set of `--ignore` glob patterns.
///
/// [`IgnoreFilter::new`] with an empty slice yields an inactive filter whose
/// [`IgnoreFilter::is_ignored`] short-circuits — so the common case of "no
/// `--ignore`" pays nothing. Active filters use `literal_separator(true)`,
/// meaning `*` stays within a single path component and only `**` crosses `/`.
#[derive(Debug)]
struct IgnoreFilter(Option<globset::GlobSet>);

impl IgnoreFilter {
    /// Compile every pattern; the first invalid one bails out with
    /// [`AutoarcError::Other`].
    fn new(patterns: &[String]) -> Result<Self, AutoarcError> {
        if patterns.is_empty() {
            return Ok(Self(None));
        }
        let mut builder = globset::GlobSetBuilder::new();
        for p in patterns {
            let glob = globset::GlobBuilder::new(p)
                .literal_separator(true)
                .build()
                .map_err(|e| AutoarcError::Other(format!("invalid --ignore glob {p:?}: {e}")))?;
            builder.add(glob);
        }
        let set = builder
            .build()
            .map_err(|e| AutoarcError::Other(format!("failed to compile --ignore set: {e}")))?;
        Ok(Self(Some(set)))
    }

    /// True when `path` (relative to the scan root `dir`) matches any pattern.
    fn is_ignored(&self, dir: &Path, path: &Path) -> bool {
        match &self.0 {
            None => false,
            Some(set) => set.is_match(relative_path(dir, path)),
        }
    }
}

/// One archive file discovered during the scan.
#[derive(Debug, Clone)]
struct ScanItem {
    path: PathBuf,
    #[allow(dead_code)]
    // kept for future kind-aware grouping; currently re-derived at execute time.
    kind: FileType,
}

/// Outcome of [`scan`]: archives that need extraction + videos that need a
/// rename + other recognised media (audio / pdf / office / text) that are
/// merely reported to the user so the scan surface isn't purely video-centric.
struct ScanResult {
    archives: Vec<ScanItem>,
    videos: Vec<(PathBuf, FileType)>,
    others: Vec<(PathBuf, FileType)>,
}

/// Walk `target_dir` (respecting `max_depth`) and classify every file.
///
/// This pass performs **no filesystem mutations** so it is safe to run in
/// dry-run mode and to surface to the user for confirmation.
fn scan(target_dir: &Path, max_depth: usize, ignore: &IgnoreFilter) -> Result<ScanResult> {
    if max_depth <= 1 {
        scan_top_level(target_dir, ignore)
    } else {
        scan_recursive(target_dir, max_depth, ignore)
    }
}

/// Top-level scan: only the immediate contents of `target_dir`.
fn scan_top_level(target_dir: &Path, ignore: &IgnoreFilter) -> Result<ScanResult> {
    let mut result = ScanResult {
        archives: Vec::new(),
        videos: Vec::new(),
        others: Vec::new(),
    };

    let entries =
        std::fs::read_dir(target_dir).map_err(|e| AutoarcError::io(target_dir.to_path_buf(), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| AutoarcError::io(target_dir.to_path_buf(), e))?;
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let path = entry.path();
        if ignore.is_ignored(target_dir, &path) {
            continue;
        }
        let kind = get_file_type(&path);
        if is_type_archive(kind) {
            result.archives.push(ScanItem { path, kind });
        } else if is_type_video(kind) {
            result.videos.push((path, kind));
        } else if is_type_document(kind) {
            result.others.push((path, kind));
        }
    }
    Ok(result)
}

/// Recursive scan: walk up to `max_depth` directory levels, pruning our own
/// `*_out` artefact directories from the walk.
fn scan_recursive(
    target_dir: &Path,
    max_depth: usize,
    ignore: &IgnoreFilter,
) -> Result<ScanResult> {
    use walkdir::WalkDir;

    let mut result = ScanResult {
        archives: Vec::new(),
        videos: Vec::new(),
        others: Vec::new(),
    };

    let walker = WalkDir::new(target_dir)
        .max_depth(max_depth)
        .min_depth(1)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            // --ignore has first say: a matched directory prunes its whole
            // subtree, a matched file is simply skipped.
            if ignore.is_ignored(target_dir, e.path()) {
                return false;
            }
            if e.file_type().is_dir() {
                let name = e.file_name().to_string_lossy();
                !name.ends_with("_out")
            } else {
                true
            }
        });

    for entry in walker {
        let entry = entry
            .map_err(|e| AutoarcError::Other(format!("walkdir error under {target_dir:?}: {e}")))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.into_path();
        let kind = get_file_type(&path);
        if is_type_archive(kind) {
            result.archives.push(ScanItem { path, kind });
        } else if is_type_video(kind) {
            result.videos.push((path, kind));
        } else if is_type_document(kind) {
            result.others.push((path, kind));
        }
    }
    Ok(result)
}

// ============================================================================
// Phase 2: plan — group multi-volume parts into single logical entries.
// ============================================================================

/// One row in the user-facing extraction plan.
#[derive(Debug, Clone)]
struct PlanItem {
    /// The path that will be passed to the extractor (e.g. the `.z01` for
    /// ZIP multi-volume sets).
    primary: PathBuf,
    /// All filesystem files belonging to this logical archive (≥ 1).
    parts: Vec<PathBuf>,
    /// Total bytes across all `parts`.
    total_size: u64,
    /// True when `parts.len() > 1` — the archive spans multiple volume files.
    is_multi_volume: bool,
}

/// Group scan items into plan items, fusing multi-volume sets into a single
/// row and de-duplicating sibling parts that the scan classified independently
/// (e.g. both `foo.zip` and `foo.z01` showing up as separate ScanItems).
fn build_plan(archives: Vec<ScanItem>) -> Vec<PlanItem> {
    use std::collections::HashSet;

    let mut absorbed: HashSet<PathBuf> = HashSet::new();
    let mut plan = Vec::new();

    // Sort for deterministic plan output.
    let mut sorted = archives;
    sorted.sort_by(|a, b| a.path.cmp(&b.path));

    for item in &sorted {
        if absorbed.contains(&item.path) {
            continue;
        }

        if let Some(parts) = discover_volume_parts(&item.path) {
            // Pick the primary the runtime should hand to the extractor.
            // Preference order: .z01 > .001 > .zip > whatever sorted first.
            let primary = parts
                .iter()
                .find(|p| has_ext(p, "z01"))
                .or_else(|| parts.iter().find(|p| has_ext(p, "001")))
                .or_else(|| parts.iter().find(|p| has_ext(p, "zip")))
                .cloned()
                .unwrap_or_else(|| parts[0].clone());
            let total_size: u64 = parts
                .iter()
                .filter_map(|p| std::fs::metadata(p).ok().map(|m| m.len()))
                .sum();
            for p in &parts {
                absorbed.insert(p.clone());
            }
            plan.push(PlanItem {
                primary,
                parts,
                total_size,
                is_multi_volume: true,
            });
        } else {
            let size = std::fs::metadata(&item.path).map(|m| m.len()).unwrap_or(0);
            absorbed.insert(item.path.clone());
            plan.push(PlanItem {
                primary: item.path.clone(),
                parts: vec![item.path.clone()],
                total_size: size,
                is_multi_volume: false,
            });
        }
    }

    plan
}

/// If `primary` looks like one part of a multi-volume set, scan its parent
/// directory for siblings and return the full part list (including `primary`).
///
/// Returns `None` for solo archives (the caller should treat them as standalone).
fn discover_volume_parts(primary: &Path) -> Option<Vec<PathBuf>> {
    let parent = primary.parent()?;
    let name = primary.file_name()?.to_str()?;
    let lower = name.to_ascii_lowercase();
    let siblings = sibling_paths_by_lowercase_name(parent)?;

    // ZIP-style multi-volume: foo.zip + foo.z01 + foo.z02 + ... + foo.zNN.
    let zip_stem_len = lower
        .strip_suffix(".zip")
        .or_else(|| lower.strip_suffix(".z01"))
        .map(|s| s.len());
    if let Some(stem_len) = zip_stem_len {
        let stem_orig = &name[..stem_len];
        let mut parts = Vec::new();
        let zip_name = format!("{stem_orig}.zip").to_ascii_lowercase();
        if let Some(zip_path) = siblings.get(&zip_name) {
            parts.push(zip_path.clone());
        }
        for n in 1..=99 {
            let z_name = format!("{stem_orig}.z{n:02}").to_ascii_lowercase();
            if let Some(z) = siblings.get(&z_name) {
                parts.push(z.clone());
            } else if n > 1 {
                break;
            }
        }
        if parts.len() > 1 {
            return Some(parts);
        }
    }

    // Generic numeric splits: foo.001 + foo.002 + ..., or foo.7z.001 + foo.7z.002 + ...
    if let Some(stem_len) = lower.strip_suffix(".001").map(|s| s.len()) {
        let stem_orig = &name[..stem_len];
        let mut parts = Vec::new();
        for n in 1..=999 {
            let part_name = format!("{stem_orig}.{n:03}").to_ascii_lowercase();
            if let Some(p) = siblings.get(&part_name) {
                parts.push(p.clone());
            } else if n > 1 {
                break;
            }
        }
        if parts.len() > 1 {
            return Some(parts);
        }
    }

    None
}

/// Enumerate sibling files once and retain their actual on-disk casing.
fn sibling_paths_by_lowercase_name(
    parent: &Path,
) -> Option<std::collections::HashMap<String, PathBuf>> {
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let mut siblings = std::collections::HashMap::new();
    for entry in std::fs::read_dir(parent).ok()? {
        let Ok(entry) = entry else {
            continue;
        };
        if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
            continue;
        }
        let filename = entry.file_name();
        let Some(name) = filename.to_str() else {
            continue;
        };
        let name = name.to_ascii_lowercase();
        siblings.entry(name).or_insert_with(|| entry.path());
    }
    Some(siblings)
}

/// Case-insensitive extension check.
fn has_ext(path: &Path, ext: &str) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

// ============================================================================
// Phase 3: render — print the plan and (optionally) prompt the user.
// ============================================================================

/// Print a human-readable extraction plan to stdout.
fn print_plan(
    plan: &[PlanItem],
    videos: &[(PathBuf, FileType)],
    others: &[(PathBuf, FileType)],
    dir: &Path,
    max_depth: usize,
) {
    use console::style;
    use indicatif::HumanBytes;

    let multi_count = plan.iter().filter(|p| p.is_multi_volume).count();
    let total_bytes: u64 = plan.iter().map(|p| p.total_size).sum();
    let depth_note = if max_depth == usize::MAX {
        "recursive".to_string()
    } else {
        format!("depth={max_depth}")
    };

    println!(
        "{} {} archives ({} multi-volume), {} total \u{2014} {} ({})",
        style("Plan:").bold().cyan(),
        plan.len(),
        multi_count,
        HumanBytes(total_bytes),
        dir.display(),
        depth_note,
    );

    let max_label = plan
        .iter()
        .map(|p| {
            relative_path(dir, &p.primary)
                .to_string_lossy()
                .chars()
                .count()
        })
        .max()
        .unwrap_or(0);

    for item in plan {
        let kind_tag = match get_file_type(&item.primary) {
            FileType::Zip => "zip",
            FileType::Rar => "rar",
            FileType::SevenZ => "7z",
            FileType::Multi => "multi",
            FileType::Sfx => "sfx",
            _ => "?",
        };
        let rel = relative_path(dir, &item.primary);
        let label = rel.to_string_lossy();
        let pad = max_label.saturating_sub(label.chars().count());
        let spacer = " ".repeat(pad);
        let suffix = if item.is_multi_volume {
            format!(", {} parts", item.parts.len())
        } else {
            String::new()
        };
        println!(
            "  [{:<5}] {}{}  ({}{})",
            style(kind_tag).yellow(),
            label,
            spacer,
            HumanBytes(item.total_size),
            suffix,
        );
    }

    if !videos.is_empty() {
        println!(
            "\n{} {} video file(s) will be renamed in place.",
            style("Note:").dim(),
            videos.len()
        );
    }
    if !others.is_empty() {
        let mut counts: [(FileType, &str, usize); 6] = [
            (FileType::Audio, "audio", 0),
            (FileType::Pdf, "pdf", 0),
            (FileType::Docx, "docx", 0),
            (FileType::Pptx, "pptx", 0),
            (FileType::Xlsx, "xlsx", 0),
            (FileType::Text, "text", 0),
        ];
        for (_, kind) in others {
            if let Some(slot) = counts.iter_mut().find(|(k, _, _)| *k == *kind) {
                slot.2 += 1;
            }
        }
        let breakdown: Vec<String> = counts
            .iter()
            .filter(|(_, _, n)| *n > 0)
            .map(|(_, tag, n)| format!("{n} {tag}"))
            .collect();
        println!(
            "{} {} media file(s) detected ({}) \u{2014} reported only, not modified.",
            style("Note:").dim(),
            others.len(),
            breakdown.join(", "),
        );
    }
    println!();
}

/// Read a Y/n answer from stdin. Returns `Ok(false)` only when the user typed
/// `n` or `no` (case-insensitive). Anything else — including just pressing
/// Enter — defaults to `true`.
fn prompt_continue() -> Result<bool> {
    use std::io::{BufRead, Write};

    print!("Continue? [Y/n] ");
    std::io::stdout()
        .flush()
        .map_err(|e| AutoarcError::Other(format!("flush stdout: {e}")))?;

    let mut buf = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut buf)
        .map_err(|e| AutoarcError::Other(format!("read stdin: {e}")))?;

    Ok(!matches!(
        buf.trim().to_ascii_lowercase().as_str(),
        "n" | "no"
    ))
}

// ============================================================================
// Phase 4: execute — mutate the filesystem and produce TaskParams.
// ============================================================================

/// Apply the plan: rename any detected videos in place and emit one
/// [`TaskParams`] per logical archive for the runner to consume.
///
/// Archives are **not** moved — each extractor writes into a sibling
/// `{complete_filename}_out/` directory (`foo.zip` → `foo.zip_out/`),
/// keeping originals exactly where the user put them.
fn execute(plan: Vec<PlanItem>, videos: Vec<(PathBuf, FileType)>) -> Result<Vec<TaskParams>> {
    let tasks = plan
        .into_iter()
        .map(|item| TaskParams {
            archive_path: item.primary.clone(),
            root: item.primary,
        })
        .collect();

    // Validate the entire rename set before mutating anything so a conflict
    // cannot leave half the top-level videos renamed.
    let mut rename_targets = std::collections::HashMap::new();
    for (path, kind) in &videos {
        let Some(target) = video_rename_target(path, *kind) else {
            continue;
        };
        if target.exists()
            || rename_targets
                .insert(target.clone(), path.clone())
                .is_some()
        {
            return Err(AutoarcError::OutputCollision(target).into());
        }
    }

    for (path, kind) in videos {
        rename_video(&path, kind)?;
    }

    Ok(tasks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tempfile::TempDir;

    fn task(name: impl Into<PathBuf>) -> TaskParams {
        let archive_path = name.into();
        TaskParams {
            root: archive_path.clone(),
            archive_path,
        }
    }

    // --- resolve_jobs --------------------------------------------------------

    #[test]
    fn resolve_jobs_returns_cli_value_verbatim_when_positive() {
        assert_eq!(resolve_jobs(1).get(), 1);
        assert_eq!(resolve_jobs(3).get(), 3);
        assert_eq!(resolve_jobs(99).get(), 99);
    }

    #[test]
    fn resolve_jobs_zero_falls_back_to_available_parallelism() {
        let n = resolve_jobs(0);
        // Must match what std reports directly since that's the documented
        // auto-path.
        let expected =
            std::thread::available_parallelism().unwrap_or_else(|_| NonZeroUsize::new(4).unwrap());
        assert_eq!(n, expected);
    }

    #[test]
    fn resolve_jobs_ignores_autoarc_jobs_env_var() {
        // AUTOARC_JOBS is intentionally *not* consulted — parallelism is a
        // per-invocation knob, not a persistent secret. Even when the env
        // var is set to something silly, the CLI path must still win.
        // SAFETY: single-threaded set_var is fine for this short assertion.
        unsafe { std::env::set_var("AUTOARC_JOBS", "999") };
        assert_eq!(
            resolve_jobs(2).get(),
            2,
            "CLI flag must override any env var"
        );
        let auto = resolve_jobs(0);
        assert_ne!(
            auto.get(),
            999,
            "auto path must not read AUTOARC_JOBS (saw 999, that's the env leak)"
        );
        unsafe { std::env::remove_var("AUTOARC_JOBS") };
    }

    // --- bounded task scheduler ---------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn task_queue_never_exceeds_job_limit() {
        const JOBS: usize = 3;
        const TASKS: usize = 18;

        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let reporter = Reporter::new(TASKS);
        let tasks = (0..TASKS)
            .map(|index| task(format!("{index}.zip")))
            .collect();

        let active_for_worker = Arc::clone(&active);
        let max_for_worker = Arc::clone(&max_active);
        let completed_for_worker = Arc::clone(&completed);
        run_task_queue(
            tasks,
            Path::new("."),
            NonZeroUsize::new(JOBS).unwrap(),
            &reporter,
            move |_task, _task_reporter| {
                let now = active_for_worker.fetch_add(1, Ordering::SeqCst) + 1;
                max_for_worker.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(20));
                active_for_worker.fetch_sub(1, Ordering::SeqCst);
                completed_for_worker.fetch_add(1, Ordering::SeqCst);
                Ok(Vec::new())
            },
        )
        .await;

        assert_eq!(completed.load(Ordering::SeqCst), TASKS);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(max_active.load(Ordering::SeqCst), JOBS);
        assert_eq!(reporter.finish_summary(), 0);
    }

    #[tokio::test]
    async fn task_queue_processes_nested_tasks_and_terminates() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_for_worker = Arc::clone(&seen);
        let reporter = Reporter::new(1);

        let run = run_task_queue(
            vec![task("root.zip")],
            Path::new("."),
            NonZeroUsize::new(2).unwrap(),
            &reporter,
            move |task, _task_reporter| {
                let name = task
                    .archive_path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                seen_for_worker.lock().unwrap().push(name.clone());

                if name == "root.zip" {
                    Ok(vec![
                        TaskParams {
                            archive_path: PathBuf::from("child-a.7z"),
                            root: task.root.clone(),
                        },
                        TaskParams {
                            archive_path: PathBuf::from("child-b.rar"),
                            root: task.root,
                        },
                    ])
                } else {
                    Ok(Vec::new())
                }
            },
        );

        tokio::time::timeout(Duration::from_secs(1), run)
            .await
            .expect("dynamic queue should terminate without a separate shutdown signal");

        let mut seen = seen.lock().unwrap().clone();
        seen.sort();
        assert_eq!(seen, ["child-a.7z", "child-b.rar", "root.zip"]);
        assert_eq!(reporter.finish_summary(), 0);
    }

    #[tokio::test]
    async fn task_queue_reports_panics_without_stranding_other_work() {
        let completed = Arc::new(AtomicUsize::new(0));
        let completed_for_worker = Arc::clone(&completed);
        let reporter = Reporter::new(2);

        let run = run_task_queue(
            vec![task("panic.zip"), task("ok.zip")],
            Path::new("."),
            NonZeroUsize::new(2).unwrap(),
            &reporter,
            move |task, _task_reporter| {
                if task.archive_path == Path::new("panic.zip") {
                    panic!("synthetic worker panic");
                }
                completed_for_worker.fetch_add(1, Ordering::SeqCst);
                Ok(Vec::new())
            },
        );

        tokio::time::timeout(Duration::from_secs(1), run)
            .await
            .expect("a worker panic must not strand the task queue");

        assert_eq!(completed.load(Ordering::SeqCst), 1);
        assert_eq!(reporter.finish_summary(), 1);
    }

    // --- has_ext -------------------------------------------------------------

    #[test]
    fn has_ext_is_case_insensitive() {
        assert!(has_ext(Path::new("foo.ZIP"), "zip"));
        assert!(has_ext(Path::new("foo.zip"), "ZIP"));
        assert!(has_ext(Path::new("a/b/c.7Z"), "7z"));
    }

    #[test]
    fn has_ext_rejects_mismatches_and_missing() {
        assert!(!has_ext(Path::new("foo.rar"), "zip"));
        assert!(!has_ext(Path::new("foo"), "zip"));
        // `has_ext` only looks at the final extension, not suffixes.
        assert!(!has_ext(Path::new("foo.7z.001"), "7z"));
        assert!(has_ext(Path::new("foo.7z.001"), "001"));
    }

    // --- TaskParams::display -------------------------------------------------

    #[test]
    fn display_shows_single_label_when_archive_equals_root() {
        let task = TaskParams {
            archive_path: PathBuf::from("/work/foo.zip"),
            root: PathBuf::from("/work/foo.zip"),
        };
        assert_eq!(task.display(Path::new("/work")), "foo.zip");
    }

    #[test]
    fn display_shows_nested_arrow_when_descending_from_parent() {
        let task = TaskParams {
            archive_path: PathBuf::from("/work/foo.zip_out/inner.7z"),
            root: PathBuf::from("/work/foo.zip"),
        };
        assert_eq!(
            task.display(Path::new("/work")),
            "foo.zip_out/inner.7z <- foo.zip"
        );
    }

    // --- discover_volume_parts -----------------------------------------------

    /// Create an empty file at `dir/name`.
    fn touch(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::File::create(&p).unwrap();
        p
    }

    /// Create a file at `dir/name` with `size` bytes of zero payload.
    fn touch_sized(dir: &Path, name: &str, size: usize) -> PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(&vec![0u8; size]).unwrap();
        p
    }

    #[test]
    fn discover_returns_none_for_solo_archive() {
        let td = TempDir::new().unwrap();
        let p = touch(td.path(), "solo.zip");
        assert!(discover_volume_parts(&p).is_none());
    }

    #[test]
    fn discover_groups_zip_plus_z01_z02() {
        let td = TempDir::new().unwrap();
        let zip = touch(td.path(), "multi.zip");
        let z01 = touch(td.path(), "multi.z01");
        let z02 = touch(td.path(), "multi.z02");

        // The function only anchors on `.zip` / `.z01` (the two names that
        // sort first in a real scan), not arbitrary `.zNN`, so we only test
        // those two entry points.
        for entry_point in [&zip, &z01] {
            let parts = discover_volume_parts(entry_point).expect("should detect multi-volume");
            assert_eq!(parts.len(), 3);
            assert!(parts.contains(&zip));
            assert!(parts.contains(&z01));
            assert!(parts.contains(&z02));
        }
    }

    #[test]
    fn discover_groups_numeric_001_002_003() {
        let td = TempDir::new().unwrap();
        let a = touch(td.path(), "pack.001");
        let b = touch(td.path(), "pack.002");
        let c = touch(td.path(), "pack.003");

        let parts = discover_volume_parts(&a).expect("should detect .001 split");
        assert_eq!(parts, vec![a, b, c]);
    }

    #[test]
    fn discover_groups_7z_dot_001_splits() {
        // Regression: .7z.001 / .7z.002 must be fused so the extractor receives
        // a single multi-volume plan item (not two separate 7z tasks).
        let td = TempDir::new().unwrap();
        let a = touch(td.path(), "data.7z.001");
        let b = touch(td.path(), "data.7z.002");

        let parts = discover_volume_parts(&a).expect("should detect .7z.001 split");
        assert_eq!(parts, vec![a, b]);
    }

    #[test]
    fn discover_handles_case_insensitive_extensions() {
        let td = TempDir::new().unwrap();
        // Retain actual paths so this works on case-sensitive filesystems too.
        let zip = touch(td.path(), "MIX.ZIP");
        let z01 = touch(td.path(), "MIX.Z01");

        let entry = td.path().join("MIX.ZIP");
        let parts = discover_volume_parts(&entry).expect("should handle upper-case .ZIP");
        assert_eq!(parts, vec![zip, z01]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unrelated_non_utf8_sibling_does_not_disable_volume_discovery() {
        use std::os::unix::ffi::OsStringExt;

        let td = TempDir::new().unwrap();
        let zip = touch(td.path(), "multi.zip");
        let z01 = touch(td.path(), "multi.z01");
        let odd_name = std::ffi::OsString::from_vec(vec![0xff, 0xfe]);
        std::fs::File::create(td.path().join(odd_name)).unwrap();

        let parts = discover_volume_parts(&zip).expect("should ignore unrelated non-UTF8 names");
        assert_eq!(parts, vec![zip, z01]);
    }

    // --- build_plan ----------------------------------------------------------

    #[test]
    fn build_plan_sums_sizes_and_deduplicates_multi_volume_siblings() {
        let td = TempDir::new().unwrap();
        // 3 parts, 10 + 20 + 30 = 60 bytes total.
        let zip = touch_sized(td.path(), "set.zip", 10);
        let z01 = touch_sized(td.path(), "set.z01", 20);
        let z02 = touch_sized(td.path(), "set.z02", 30);

        // Scan surfaces every file individually; plan must collapse them into 1.
        let archives = vec![
            ScanItem {
                path: zip.clone(),
                kind: FileType::Zip,
            },
            ScanItem {
                path: z01.clone(),
                kind: FileType::Multi,
            },
            ScanItem {
                path: z02.clone(),
                kind: FileType::Zip,
            },
        ];

        let plan = build_plan(archives);
        assert_eq!(plan.len(), 1, "multi-volume parts must collapse to 1 item");
        let item = &plan[0];
        assert!(item.is_multi_volume);
        assert_eq!(item.parts.len(), 3);
        assert_eq!(item.total_size, 60);
        // Preference order prefers .z01 as the primary handed to the extractor.
        assert_eq!(item.primary, z01);
    }

    #[test]
    fn build_plan_prefers_001_as_primary_for_numeric_splits() {
        let td = TempDir::new().unwrap();
        let a = touch_sized(td.path(), "x.001", 5);
        let b = touch_sized(td.path(), "x.002", 5);

        let plan = build_plan(vec![
            ScanItem {
                path: a.clone(),
                kind: FileType::Multi,
            },
            ScanItem {
                path: b.clone(),
                kind: FileType::Multi,
            },
        ]);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].primary, a);
    }

    #[test]
    fn build_plan_keeps_unrelated_archives_separate() {
        let td = TempDir::new().unwrap();
        let a = touch_sized(td.path(), "one.zip", 11);
        let b = touch_sized(td.path(), "two.rar", 22);

        let plan = build_plan(vec![
            ScanItem {
                path: a.clone(),
                kind: FileType::Zip,
            },
            ScanItem {
                path: b.clone(),
                kind: FileType::Rar,
            },
        ]);
        assert_eq!(plan.len(), 2);
        assert!(plan.iter().all(|p| !p.is_multi_volume));
        let total: u64 = plan.iter().map(|p| p.total_size).sum();
        assert_eq!(total, 33);
    }

    #[test]
    fn build_plan_treats_solo_zip_as_standalone_even_without_siblings() {
        let td = TempDir::new().unwrap();
        let lone = touch_sized(td.path(), "lone.zip", 7);

        let plan = build_plan(vec![ScanItem {
            path: lone.clone(),
            kind: FileType::Zip,
        }]);
        assert_eq!(plan.len(), 1);
        assert!(!plan[0].is_multi_volume);
        assert_eq!(plan[0].parts, vec![lone]);
    }

    // --- execute -------------------------------------------------------------

    #[test]
    fn execute_emits_one_task_per_plan_item_with_primary_as_root() {
        let td = TempDir::new().unwrap();
        let zip = touch_sized(td.path(), "a.zip", 1);
        let sevenz = touch_sized(td.path(), "b.7z", 1);

        let plan = vec![
            PlanItem {
                primary: zip.clone(),
                parts: vec![zip.clone()],
                total_size: 1,
                is_multi_volume: false,
            },
            PlanItem {
                primary: sevenz.clone(),
                parts: vec![sevenz.clone()],
                total_size: 1,
                is_multi_volume: false,
            },
        ];

        let tasks = execute(plan, Vec::new()).unwrap();
        assert_eq!(tasks.len(), 2);
        // root == archive_path at the top level so display() collapses to a single label.
        assert_eq!(tasks[0].archive_path, zip);
        assert_eq!(tasks[0].root, zip);
        assert_eq!(tasks[1].archive_path, sevenz);
        assert_eq!(tasks[1].root, sevenz);
    }

    #[test]
    fn execute_rejects_video_target_collision_before_any_rename() {
        let td = TempDir::new().unwrap();
        let first = td.path().join("first.bin");
        let second = td.path().join("second.bin");
        let first_target = td.path().join("first.mp4");
        std::fs::write(&first, b"first").unwrap();
        std::fs::write(&second, b"second").unwrap();
        std::fs::write(&first_target, b"existing").unwrap();

        let err = execute(
            Vec::new(),
            vec![
                (second.clone(), FileType::Mp4),
                (first.clone(), FileType::Mp4),
            ],
        )
        .unwrap_err();

        assert!(
            err.downcast_ref::<AutoarcError>().is_some_and(
                |e| matches!(e, AutoarcError::OutputCollision(path) if path == &first_target)
            ),
            "expected output collision, got {err:#}",
        );
        assert!(first.exists());
        assert!(second.exists());
        assert_eq!(std::fs::read(first_target).unwrap(), b"existing");
    }

    // --- ignore + scan fixtures ---------------------------------------------

    /// ZIP local-file-header magic, enough for `infer` to classify the file as
    /// `application/zip` — same trick used in `src/fs/classify.rs` tests.
    const ZIP_MAGIC: &[u8] = b"PK\x03\x04";

    /// Create a file at `dir/name` whose contents make `get_file_type` return
    /// [`FileType::Zip`]. The scan integration tests below use this to assert
    /// which archives survive `--ignore` pruning.
    fn write_zip(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(ZIP_MAGIC).unwrap();
        f.write_all(&[0u8; 64]).unwrap();
        p
    }

    /// Sorted archive paths from a [`ScanResult`] — convenient for equality
    /// assertions in the scan tests.
    fn archive_paths(result: &ScanResult) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = result.archives.iter().map(|i| i.path.clone()).collect();
        v.sort();
        v
    }

    // --- IgnoreFilter (pure, no filesystem) ---------------------------------

    #[test]
    fn ignore_filter_empty_is_inactive() {
        let f = IgnoreFilter::new(&[]).unwrap();
        // An inactive filter must never claim a path, regardless of input.
        assert!(!f.is_ignored(Path::new("/root"), Path::new("/root/scratch")));
        assert!(!f.is_ignored(Path::new("/root"), Path::new("/root/a/b.tmp")));
    }

    #[test]
    fn ignore_filter_bare_name_matches_top_level_only() {
        let f = IgnoreFilter::new(&["scratch".to_string()]).unwrap();
        let root = Path::new("/root");
        assert!(f.is_ignored(root, Path::new("/root/scratch")));
        // Fully anchored + literal_separator: a nested dir of the same name
        // does NOT match a bare pattern.
        assert!(!f.is_ignored(root, Path::new("/root/sub/scratch")));
    }

    #[test]
    fn ignore_filter_double_star_matches_any_depth() {
        let f = IgnoreFilter::new(&["**/node_modules".to_string()]).unwrap();
        let root = Path::new("/root");
        assert!(f.is_ignored(root, Path::new("/root/node_modules")));
        assert!(f.is_ignored(root, Path::new("/root/a/node_modules")));
        assert!(f.is_ignored(root, Path::new("/root/a/b/node_modules")));
    }

    #[test]
    fn ignore_filter_star_does_not_cross_separator() {
        let top = IgnoreFilter::new(&["*.tmp".to_string()]).unwrap();
        let any = IgnoreFilter::new(&["**/*.tmp".to_string()]).unwrap();
        let root = Path::new("/root");
        // `*.tmp` only matches a top-level .tmp file (literal separator).
        assert!(top.is_ignored(root, Path::new("/root/foo.tmp")));
        assert!(!top.is_ignored(root, Path::new("/root/sub/foo.tmp")));
        // `**/*.tmp` matches at any depth, including the top level.
        assert!(any.is_ignored(root, Path::new("/root/foo.tmp")));
        assert!(any.is_ignored(root, Path::new("/root/sub/foo.tmp")));
    }

    #[test]
    fn ignore_filter_multiple_patterns_match_on_any() {
        let f = IgnoreFilter::new(&["scratch".to_string(), "*.tmp".to_string()]).unwrap();
        let root = Path::new("/root");
        assert!(f.is_ignored(root, Path::new("/root/scratch")));
        assert!(f.is_ignored(root, Path::new("/root/foo.tmp")));
        assert!(!f.is_ignored(root, Path::new("/root/keep.zip")));
    }

    #[test]
    fn ignore_filter_invalid_glob_errors() {
        // An unclosed character class is not a valid glob.
        let err = IgnoreFilter::new(&["[unclosed".to_string()]).unwrap_err();
        assert!(matches!(err, AutoarcError::Other(_)), "got {err:?}");
    }

    // --- scan integration (TempDir + ZIP magic) -----------------------------

    #[test]
    fn scan_recursive_prunes_ignored_directory_subtree() {
        let td = TempDir::new().unwrap();
        let keep = write_zip(td.path(), "keep.zip");
        std::fs::create_dir(td.path().join("scratch")).unwrap();
        write_zip(&td.path().join("scratch"), "inner.zip");

        let ignore = IgnoreFilter::new(&["scratch".to_string()]).unwrap();
        let result = scan(td.path(), 5, &ignore).unwrap();
        assert_eq!(archive_paths(&result), vec![keep]);
    }

    #[test]
    fn scan_recursive_double_star_prunes_nested_dir() {
        let td = TempDir::new().unwrap();
        std::fs::create_dir_all(td.path().join("a/b/node_modules")).unwrap();
        write_zip(&td.path().join("a/b/node_modules"), "x.zip");
        let keep = write_zip(&td.path().join("a"), "keep.zip");

        let ignore = IgnoreFilter::new(&["**/node_modules".to_string()]).unwrap();
        let result = scan(td.path(), 10, &ignore).unwrap();
        assert_eq!(archive_paths(&result), vec![keep]);
    }

    #[test]
    fn scan_top_level_ignores_matching_file() {
        let td = TempDir::new().unwrap();
        let keep = write_zip(td.path(), "keep.zip");
        write_zip(td.path(), "secret.zip");

        let ignore = IgnoreFilter::new(&["secret.zip".to_string()]).unwrap();
        let result = scan(td.path(), 1, &ignore).unwrap();
        assert_eq!(archive_paths(&result), vec![keep]);
    }

    #[test]
    fn scan_top_level_with_empty_ignore_returns_all() {
        let td = TempDir::new().unwrap();
        let a = write_zip(td.path(), "a.zip");
        let b = write_zip(td.path(), "b.zip");

        let ignore = IgnoreFilter::new(&[]).unwrap();
        let result = scan(td.path(), 1, &ignore).unwrap();
        let mut expected = vec![a, b];
        expected.sort();
        assert_eq!(archive_paths(&result), expected);
    }

    #[test]
    fn scan_recursive_out_pruning_coexists_with_ignore() {
        let td = TempDir::new().unwrap();
        let foo = write_zip(td.path(), "foo.zip");
        // A fake prior-run artefact dir: pruned by the `_out` rule even
        // without any --ignore pattern.
        std::fs::create_dir(td.path().join("foo.zip_out")).unwrap();
        write_zip(&td.path().join("foo.zip_out"), "already.zip");
        // An unrelated dir that --ignore prunes.
        std::fs::create_dir(td.path().join("scratch")).unwrap();
        write_zip(&td.path().join("scratch"), "inner.zip");

        let ignore = IgnoreFilter::new(&["scratch".to_string()]).unwrap();
        let result = scan(td.path(), 5, &ignore).unwrap();
        assert_eq!(archive_paths(&result), vec![foo]);
    }

    #[tokio::test]
    async fn run_returns_an_error_when_an_archive_task_fails() {
        let td = TempDir::new().unwrap();
        write_zip(td.path(), "broken.zip");

        let err = run(td.path().to_path_buf(), 1, false, true, 1, Vec::new())
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("archive task(s) failed"),
            "unexpected runner error: {err:#}",
        );
    }
}
