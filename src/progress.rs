//! Console progress reporting built on top of [`indicatif::MultiProgress`].
//!
//! The reporter renders one progress bar per concurrent extraction task on top of an
//! "overall" bar that tracks `done / total` archives. A coloured summary is printed
//! when [`Reporter::finish_summary`] is called after the task queue is exhausted.
//!
//! Tracing log output is rerouted through a custom writer that wraps every line in
//! [`MultiProgress::suspend`], so log lines and live bars never tear each other.

use std::borrow::Cow;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;

use console::{Style, style};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

/// Aggregate statistics gathered across the run, reported in the final summary.
#[derive(Debug, Default)]
struct Stats {
    succeeded: usize,
    failed: usize,
    videos_renamed: usize,
    /// Media tails carved out into standalone archive files.
    tails_carved: usize,
    /// Real PE executables seen among extracted/scanned files. Reported only;
    /// autoarc never executes them.
    executables: usize,
}

/// Top-level progress reporter shared across the runner and every extraction task.
///
/// Cheap to clone; the underlying [`MultiProgress`] and stats are reference-counted.
#[derive(Clone)]
pub struct Reporter {
    multi: MultiProgress,
    overall: ProgressBar,
    stats: Arc<Mutex<Stats>>,
    started_at: Instant,
}

impl Reporter {
    /// Create a new reporter with an overall bar sized to `total_initial` archives.
    /// Newly-discovered nested archives extend the bar via [`Reporter::task_added`].
    pub fn new(total_initial: usize) -> Self {
        let multi = MultiProgress::new();
        let overall = multi.add(ProgressBar::new(total_initial as u64));
        overall.set_style(
            ProgressStyle::with_template(
                "{prefix:>10.cyan.bold} [{bar:32.cyan/blue}] {pos}/{len} ({elapsed})",
            )
            .expect("valid overall template")
            .progress_chars("=> "),
        );
        overall.set_prefix("Overall");
        overall.enable_steady_tick(std::time::Duration::from_millis(120));

        Self {
            multi,
            overall,
            stats: Arc::new(Mutex::new(Stats::default())),
            started_at: Instant::now(),
        }
    }

    /// Spawn a per-task progress bar with the given short label.
    pub fn task(&self, label: impl Into<String>) -> TaskReporter {
        let label = label.into();
        let bar = self.multi.add(ProgressBar::new_spinner());
        bar.set_style(
            ProgressStyle::with_template("{prefix:>10.yellow} {spinner:.green} {wide_msg}")
                .expect("valid task spinner template"),
        );
        bar.set_prefix("Task");
        bar.set_message(label.clone());
        bar.enable_steady_tick(std::time::Duration::from_millis(120));

        TaskReporter {
            bar,
            label,
            stats: Arc::clone(&self.stats),
            multi: self.multi.clone(),
        }
    }

    /// Extend the overall bar with `n` newly-discovered nested archives.
    pub fn task_added(&self, n: usize) {
        self.overall.inc_length(n as u64);
    }

    /// Mark one task as successfully completed.
    pub fn task_succeeded(&self) {
        if let Ok(mut s) = self.stats.lock() {
            s.succeeded += 1;
        }
        self.overall.inc(1);
    }

    /// Mark one task as failed and surface the error above the bars.
    pub fn task_failed(&self, label: &str, err: &dyn std::fmt::Display) {
        if let Ok(mut s) = self.stats.lock() {
            s.failed += 1;
        }
        self.overall.inc(1);
        let line = format!("{} {}: {}", style("FAIL").red().bold(), label, err);
        // `MultiProgress::println` is hidden when stderr is not a terminal.
        // Suspending and writing directly preserves diagnostics in CI/pipes
        // while still keeping interactive progress bars intact.
        self.multi.suspend(|| eprintln!("{line}"));
    }

    /// Increment the renamed-video counter (used by extractors).
    pub fn note_video_renamed(&self) {
        if let Ok(mut s) = self.stats.lock() {
            s.videos_renamed += 1;
        }
    }

    /// Increment the carved-media-tail counter (used by the tail extractor).
    pub fn note_tail_carved(&self) {
        if let Ok(mut s) = self.stats.lock() {
            s.tails_carved += 1;
        }
    }

    /// Increment the detected-executable counter (used by extractors + scan).
    pub fn note_executable(&self) {
        if let Ok(mut s) = self.stats.lock() {
            s.executables += 1;
        }
    }

    /// Borrow the underlying [`MultiProgress`] (for the tracing writer).
    pub fn multi(&self) -> &MultiProgress {
        &self.multi
    }

    /// Stop the bars and print a coloured summary table.
    pub fn finish_summary(self) -> usize {
        self.overall.finish_and_clear();
        let stats = self
            .stats
            .lock()
            .map(|g| (*g).clone_into_owned())
            .unwrap_or_default();
        let elapsed = self.started_at.elapsed();

        let label = Style::new().bold();
        let ok = Style::new().green().bold();
        let fail = Style::new().red().bold();
        let neutral = Style::new().cyan();

        let summary = format!(
            "\n{}\n  {} {}\n  {} {}\n  {} {}\n  {} {}\n  {} {}\n  {} {:.2?}\n",
            label.apply_to("Summary"),
            ok.apply_to("succeeded :"),
            stats.succeeded,
            fail.apply_to("failed    :"),
            stats.failed,
            neutral.apply_to("videos    :"),
            stats.videos_renamed,
            neutral.apply_to("tails     :"),
            stats.tails_carved,
            neutral.apply_to("executables:"),
            stats.executables,
            label.apply_to("elapsed   :"),
            elapsed,
        );
        self.multi.suspend(|| eprintln!("{summary}"));
        stats.failed
    }
}

/// Per-task handle exposed to extractors.
///
/// Extractors set the bar length when they know the entry count up-front
/// (zip / 7z), or leave it unset and call [`Self::tick`] for spinner-style updates
/// (rar / unar).
///
/// When the task finishes the bar is **cleared** and the final status is
/// printed as a log line above the remaining live bars via
/// [`MultiProgress::println`]. This keeps the rendered bar region bounded to
/// in-flight tasks only, so we don't run into indicatif's terminal-height
/// rendering cap when hundreds of archives are queued.
pub struct TaskReporter {
    bar: ProgressBar,
    label: String,
    stats: Arc<Mutex<Stats>>,
    multi: MultiProgress,
}

impl TaskReporter {
    /// Switch to a determinate bar with `total` entries.
    pub fn set_length(&self, total: u64) {
        self.bar.set_style(
            ProgressStyle::with_template(
                "{prefix:>10.yellow} [{bar:32.green/blue}] {pos}/{len} {wide_msg}",
            )
            .expect("valid task bar template")
            .progress_chars("=> "),
        );
        self.bar.set_length(total);
        self.bar.set_message(self.label.clone());
    }

    /// Switch to a determinate bar whose progress is byte-based, rendered with
    /// human-readable sizes (used when carving multi-gigabyte tails).
    pub fn set_length_bytes(&self, total: u64) {
        self.bar.set_style(
            ProgressStyle::with_template(
                "{prefix:>10.yellow} [{bar:32.green/blue}] {bytes}/{total_bytes} {wide_msg}",
            )
            .expect("valid task bar template")
            .progress_chars("=> "),
        );
        self.bar.set_length(total);
        self.bar.set_message(self.label.clone());
    }

    /// Advance the bar by one entry.
    pub fn inc(&self) {
        self.bar.inc(1);
    }

    /// Set the absolute bar position (e.g. bytes copied so far).
    pub fn set_position(&self, pos: u64) {
        self.bar.set_position(pos);
    }

    /// Manual spinner tick (for extractors that don't know the entry count).
    pub fn tick(&self) {
        self.bar.tick();
    }

    /// Replace the bar's secondary message (e.g. current entry name).
    pub fn set_message(&self, msg: impl Into<Cow<'static, str>>) {
        self.bar.set_message(msg);
    }

    /// Increment the renamed-video stat.
    pub fn note_video_renamed(&self) {
        if let Ok(mut s) = self.stats.lock() {
            s.videos_renamed += 1;
        }
    }

    /// Increment the carved-media-tail stat.
    pub fn note_tail_carved(&self) {
        if let Ok(mut s) = self.stats.lock() {
            s.tails_carved += 1;
        }
    }

    /// Increment the detected-executable stat (reported only, never executed).
    pub fn note_executable(&self) {
        if let Ok(mut s) = self.stats.lock() {
            s.executables += 1;
        }
    }

    /// Finish the bar with a success message.
    ///
    /// Clears the bar from the active region and logs a persistent
    /// `Task   OK <label>` line above the remaining live bars.
    pub fn finish_ok(self) {
        self.bar.finish_and_clear();
        let _ = self.multi.println(format!(
            "{:>10} {} {}",
            style("Task").yellow(),
            style("OK").green().bold(),
            self.label,
        ));
    }

    /// Finish the bar with an error message.
    ///
    /// Clears the bar from the active region and logs a persistent
    /// `Task  ERR <label>: <err>` line above the remaining live bars.
    pub fn finish_err(self, err: &dyn std::fmt::Display) {
        self.bar.finish_and_clear();
        let line = format!(
            "{:>10} {} {}: {}",
            style("Task").yellow(),
            style("ERR").red().bold(),
            self.label,
            err,
        );
        self.multi.suspend(|| eprintln!("{line}"));
    }
}

/// Initialise `tracing` so its log lines coexist with the live progress bars.
///
/// All log writes are funnelled through [`MultiProgress::suspend`] on stderr.
/// When `RUST_LOG` is unset, only `WARN`+ messages survive the default filter.
pub fn init_tracing(reporter: &Reporter) {
    let writer = SuspendingWriter {
        multi: reporter.multi.clone(),
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_target(false)
        .try_init();
}

/// `MakeWriter` that suspends the [`MultiProgress`] for the duration of every write.
#[derive(Clone)]
struct SuspendingWriter {
    multi: MultiProgress,
}

impl<'a> MakeWriter<'a> for SuspendingWriter {
    type Writer = SuspendingHandle;
    fn make_writer(&'a self) -> Self::Writer {
        SuspendingHandle {
            multi: self.multi.clone(),
        }
    }
}

struct SuspendingHandle {
    multi: MultiProgress,
}

impl Write for SuspendingHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0;
        self.multi.suspend(|| {
            written = io::stderr().write(buf).unwrap_or(0);
        });
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stderr().flush()
    }
}

// Local clone helper so we can copy out of the mutex without requiring `Clone` on Stats.
trait CloneIntoOwned {
    fn clone_into_owned(&self) -> Stats;
}

impl CloneIntoOwned for Stats {
    fn clone_into_owned(&self) -> Stats {
        Stats {
            succeeded: self.succeeded,
            failed: self.failed,
            videos_renamed: self.videos_renamed,
            tails_carved: self.tails_carved,
            executables: self.executables,
        }
    }
}
