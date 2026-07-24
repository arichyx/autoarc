//! `unar`/`lsar` subprocess backend, used for split archives and edge cases the
//! native crates can't handle.

use std::path::{Path, PathBuf};

use anyhow::Result;
use tracing::{debug, error, trace};

use crate::error::AutoarcError;
use crate::fs::{
    get_file_type, is_type_archive, is_type_video, out_dir_path, rename_noreplace, rename_video,
};
use crate::progress::TaskReporter;

use super::{ExtractOutcome, Extractor};

/// `Extractor` implementation that shells out to the `unar` binary.
pub struct UnarExtractor;

impl Extractor for UnarExtractor {
    fn try_extract(path: &Path, password: &str, reporter: &TaskReporter) -> Result<ExtractOutcome> {
        debug!("[unar] try_extract {path:?}");

        let dirname = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let outdir = out_dir_path(path);

        if outdir.exists() {
            return Err(AutoarcError::OutputCollision(outdir).into());
        }

        // Each password attempt gets an isolated sibling staging directory.
        // A failed attempt drops only this temporary directory; a pre-existing
        // final output directory is never touched.
        let staging = tempfile::Builder::new()
            .prefix(".autoarc-unar-")
            .tempdir_in(dirname)
            .map_err(|e| AutoarcError::io(dirname.to_path_buf(), e))?;

        reporter.set_message(format!("unar -> {}", staging.path().display()));
        reporter.tick();

        let output = std::process::Command::new("unar")
            .arg("-q")
            .arg("-o")
            .arg(staging.path())
            .arg("-p")
            .arg(password)
            .arg(path)
            .output()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => AutoarcError::ToolNotFound("unar"),
                _ => AutoarcError::io(path.to_path_buf(), e),
            })?;

        if !output.status.success() {
            // `unar` uses the same exit status for a wrong password, a corrupt
            // archive, and missing volumes. Retry the remaining candidates, but
            // retain the diagnostic so exhaustion reports the real subprocess
            // failure rather than an invented `NoCorrectPassword`.
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let detail = if !stderr.trim().is_empty() {
                stderr.trim()
            } else {
                stdout.trim()
            };
            return Ok(ExtractOutcome::RetryableFailure(format!(
                "unar failed for {} (status {}): {}",
                path.display(),
                output.status,
                detail
            )));
        }

        // Validate and post-process inside staging. Only a completely successful
        // attempt is renamed into the deterministic final output directory.
        let mut nested_relative = Vec::new();
        for entry in walkdir::WalkDir::new(staging.path())
            .min_depth(1)
            .into_iter()
        {
            let entry = entry.map_err(|e| {
                AutoarcError::Other(format!(
                    "walkdir error under {}: {e}",
                    staging.path().display()
                ))
            })?;
            if !entry.file_type().is_file() {
                continue;
            }
            let filepath = entry.into_path();
            let kind = get_file_type(&filepath);
            if is_type_archive(kind) {
                let relative = filepath.strip_prefix(staging.path()).map_err(|e| {
                    AutoarcError::Other(format!(
                        "staged path {} escaped {}: {e}",
                        filepath.display(),
                        staging.path().display()
                    ))
                })?;
                nested_relative.push(relative.to_path_buf());
            } else if is_type_video(kind) {
                rename_video(&filepath, kind)?;
                reporter.note_video_renamed();
            }
            reporter.tick();
        }

        rename_noreplace(staging.path(), &outdir).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                AutoarcError::OutputCollision(outdir.clone())
            } else {
                AutoarcError::io(outdir.clone(), error)
            }
        })?;

        let nested = nested_relative
            .into_iter()
            .map(|relative| outdir.join(relative))
            .collect();
        Ok(ExtractOutcome::Success(nested))
    }
}

/// Run `lsar <archive>` and parse the entry list (one path per line, header skipped).
pub fn lsar(archive_path: &Path) -> Result<Vec<PathBuf>> {
    debug!("lsar {}", archive_path.display());
    let output = std::process::Command::new("lsar")
        .arg(archive_path)
        .output()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => AutoarcError::ToolNotFound("lsar"),
            _ => AutoarcError::io(archive_path.to_path_buf(), e),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("lsar error for {:?}: {}", archive_path, stderr);
        return Err(AutoarcError::Other(format!(
            "lsar error for file {:?}: {}",
            archive_path, stderr
        ))
        .into());
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| AutoarcError::Other(format!("lsar produced non-UTF8 output: {e}")))?;
    trace!("lsar output: {stdout}");

    // The first line is `Archive: <name>` metadata; the entries follow.
    Ok(stdout
        .lines()
        .skip(1)
        .map(|line| PathBuf::from(line.to_string()))
        .collect())
}
