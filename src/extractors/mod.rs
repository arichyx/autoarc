//! Pluggable archive backends.
//!
//! Each supported format implements [`Extractor`]. The shared [`run`] driver loops
//! over the configured passwords until one succeeds, then converts discovered
//! nested archives into [`TaskParams`] for the runner to enqueue.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::config::get_password_list;
use crate::error::AutoarcError;
use crate::fs::FileType;
use crate::progress::TaskReporter;
use crate::runner::TaskParams;

pub mod rar;
pub mod sevenz;
pub mod unar;
pub mod zip;

/// Outcome of attempting to extract an archive with one specific password.
#[derive(Debug)]
pub enum ExtractOutcome {
    /// Extraction succeeded; the inner vector lists any nested archives that
    /// the runner should now enqueue.
    Success(Vec<PathBuf>),
    /// The password was incorrect; the central driver will try the next one.
    BadPassword,
    /// The backend could not distinguish a wrong password from another
    /// recoverable attempt failure. Keep trying, but preserve this diagnostic
    /// in case no candidate succeeds.
    RetryableFailure(String),
}

/// One archive backend (zip, rar, 7z, or `unar` subprocess).
pub trait Extractor {
    /// Try to extract `path` with `password`, reporting per-entry progress.
    ///
    /// Implementations are responsible for translating their format-specific
    /// "wrong password" error into [`ExtractOutcome::BadPassword`]; any other
    /// error is propagated as `Err`.
    fn try_extract(path: &Path, password: &str, reporter: &TaskReporter) -> Result<ExtractOutcome>;
}

/// Drive an [`Extractor`] over the full password list.
fn try_with_passwords<E: Extractor>(
    path: &Path,
    passwords: &[String],
    reporter: &TaskReporter,
) -> Result<Vec<PathBuf>> {
    let mut deferred_failure = None;
    for password in passwords {
        match E::try_extract(path, password, reporter)? {
            ExtractOutcome::Success(children) => return Ok(children),
            ExtractOutcome::BadPassword => continue,
            ExtractOutcome::RetryableFailure(message) => deferred_failure = Some(message),
        }
    }
    if let Some(message) = deferred_failure {
        return Err(AutoarcError::Other(message).into());
    }
    Err(AutoarcError::NoCorrectPassword.into())
}

/// Pick the right backend for `file_type` and run it through every candidate
/// password, returning [`TaskParams`] for any nested archives encountered.
pub fn run(
    file_type: FileType,
    path: PathBuf,
    root: PathBuf,
    reporter: &TaskReporter,
) -> Result<Vec<TaskParams>> {
    let passwords = get_password_list();
    let children = match file_type {
        FileType::Zip => try_with_passwords::<zip::ZipExtractor>(&path, passwords, reporter)?,
        FileType::Rar => try_with_passwords::<rar::RarExtractor>(&path, passwords, reporter)?,
        FileType::SevenZ => {
            try_with_passwords::<sevenz::SevenzExtractor>(&path, passwords, reporter)?
        }
        FileType::Multi => try_with_passwords::<unar::UnarExtractor>(&path, passwords, reporter)?,
        FileType::Sfx => try_with_passwords::<unar::UnarExtractor>(&path, passwords, reporter)?,
        unsupported => return Err(AutoarcError::UnsupportedFileType(unsupported).into()),
    };
    Ok(children
        .into_iter()
        .map(|child| TaskParams {
            archive_path: child,
            root: root.clone(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{ExtractOutcome, Extractor, try_with_passwords};
    use crate::AutoarcError;
    use crate::progress::{Reporter, TaskReporter};
    use std::path::{Path, PathBuf};

    struct AmbiguousThenSuccess;

    impl Extractor for AmbiguousThenSuccess {
        fn try_extract(
            _path: &Path,
            password: &str,
            _reporter: &TaskReporter,
        ) -> anyhow::Result<ExtractOutcome> {
            if password == "correct" {
                Ok(ExtractOutcome::Success(vec![PathBuf::from("child.zip")]))
            } else {
                Ok(ExtractOutcome::RetryableFailure(
                    "backend diagnostic".to_string(),
                ))
            }
        }
    }

    struct AlwaysAmbiguous;

    impl Extractor for AlwaysAmbiguous {
        fn try_extract(
            _path: &Path,
            _password: &str,
            _reporter: &TaskReporter,
        ) -> anyhow::Result<ExtractOutcome> {
            Ok(ExtractOutcome::RetryableFailure(
                "backend diagnostic".to_string(),
            ))
        }
    }

    #[test]
    fn retryable_failure_does_not_stop_later_passwords() {
        let reporter = Reporter::new(1).task("password loop");
        let passwords = vec!["".to_string(), "correct".to_string()];

        let children =
            try_with_passwords::<AmbiguousThenSuccess>(Path::new("archive"), &passwords, &reporter)
                .unwrap();

        assert_eq!(children, [PathBuf::from("child.zip")]);
    }

    #[test]
    fn retryable_failure_preserves_backend_diagnostic_after_exhaustion() {
        let reporter = Reporter::new(1).task("password loop");
        let passwords = vec!["".to_string(), "wrong".to_string()];

        let error =
            try_with_passwords::<AlwaysAmbiguous>(Path::new("archive"), &passwords, &reporter)
                .unwrap_err();

        assert!(
            error.downcast_ref::<AutoarcError>().is_some_and(
                |error| matches!(error, AutoarcError::Other(message) if message == "backend diagnostic")
            ),
            "unexpected error: {error:#}",
        );
    }
}
