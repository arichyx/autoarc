//! RAR backend powered by the [`unrar`] crate.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use tracing::debug;
use unrar::{
    Archive,
    error::{Code, UnrarError},
};

use crate::error::AutoarcError;
use crate::fs::{create_outpath, get_file_type, is_type_archive, is_type_video, rename_video};
use crate::progress::TaskReporter;

use super::{ExtractOutcome, Extractor};

/// `Extractor` implementation for RAR archives.
pub struct RarExtractor;

impl Extractor for RarExtractor {
    fn try_extract(path: &Path, password: &str, reporter: &TaskReporter) -> Result<ExtractOutcome> {
        debug!("[rar] try_extract {path:?}");
        match check_password(path, password.as_bytes()) {
            Ok(()) => {}
            Err(e) if is_retryable_password_error(e.code) => {
                return Ok(ExtractOutcome::BadPassword);
            }
            Err(e) => return Err(e.into()),
        }
        let children = unrar_with_password(path, password, reporter)?;
        Ok(ExtractOutcome::Success(children))
    }
}

/// Whether an UnRAR error means only that the current password candidate failed.
///
/// UnRAR distinguishes an omitted/empty password (`MissingPassword`) from an
/// explicitly incorrect one (`BadPassword`). Both should advance the shared
/// password loop rather than aborting the archive task.
fn is_retryable_password_error(code: Code) -> bool {
    matches!(code, Code::MissingPassword | Code::BadPassword)
}

/// Open the archive and test the first real file to verify the password.
///
/// Directory headers have no encrypted payload, so accepting one would let an
/// empty password through for archives whose first member is a directory.
fn check_password(archive_path: &Path, password: &[u8]) -> Result<(), UnrarError> {
    let mut archive = Archive::with_password(archive_path, password).open_for_processing()?;
    while let Some(header) = archive.read_header()? {
        if header.entry().is_directory() {
            archive = header.skip()?;
            continue;
        }
        header.test()?;
        break;
    }
    Ok(())
}

/// Walk every entry in the archive once the password is known, writing files and
/// collecting any nested archives to schedule next.
fn unrar_with_password(
    archive_path: &Path,
    password: &str,
    reporter: &TaskReporter,
) -> Result<Vec<PathBuf>> {
    let mut archive = Archive::with_password(archive_path, password).open_for_processing()?;

    // RAR doesn't expose entry count up-front, so stay in spinner mode.
    let mut nested = Vec::new();

    while let Some(header) = archive.read_header()? {
        if header.entry().is_directory() {
            archive = header.skip()?;
            continue;
        }

        let filename = header.entry().filename.clone();
        if filename.to_string_lossy().contains("__MACOSX") {
            archive = header.skip()?;
            continue;
        }

        let outpath = create_outpath(archive_path, &filename)?;
        ensure_output_parent(&outpath)?;
        if outpath.exists() {
            return Err(AutoarcError::OutputCollision(outpath).into());
        }
        archive = header.extract_to(&outpath)?;

        reporter.set_message(filename.to_string_lossy().into_owned());
        reporter.tick();

        let kind = get_file_type(&outpath);
        if is_type_archive(kind) {
            nested.push(outpath);
        } else if is_type_video(kind) {
            rename_video(&outpath, kind)?;
            reporter.note_video_renamed();
        }
    }

    Ok(nested)
}

/// Create the output directory (and any archived subdirectories) before asking
/// UnRAR to create the destination file.
fn ensure_output_parent(outpath: &Path) -> Result<()> {
    if let Some(parent) = outpath.parent() {
        fs::create_dir_all(parent).map_err(|e| AutoarcError::io(parent.to_path_buf(), e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ensure_output_parent, is_retryable_password_error};
    use unrar::error::Code;

    #[test]
    fn missing_and_bad_password_errors_are_retryable() {
        assert!(is_retryable_password_error(Code::MissingPassword));
        assert!(is_retryable_password_error(Code::BadPassword));
    }

    #[test]
    fn non_password_errors_are_not_retryable() {
        assert!(!is_retryable_password_error(Code::BadData));
        assert!(!is_retryable_password_error(Code::ERead));
    }

    #[test]
    fn output_parent_is_created_before_extraction() {
        let temp = tempfile::tempdir().unwrap();
        let outpath = temp
            .path()
            .join("archive.rar_out")
            .join("nested")
            .join("file.bin");

        ensure_output_parent(&outpath).unwrap();

        assert!(outpath.parent().unwrap().is_dir());
    }
}
