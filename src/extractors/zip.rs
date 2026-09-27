//! ZIP backend powered by the [`zip`] crate.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::debug;
use zip::{ZipArchive, result::ZipError};

use crate::error::AutoarcError;
use crate::fs::{
    create_outpath, get_file_type, is_type_archive, is_type_executable, is_type_video, rename_video,
};
use crate::progress::TaskReporter;

use super::{ExtractOutcome, Extractor};

/// `Extractor` implementation for single-volume ZIP archives.
pub struct ZipExtractor;

impl Extractor for ZipExtractor {
    fn try_extract(path: &Path, password: &str, reporter: &TaskReporter) -> Result<ExtractOutcome> {
        debug!("[zip] try_extract {path:?}");
        match check_password(path, password.as_bytes()) {
            Ok(()) => {}
            Err(ZipError::InvalidPassword) => return Ok(ExtractOutcome::BadPassword),
            // Some encrypted ZIPs report a wrong password as a generic IO/CRC failure.
            // Keep trying candidates, but retain the concrete error in case the
            // archive is corrupt or unreadable rather than merely encrypted.
            Err(error @ ZipError::Io(_)) => {
                return Ok(ExtractOutcome::RetryableFailure(format!(
                    "ZIP password probe failed for {}: {error}",
                    path.display()
                )));
            }
            Err(e) => return Err(e.into()),
        }
        let children = unzip_with_password(path, password, reporter)?;
        Ok(ExtractOutcome::Success(children))
    }
}

/// Probe every real file entry to validate `password` without writing to disk.
fn check_password(archive_path: &Path, password: &[u8]) -> Result<(), ZipError> {
    let file = File::open(archive_path)?;
    let mut archive = ZipArchive::new(file)?;

    // Directory entries carry no encrypted payload, so keep scanning until all
    // real files have accepted this password candidate. Checking every file also
    // covers ZIPs whose entries use different encryption settings.
    for i in 0..archive.len() {
        let mut entry = archive.by_index_decrypt(i, password)?;
        if entry.is_dir() {
            continue;
        }

        // Reading one byte forces the decryption code path; a bad key surfaces here.
        let mut buf = [0u8; 1];
        let _ = entry.read(&mut buf)?;
    }
    Ok(())
}

/// Stream every entry to `<archive_dir>/<filename>_out/...` once we've confirmed `password`.
fn unzip_with_password(
    archive_path: &Path,
    password: &str,
    reporter: &TaskReporter,
) -> Result<Vec<PathBuf>> {
    let file =
        File::open(archive_path).map_err(|e| AutoarcError::io(archive_path.to_path_buf(), e))?;
    let mut archive = ZipArchive::new(file)?;

    reporter.set_length(archive.len() as u64);

    let mut nested = Vec::new();

    for i in 0..archive.len() {
        let mut entry = archive.by_index_decrypt(i, password.as_bytes())?;

        // `enclosed_name` rejects absolute paths and names that would escape
        // the extraction root. The shared path helper validates it again for
        // the non-ZIP backends that do not provide an equivalent API.
        let filename = entry
            .enclosed_name()
            .ok_or_else(|| AutoarcError::UnsafeArchivePath {
                archive: archive_path.to_path_buf(),
                entry: PathBuf::from(entry.name()),
            })?;

        // Skip macOS metadata sidecars and pure directory entries.
        if filename.to_string_lossy().contains("__MACOSX") || entry.is_dir() {
            reporter.inc();
            continue;
        }

        let outpath = create_outpath(archive_path, &filename)?;
        if let Some(parent) = outpath.parent()
            && !parent.exists()
        {
            fs::create_dir_all(parent).context("create parent dir")?;
        }

        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&outpath)
            .map_err(|e| {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    AutoarcError::OutputCollision(outpath.clone())
                } else {
                    AutoarcError::io(outpath.clone(), e)
                }
            })?;
        io::copy(&mut entry, &mut out).map_err(|e| AutoarcError::io(outpath.clone(), e))?;

        reporter.set_message(filename.to_string_lossy().into_owned());
        reporter.inc();

        // Classify the freshly-written file.
        let kind = get_file_type(&outpath);
        if is_type_archive(kind) {
            nested.push(outpath);
        } else if is_type_video(kind) {
            rename_video(&outpath, kind)?;
            reporter.note_video_renamed();
        } else if is_type_executable(kind) {
            reporter.note_executable();
        }
    }

    Ok(nested)
}

#[cfg(test)]
mod tests {
    use super::{check_password, unzip_with_password};
    use crate::AutoarcError;
    use crate::progress::Reporter;
    use std::fs::File;
    use std::io::Write;
    use zip::unstable::write::FileOptionsExt;
    use zip::write::SimpleFileOptions;
    use zip::{ZipWriter, result::ZipError};

    #[test]
    fn password_probe_skips_leading_directory_entries() {
        let temp = tempfile::tempdir().unwrap();
        let archive_path = temp.path().join("directory-first.zip");
        let file = File::create(&archive_path).unwrap();
        let mut writer = ZipWriter::new(file);
        writer
            .add_directory("payload/", SimpleFileOptions::default())
            .unwrap();
        writer
            .start_file(
                "payload/hello.txt",
                SimpleFileOptions::default()
                    .with_deprecated_encryption(b"secret")
                    .unwrap(),
            )
            .unwrap();
        writer.write_all(b"secret payload").unwrap();
        writer.finish().unwrap();

        assert!(matches!(
            check_password(&archive_path, b""),
            Err(ZipError::InvalidPassword) | Err(ZipError::Io(_))
        ));
        check_password(&archive_path, b"secret").unwrap();
    }

    #[test]
    fn extraction_rejects_parent_path_traversal() {
        let temp = tempfile::tempdir().unwrap();
        let archive_path = temp.path().join("unsafe.zip");
        let file = File::create(&archive_path).unwrap();
        let mut writer = ZipWriter::new(file);
        writer
            .start_file("../escaped.txt", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"must stay contained").unwrap();
        writer.finish().unwrap();

        let task = Reporter::new(1).task("unsafe zip");
        let error = unzip_with_password(&archive_path, "", &task).unwrap_err();

        assert!(
            error
                .downcast_ref::<AutoarcError>()
                .is_some_and(|error| matches!(error, AutoarcError::UnsafeArchivePath { .. })),
            "expected unsafe-path error, got {error:#}",
        );
        assert!(!temp.path().join("escaped.txt").exists());
    }
}
