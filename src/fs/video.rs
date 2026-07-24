//! Video file post-processing: enforce the canonical extension for MP4/TS files.

use std::path::Path;

use crate::error::AutoarcError;
use crate::fs::{FileType, rename_noreplace};

/// Rename `path` so its extension matches `file_type` (`.mp4` or `.ts`).
///
/// This is a no-op if the extension already matches. Destination creation is
/// atomic and never replaces a file that appears between validation and the
/// rename.
pub fn rename_video(path: &Path, file_type: FileType) -> Result<(), AutoarcError> {
    let Some(new_path) = video_rename_target(path, file_type) else {
        return Ok(());
    };

    match rename_noreplace(path, &new_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(AutoarcError::OutputCollision(new_path));
        }
        Err(error) => return Err(AutoarcError::io(new_path, error)),
    }

    Ok(())
}

/// Return the target path for a video rename, or `None` when no rename is needed.
pub(crate) fn video_rename_target(path: &Path, file_type: FileType) -> Option<std::path::PathBuf> {
    let target_ext = match file_type {
        FileType::Mp4 => "mp4",
        FileType::TS => "ts",
        _ => return None,
    };

    // Skip if the extension is already correct (case-insensitive).
    if let Some(ext) = path.extension()
        && ext.to_string_lossy().to_ascii_lowercase() == target_ext
    {
        return None;
    }

    Some(path.with_extension(target_ext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rename_refuses_to_replace_existing_target() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("clip.m");
        let target = temp.path().join("clip.mp4");
        std::fs::write(&source, b"new").unwrap();
        std::fs::write(&target, b"existing").unwrap();

        let err = rename_video(&source, FileType::Mp4).unwrap_err();

        assert!(matches!(err, AutoarcError::OutputCollision(ref p) if p == &target));
        assert_eq!(std::fs::read(&source).unwrap(), b"new");
        assert_eq!(std::fs::read(&target).unwrap(), b"existing");
    }

    #[test]
    fn rename_moves_content_to_the_canonical_extension() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("clip.unknown");
        let target = temp.path().join("clip.mp4");
        std::fs::write(&source, b"video").unwrap();

        rename_video(&source, FileType::Mp4).unwrap();

        assert!(!source.exists());
        assert_eq!(std::fs::read(target).unwrap(), b"video");
    }
}
