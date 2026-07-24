//! Path-construction helpers shared by all extractors.

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use crate::error::AutoarcError;

/// Build the sibling output directory **name** (not a full path) for an
/// archive by appending `_out` to its complete file name.
///
/// Examples:
///   `foo.zip`        → `foo.zip_out`
///   `foo.7z`         → `foo.7z_out`
///   `split.7z.001`   → `split.7z.001_out`
///   `archive`        → `archive_out`
///
/// Keeping the original name intact makes this mapping one-to-one: unlike
/// replacing punctuation, `a.b.zip` and `a_b.zip` cannot collapse to the same
/// directory. `OsString` also preserves non-UTF8 file names on Unix.
pub fn out_dir_name(archive_path: &Path) -> OsString {
    let mut filename = archive_path
        .file_name()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| OsString::from("archive"));
    filename.push("_out");
    filename
}

/// Build the complete sibling output-directory path for `archive_path`.
pub fn out_dir_path(archive_path: &Path) -> PathBuf {
    let dirname = archive_path.parent().unwrap_or_else(|| Path::new("."));
    dirname.join(out_dir_name(archive_path))
}

/// Atomically rename `source` to `destination` without replacing anything.
///
/// Apple and Linux kernels expose a native no-replace rename operation. The
/// fallback retains the same visible contract on platforms whose ordinary
/// rename already rejects an existing destination.
pub(crate) fn rename_noreplace(source: &Path, destination: &Path) -> std::io::Result<()> {
    #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
    {
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            source,
            rustix::fs::CWD,
            destination,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(std::io::Error::from)
    }

    #[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android")))]
    {
        if destination.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "destination already exists",
            ));
        }
        std::fs::rename(source, destination)
    }
}

/// Build the per-entry output path: `<archive_dir>/<out_dir_name>/<filename>`.
///
/// All extractors funnel writes through this helper so that nested archives can be
/// discovered next to their parent and visualised consistently. Unsafe entry
/// paths are rejected rather than normalised: an archive must not be able to
/// escape its dedicated output directory.
pub fn create_outpath(archive_path: &Path, filename: &Path) -> Result<PathBuf, AutoarcError> {
    let mut relative = PathBuf::new();
    for component in filename.components() {
        match component {
            Component::Normal(part) => relative.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(AutoarcError::UnsafeArchivePath {
                    archive: archive_path.to_path_buf(),
                    entry: filename.to_path_buf(),
                });
            }
        }
    }

    if relative.as_os_str().is_empty() {
        return Err(AutoarcError::UnsafeArchivePath {
            archive: archive_path.to_path_buf(),
            entry: filename.to_path_buf(),
        });
    }

    Ok(out_dir_path(archive_path).join(relative))
}

/// Compute `absolute_path` relative to `dir`, falling back to the original path
/// when no relation exists (e.g. across different drives on Windows).
pub fn relative_path(dir: &Path, absolute_path: &Path) -> PathBuf {
    pathdiff::diff_paths(absolute_path, dir).unwrap_or_else(|| absolute_path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- out_dir_name --------------------------------------------------------

    #[test]
    fn out_dir_name_preserves_single_extension_dot() {
        assert_eq!(out_dir_name(Path::new("foo.zip")), "foo.zip_out");
        assert_eq!(out_dir_name(Path::new("/tmp/foo.7z")), "foo.7z_out");
    }

    #[test]
    fn out_dir_name_disambiguates_same_stem_siblings() {
        // The complete archive name remains part of the directory name.
        assert_ne!(
            out_dir_name(Path::new("foo.zip")),
            out_dir_name(Path::new("foo.7z"))
        );
    }

    #[test]
    fn out_dir_name_does_not_collapse_dots_and_underscores() {
        assert_ne!(
            out_dir_name(Path::new("a.b.zip")),
            out_dir_name(Path::new("a_b.zip"))
        );
        assert_eq!(out_dir_name(Path::new("split.7z.001")), "split.7z.001_out");
    }

    #[test]
    fn out_dir_name_handles_no_extension() {
        assert_eq!(out_dir_name(Path::new("archive")), "archive_out");
    }

    #[test]
    fn out_dir_name_falls_back_when_no_file_name() {
        // `Path::new(".")` has no file_name; we must still emit a valid name.
        assert_eq!(out_dir_name(Path::new("..")), "archive_out");
    }

    // --- create_outpath ------------------------------------------------------

    #[test]
    fn create_outpath_places_entry_beside_archive() {
        // /tmp/foo.zip + bar.txt  -->  /tmp/foo.zip_out/bar.txt
        let archive = Path::new("/tmp/foo.zip");
        let out = create_outpath(archive, Path::new("bar.txt")).unwrap();
        assert_eq!(out, PathBuf::from("/tmp/foo.zip_out/bar.txt"));
    }

    #[test]
    fn create_outpath_keeps_every_dot_segment_in_directory_name() {
        let archive = Path::new("/a/b/foo.tar.gz");
        let out = create_outpath(archive, Path::new("x")).unwrap();
        assert_eq!(out, PathBuf::from("/a/b/foo.tar.gz_out/x"));
    }

    #[test]
    fn create_outpath_preserves_nested_entry_paths() {
        let archive = Path::new("/root/pack.7z");
        let out = create_outpath(archive, Path::new("dir/sub/leaf.bin")).unwrap();
        assert_eq!(out, PathBuf::from("/root/pack.7z_out/dir/sub/leaf.bin"));
    }

    #[test]
    fn create_outpath_defaults_to_cwd_when_archive_has_no_parent() {
        // `Path::new("lone.zip").parent()` returns `Some("")` (an empty path,
        // not None), so we fall through to joining an empty dir with the
        // computed out name — which collapses to a plain relative path.
        let archive = Path::new("lone.zip");
        let out = create_outpath(archive, Path::new("entry")).unwrap();
        assert_eq!(out, PathBuf::from("lone.zip_out/entry"));
    }

    #[test]
    fn create_outpath_rejects_parent_traversal() {
        let err = create_outpath(
            Path::new("/tmp/archive.zip"),
            Path::new("../../escaped.txt"),
        )
        .unwrap_err();
        assert!(matches!(err, AutoarcError::UnsafeArchivePath { .. }));
    }

    #[test]
    fn create_outpath_rejects_absolute_paths() {
        let err = create_outpath(Path::new("/tmp/archive.zip"), Path::new("/tmp/escaped.txt"))
            .unwrap_err();
        assert!(matches!(err, AutoarcError::UnsafeArchivePath { .. }));
    }

    // --- relative_path -------------------------------------------------------

    #[test]
    fn relative_path_produces_relative_diff() {
        let base = Path::new("/a/b");
        let target = Path::new("/a/b/c/d.txt");
        assert_eq!(relative_path(base, target), PathBuf::from("c/d.txt"));
    }

    #[test]
    fn relative_path_falls_back_to_absolute_when_no_relation() {
        // Two absolute paths in unrelated roots can always be diffed with ../
        // climbs, so pathdiff returns Some. The only real fallback is when one
        // path is relative and the other absolute.
        let base = Path::new("relative/base");
        let target = Path::new("/absolute/target");
        assert_eq!(
            relative_path(base, target),
            PathBuf::from("/absolute/target")
        );
    }
}
