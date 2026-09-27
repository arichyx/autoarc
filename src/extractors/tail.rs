//! Carves the payload appended behind a media file's ISO-BMFF box chain.
//!
//! The host file (a perfectly playable MP4/MOV) is opened read-only and never
//! modified. The tail is streamed out in fixed-size chunks — never slurped
//! into memory — into a sibling `<original>.tail.<ext>` file, which the runner
//! then enqueues as an ordinary archive task so it goes through the normal
//! password loop and nested-archive recursion.
//!
//! PE tails are only carved when they are SFX carriers (program stub plus an
//! embedded archive); a genuine executable is reported and left in place.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use tracing::debug;

use crate::error::AutoarcError;
use crate::fs::{MediaTailInfo, TailKind, contains_archive_signature, media_tail_info};
use crate::progress::TaskReporter;

/// Chunk size for the streaming copy. Large enough to keep gigabyte-scale
/// tails fast, small enough to update the progress bar responsively.
const COPY_CHUNK: usize = 1024 * 1024;

/// How far into a PE tail we look for an embedded archive signature. SFX
/// stubs are far smaller than this; the bound just caps the I/O cost.
const SFX_SCAN_BYTES: usize = 4 * 1024 * 1024;

/// What [`carve`] decided to do with a detected tail.
#[derive(Debug, PartialEq, Eq)]
pub enum CarveOutcome {
    /// The tail was streamed to this path; the runner should enqueue it as
    /// the next archive task.
    Archive(PathBuf),
    /// The tail is a genuine PE executable with no embedded archive:
    /// counted and reported, never written or enqueued.
    Executable,
}

/// Stream-carve the appended payload out of `path`.
///
/// On success the carved file (a sibling of `path` named
/// `<file name>.tail.<ext>`) is returned, ready to be enqueued as the next
/// task. Refuses to overwrite an existing file, mirroring the `_out`-directory
/// collision semantics used everywhere else.
pub fn carve(path: &Path, reporter: &TaskReporter) -> Result<CarveOutcome> {
    debug!("[tail] carving {path:?}");
    let Some(info) = media_tail_info(path) else {
        return Err(AutoarcError::Other(format!(
            "no archive tail found in {} (media file changed since scan?)",
            path.display()
        ))
        .into());
    };

    // A PE tail is only worth carving when it actually carries an archive
    // behind the stub. A plain executable gets the report-only treatment —
    // never extracted, never run, and not even written back to disk.
    if info.kind == TailKind::Pe && !carries_embedded_archive(path, &info)? {
        reporter.set_message(format!(
            "PE tail without embedded archive \u{2014} reported only: {}",
            path.display()
        ));
        reporter.note_executable();
        return Ok(CarveOutcome::Executable);
    }

    let target = tail_target_path(path, info.kind.extension());
    let mut source = File::open(path).map_err(|e| AutoarcError::io(path.to_path_buf(), e))?;
    source
        .seek(SeekFrom::Start(info.tail_start))
        .map_err(|e| AutoarcError::io(path.to_path_buf(), e))?;

    reporter.set_length_bytes(info.tail_len);
    reporter.set_message(format!(
        "carving {}.tail.{}",
        path.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default(),
        info.kind.extension()
    ));

    // `create_new` is an atomic no-replace create: same guarantee as
    // `rename_noreplace`, without needing a staging file.
    let mut dest = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
        .map_err(|e| match e.kind() {
            io::ErrorKind::AlreadyExists => AutoarcError::OutputCollision(target.clone()),
            _ => AutoarcError::io(target.clone(), e),
        })?;

    let mut remaining = info.tail_len;
    let mut copied: u64 = 0;
    let mut buf = vec![0u8; COPY_CHUNK];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let n = source
            .read(&mut buf[..want])
            .map_err(|e| AutoarcError::io(path.to_path_buf(), e))?;
        if n == 0 {
            // The host shrank between detection and copy — never happens for
            // a finished file, but the error is clearer than a wrong archive.
            let _ = fs::remove_file(&target);
            return Err(AutoarcError::io(
                path.to_path_buf(),
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "host file truncated while carving tail (got {copied} of {} bytes)",
                        info.tail_len
                    ),
                ),
            )
            .into());
        }
        dest.write_all(&buf[..n])
            .map_err(|e| AutoarcError::io(target.clone(), e))?;
        copied += n as u64;
        remaining -= n as u64;
        reporter.set_position(copied);
    }
    reporter.set_position(info.tail_len);
    reporter.note_tail_carved();

    Ok(CarveOutcome::Archive(target))
}

/// Whether a PE tail hides an archive signature behind its program stub.
/// The read may come back short when the tail itself is smaller than the
/// scan window — that is still enough to spot the payload.
fn carries_embedded_archive(host: &Path, info: &MediaTailInfo) -> Result<bool> {
    let mut file = File::open(host).map_err(|e| AutoarcError::io(host.to_path_buf(), e))?;
    file.seek(SeekFrom::Start(info.tail_start))
        .map_err(|e| AutoarcError::io(host.to_path_buf(), e))?;
    let mut window = vec![0u8; SFX_SCAN_BYTES];
    let n = file
        .read(&mut window)
        .map_err(|e| AutoarcError::io(host.to_path_buf(), e))?;
    window.truncate(n);
    Ok(contains_archive_signature(&window))
}

/// `<dir>/<original file name>.tail.<ext>` next to the host media file.
fn tail_target_path(host: &Path, ext: &str) -> PathBuf {
    let mut name: OsString = host
        .file_name()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| OsString::from("media"));
    name.push(".tail.");
    name.push(ext);
    host.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::Reporter;
    use tempfile::TempDir;

    const ZIP_MAGIC: &[u8] = b"PK\x03\x04";

    /// Minimal legal MP4 chain (must satisfy `infer` and the box walker).
    fn minimal_mp4() -> Vec<u8> {
        let boxed = |btype: &[u8], payload: &[u8]| -> Vec<u8> {
            let mut out = ((8 + payload.len()) as u32).to_be_bytes().to_vec();
            out.extend_from_slice(btype);
            out.extend_from_slice(payload);
            out
        };
        let mut out = boxed(b"ftyp", b"isom\x00\x00\x00\x00isom");
        out.extend(boxed(b"free", b""));
        out.extend(boxed(b"mdat", b"0123456789abcdef"));
        out.extend(boxed(b"moov", b"mvhdFaked"));
        out
    }

    /// A structurally valid PE image: `MZ`, `e_lfanew` pointing at `PE\0\0`.
    fn fake_pe(payload: &[u8]) -> Vec<u8> {
        let mut pe = vec![0u8; 0x100];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        payload_into(&mut pe, 0x44, payload);
        pe
    }

    /// Splice `payload` over `dst` starting at `at`, growing if needed.
    fn payload_into(dst: &mut Vec<u8>, at: usize, payload: &[u8]) {
        if dst.len() < at + payload.len() {
            dst.resize(at + payload.len(), 0);
        }
        dst[at..at + payload.len()].copy_from_slice(payload);
    }

    /// A host media file with `tail` bytes appended.
    fn host_with_tail(dir: &TempDir, name: &str, tail: &[u8]) -> (PathBuf, Vec<u8>) {
        let mut body = minimal_mp4();
        let tail_start = body.len();
        body.extend_from_slice(tail);
        let path = dir.path().join(name);
        std::fs::write(&path, &body).unwrap();
        (path, body[tail_start..].to_vec())
    }

    fn reporter() -> TaskReporter {
        Reporter::new(0).task("tail test")
    }

    #[test]
    fn carve_streams_the_exact_tail_bytes() {
        let dir = TempDir::new().unwrap();
        let mut tail = ZIP_MAGIC.to_vec();
        tail.extend_from_slice(&[0xAAu8; 3 * COPY_CHUNK / 2]); // multi-chunk tail
        let (host, expected) = host_with_tail(&dir, "video.mp4", &tail);

        let carved = carve(&host, &reporter()).unwrap();

        assert_eq!(
            carved,
            CarveOutcome::Archive(dir.path().join("video.mp4.tail.zip"))
        );
        assert_eq!(
            std::fs::read(dir.path().join("video.mp4.tail.zip")).unwrap(),
            expected
        );
    }

    #[test]
    fn carve_leaves_the_host_media_file_untouched() {
        let dir = TempDir::new().unwrap();
        let mut tail = ZIP_MAGIC.to_vec();
        tail.extend_from_slice(&[1u8, 2, 3]);
        let (host, _) = host_with_tail(&dir, "video.mov", &tail);
        let before = std::fs::read(&host).unwrap();

        carve(&host, &reporter()).unwrap();

        assert_eq!(
            std::fs::read(&host).unwrap(),
            before,
            "host media must not change"
        );
    }

    #[test]
    fn carve_refuses_to_overwrite_an_existing_tail() {
        let dir = TempDir::new().unwrap();
        let mut tail = ZIP_MAGIC.to_vec();
        tail.extend_from_slice(&[9u8; 16]);
        let (host, _) = host_with_tail(&dir, "video.mp4", &tail);
        let existing = dir.path().join("video.mp4.tail.zip");
        std::fs::write(&existing, b"previous run").unwrap();

        let err = carve(&host, &reporter()).unwrap_err();
        assert!(
            err.downcast_ref::<AutoarcError>()
                .is_some_and(|e| matches!(e, AutoarcError::OutputCollision(p) if p == &existing)),
            "expected output collision, got {err:#}"
        );
        // The pre-existing file survives untouched.
        assert_eq!(std::fs::read(&existing).unwrap(), b"previous run");
    }

    #[test]
    fn sfx_pe_tail_is_carved_as_exe() {
        let dir = TempDir::new().unwrap();
        // Program stub with an embedded archive signature behind it: the
        // SFX-carrier shape.
        let tail = fake_pe(ZIP_MAGIC);
        let (host, expected) = host_with_tail(&dir, "video.mp4", &tail);

        let carved = carve(&host, &reporter()).unwrap();

        assert_eq!(
            carved,
            CarveOutcome::Archive(dir.path().join("video.mp4.tail.exe"))
        );
        assert_eq!(
            std::fs::read(dir.path().join("video.mp4.tail.exe")).unwrap(),
            expected
        );
    }

    #[test]
    fn plain_pe_tail_is_reported_without_carving() {
        let dir = TempDir::new().unwrap();
        let (host, _) = host_with_tail(&dir, "video.mp4", &fake_pe(&[])); // no archive inside

        let outcome = carve(&host, &reporter()).unwrap();

        assert_eq!(outcome, CarveOutcome::Executable);
        assert!(
            !dir.path().join("video.mp4.tail.exe").exists(),
            "a genuine executable must not be written out"
        );
    }

    #[test]
    fn carve_errors_when_no_tail_exists() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("clean.mp4");
        std::fs::write(&path, minimal_mp4()).unwrap();

        let err = carve(&path, &reporter()).unwrap_err();
        assert!(
            err.to_string().contains("no archive tail"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn tail_target_appends_ext_and_handles_no_parent() {
        assert_eq!(
            tail_target_path(Path::new("/tmp/a/host.mp4"), "rar"),
            PathBuf::from("/tmp/a/host.mp4.tail.rar")
        );
        assert_eq!(
            tail_target_path(Path::new("host.mp4"), "zip"),
            PathBuf::from("./host.mp4.tail.zip")
        );
    }
}
