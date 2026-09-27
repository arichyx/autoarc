//! End-to-end coverage for media files carrying an appended archive behind
//! the box chain, driven through the real runner so the whole chain runs:
//!
//! ```text
//! media_tail_aes.mp4       (valid MP4 box chain + appended archive)
//! └─ carve → media_tail_aes.mp4.tail.zip (WinZip AES-256, "outer-aes")
//!    └─ inner_nopass.zip                 (plain zip)
//!       └─ payload.exe                   (RAR5 renamed to .exe)
//!          └─ clip.movTRASH → clip.mp4   (mini MP4, garbage suffix fixed)
//! ```
//!
//! This file is a separate integration-test binary on purpose: it initialises
//! the process-wide password list with the fixture password, which latches a
//! `OnceLock` and must not leak into other test binaries' assumptions.

use std::fs;
use std::path::PathBuf;

use autoarc::extractors;
use autoarc::fs::{FileType, get_file_type};
use autoarc::progress::{Reporter, TaskReporter};
use tempfile::TempDir;

/// The AES password baked into `media_tail_aes.mp4`'s tail (a fixture placeholder,
/// never a real credential).
const OUTER_PASSWORD: &str = "outer-aes";

/// Byte-exact content of the final `clip.mp4` — the mini MP4 built by
/// `tests/fixtures/gen.sh` (must match its printf byte-for-byte).
const MINI_MP4: &[u8] = b"\
\x00\x00\x00\x1cftypisom\x00\x00\x00\x00isomiso2mp41\
\x00\x00\x00\x08free\
\x00\x00\x00\x18mdat0123456789abcdef\
\x00\x00\x00\x11moovmvhdFaked";

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn tempdir() -> TempDir {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test-tmp");
    fs::create_dir_all(&base).unwrap();
    TempDir::new_in(&base).unwrap()
}

fn copy_fixture(td: &TempDir, name: &str) -> PathBuf {
    let src = fixtures_dir().join(name);
    let dst = td.path().join(name);
    fs::copy(&src, &dst).unwrap_or_else(|e| panic!("copy {}: {e}", src.display()));
    dst
}

fn reporter() -> TaskReporter {
    Reporter::new(0).task("media tail")
}

// ============================================================================
// Classification
// ============================================================================

#[test]
fn tail_host_fixture_classifies_as_mp4tail() {
    let td = tempdir();
    let host = copy_fixture(&td, "media_tail_aes.mp4");

    assert_eq!(get_file_type(&host), FileType::Mp4Tail);

    let info = autoarc::fs::media_tail_info(&host).expect("tail info");
    assert_eq!(info.kind, autoarc::fs::TailKind::Zip);
    assert_eq!(info.host, FileType::Mp4);
    // The mini MP4 chain is exactly 77 bytes; the archive follows immediately.
    assert_eq!(info.tail_start, 77);
    assert_eq!(
        info.tail_len,
        (fs::metadata(&host).unwrap().len() - 77) as u64
    );
}

// ============================================================================
// The full appended-tail chain through the real runner
// ============================================================================

#[tokio::test]
async fn full_tail_chain_extracts_and_leaves_the_host_untouched() {
    autoarc::config::init_password_list(vec![OUTER_PASSWORD.to_string()]);

    let td = tempdir();
    let host = copy_fixture(&td, "media_tail_aes.mp4");
    let original = fs::read(&host).unwrap();

    autoarc::runner::run(td.path().to_path_buf(), 1, false, true, 1, Vec::new())
        .await
        .expect("runner must complete the whole chain");

    // The media part is data to preserve, not a work item: byte-identical afterwards.
    assert_eq!(
        fs::read(&host).unwrap(),
        original,
        "host media must be untouched"
    );

    // Carved tail exists next to it, classified as a plain zip.
    let tail = td.path().join("media_tail_aes.mp4.tail.zip");
    assert!(tail.exists(), "carved tail must exist");
    assert_eq!(get_file_type(&tail), FileType::Zip);

    // …and its bytes are exactly the appended region of the host.
    assert_eq!(fs::read(&tail).unwrap(), &original[77..]);

    // Every nesting level resolved in place.
    let inner = td
        .path()
        .join("media_tail_aes.mp4.tail.zip_out/inner_nopass.zip");
    assert!(
        inner.exists(),
        "AES layer must extract (password {OUTER_PASSWORD:?})"
    );

    let payload = td
        .path()
        .join("media_tail_aes.mp4.tail.zip_out/inner_nopass.zip_out/payload.exe");
    assert!(payload.exists(), "plain zip layer must extract");

    // The renamed RAR is classified by magic, not extension, and its video
    // payload lands with the canonical extension (garbage suffix dropped).
    assert_eq!(get_file_type(&payload), FileType::Rar);
    let final_video = td
        .path()
        .join("media_tail_aes.mp4.tail.zip_out/inner_nopass.zip_out/payload.exe_out/clip.mp4");
    assert_eq!(
        fs::read(&final_video).unwrap(),
        MINI_MP4,
        "final payload bytes must match the fixture source",
    );
    // The garbage-suffixed original name is gone (renamed, not duplicated).
    assert!(
        !td.path()
            .join(
                "media_tail_aes.mp4.tail.zip_out/inner_nopass.zip_out/payload.exe_out/clip.movTRASH"
            )
            .exists()
    );
}

// ============================================================================
// Windows-SFX tails (mp4 + PE stub + embedded archive)
// ============================================================================

#[tokio::test]
async fn sfx_tail_carves_exe_and_extracts_via_unar() {
    // media_tail_sfx.mp4 = mini MP4 + hand-made Windows SFX (PE stub, embedded
    // zip). The runner must carve it as .tail.exe, classify the carve as
    // Sfx, and unpack it through the unar subprocess.
    //
    // The password list is process-wide (OnceLock); every test initialises
    // it with the same candidates so parallel test order cannot matter —
    // the SFX chain simply matches on the empty password first.
    autoarc::config::init_password_list(vec![OUTER_PASSWORD.to_string()]);

    let td = tempdir();
    let host = copy_fixture(&td, "media_tail_sfx.mp4");
    let original = fs::read(&host).unwrap();

    autoarc::runner::run(td.path().to_path_buf(), 1, false, true, 1, Vec::new())
        .await
        .expect("SFX-tail chain must complete");

    assert_eq!(
        fs::read(&host).unwrap(),
        original,
        "host media must be untouched"
    );

    let tail = td.path().join("media_tail_sfx.mp4.tail.exe");
    assert!(tail.exists(), "PE tail must be carved as .tail.exe");
    assert_eq!(
        fs::read(&tail).unwrap(),
        &original[77..],
        "carved bytes must be the appended region",
    );

    let video = td.path().join("media_tail_sfx.mp4.tail.exe_out/clip.mp4");
    assert_eq!(fs::read(&video).unwrap(), MINI_MP4);
}

#[test]
fn plain_pe_tail_is_reported_without_carving() {
    // A PE tail with no embedded archive is a genuine executable: reported
    // only — nothing written, nothing enqueued, never run.
    let td = tempdir();
    let mut body = mini_mp4_bytes();
    body.extend(fake_pe_bytes());
    let host = td.path().join("plain-pe.mp4");
    fs::write(&host, &body).unwrap();

    assert_eq!(get_file_type(&host), FileType::Mp4Tail);

    let children =
        extractors::run(FileType::Mp4Tail, host.clone(), host.clone(), &reporter()).unwrap();
    assert!(children.is_empty(), "a genuine PE must not be enqueued");
    assert!(
        !td.path().join("plain-pe.mp4.tail.exe").exists(),
        "a genuine PE must not be written out",
    );
    assert_eq!(
        fs::read(&host).unwrap(),
        body,
        "host media must be untouched"
    );
}

/// ftyp(isom) + free + mdat + moov — the same chain `tests/fixtures/gen.sh`
/// builds for the tail-host fixtures.
fn mini_mp4_bytes() -> Vec<u8> {
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

/// A structurally valid PE image with no archive signature anywhere inside.
fn fake_pe_bytes() -> Vec<u8> {
    let mut pe = vec![0u8; 0x100];
    pe[..2].copy_from_slice(b"MZ");
    pe[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    pe[0x40..0x44].copy_from_slice(b"PE\0\0");
    pe
}

// ============================================================================
// Native RAR backend + the unar fallback
// ============================================================================

#[test]
fn renamed_rar5_extracts_via_native_backend() {
    // `payload.exe` is a RAR5 despite its extension — the native unrar crate
    // handles it once the runner routes by magic.
    let td = tempdir();
    let payload = copy_fixture(&td, "payload.exe");

    let children =
        extractors::run(FileType::Rar, payload.clone(), payload.clone(), &reporter()).unwrap();
    assert!(children.is_empty(), "a bare RAR has no nested archives");

    let out = td.path().join("payload.exe_out/clip.mp4");
    assert_eq!(fs::read(&out).unwrap(), MINI_MP4);
}

#[test]
fn damaged_rar_retries_through_the_unar_subprocess() {
    // A truncated RAR fails the native backend in the "damaged data" class,
    // which must route through the `unar` subprocess before giving up. The
    // subprocess cannot decode the missing bytes either, so the task fails —
    // but with the unar diagnostic, proving the fallback actually ran.
    let td = tempdir();
    let payload = copy_fixture(&td, "payload.exe");
    let data = fs::read(&payload).unwrap();
    let cut = data.len() / 2;
    fs::write(&payload, &data[..cut]).unwrap();

    autoarc::config::init_password_list(vec![OUTER_PASSWORD.to_string()]);

    let error = extractors::run(FileType::Rar, payload.clone(), payload.clone(), &reporter())
        .expect_err("truncated RAR must fail");
    let message = format!("{error:#}");
    assert!(
        message.contains("unar failed"),
        "error must come from the unar fallback, got: {message}"
    );
}

#[test]
fn carving_requires_an_actual_tail() {
    let td = tempdir();
    let clean = td.path().join("plain.mp4");
    fs::write(&clean, MINI_MP4).unwrap();

    let error = extractors::run(FileType::Mp4Tail, clean.clone(), clean.clone(), &reporter())
        .expect_err("a clean MP4 must not be carveable");
    assert!(
        format!("{error:#}").contains("no archive tail"),
        "unexpected error: {error:#}"
    );
    assert!(!td.path().join("plain.mp4.tail.zip").exists());
}
