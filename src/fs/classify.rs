//! File-type classification using `infer` magic-byte sniffing, with a `file(1)` fallback.

use std::io::Read;
use std::path::Path;

/// How many bytes of a PE/EXE body we scan for an embedded archive signature.
/// SFX stubs are almost always smaller than this, and it bounds the I/O cost
/// for huge `.exe` files.
const SFX_SCAN_BYTES: usize = 4 * 1024 * 1024;

/// High-level classification of a single file.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum FileType {
    /// Single-volume ZIP archive.
    Zip,
    /// RAR archive (any version).
    Rar,
    /// 7-Zip archive.
    SevenZ,
    /// MP4 / M4V video container.
    Mp4,
    /// Apple QuickTime / MOV video container.
    Mov,
    /// MPEG transport-stream video.
    TS,
    /// Archive that must be handled by the `unar` subprocess backend:
    /// a multi-volume set whose first part has a `.z01` / `.001` / `.7z.001`
    /// extension. Native Rust crates can't join volumes, so we delegate.
    Multi,
    /// Self-extracting `.exe` archive (SFX): a Windows PE executable with a
    /// 7z / RAR / ZIP payload appended after the stub. Also handled by the
    /// `unar` subprocess backend, which transparently skips the PE prefix.
    Sfx,
    /// MP3 / FLAC / OGG / WAV / AAC / M4A — any recognised audio container.
    Audio,
    /// Portable Document Format.
    Pdf,
    /// Microsoft Word document (modern `.docx` or legacy `.doc`).
    Docx,
    /// Microsoft PowerPoint presentation (modern `.pptx` or legacy `.ppt`).
    Pptx,
    /// Microsoft Excel spreadsheet (modern `.xlsx` or legacy `.xls`).
    Xlsx,
    /// Plain text / source code (detected via the `file(1)` fallback).
    Text,
    /// Anything we couldn't identify.
    Unknown,
}

/// Detect a file's [`FileType`].
///
/// Magic bytes are checked first via `infer`; if that yields nothing we fall back
/// to `file -I -b`, which covers MPEG-TS streams and plain-text files that
/// carry no distinguishing magic bytes. When `infer` reports a Windows PE
/// executable we additionally scan the first few megabytes for an embedded
/// 7z / RAR / ZIP signature (self-extracting archives), routing any hit
/// through the `unar` backend.
pub fn get_file_type(path: &Path) -> FileType {
    match infer::get_from_path(path) {
        Ok(Some(kind)) => match kind.mime_type() {
            // --- archives -----------------------------------------------
            "application/zip" => {
                // ZIP magic with a `.z01`/`.001` extension means a split archive.
                let is_multi = path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| {
                        ext.eq_ignore_ascii_case("z01") || ext.eq_ignore_ascii_case("001")
                    });
                if is_multi {
                    FileType::Multi
                } else {
                    FileType::Zip
                }
            }
            "application/vnd.rar" => FileType::Rar,
            "application/x-7z-compressed" => {
                // A `.7z.001` first-part (extension `001`) is a multi-volume
                // split; the native 7z crate can't join volumes, so route it
                // to `unar` along with the rest of the split family.
                let is_multi = path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("001"));
                if is_multi {
                    FileType::Multi
                } else {
                    FileType::SevenZ
                }
            }
            // --- videos -------------------------------------------------
            "video/mp4" | "video/x-m4v" => FileType::Mp4,
            "video/quicktime" => FileType::Mov,
            // --- audio --------------------------------------------------
            "audio/mpeg" | "audio/aac" | "audio/x-flac" | "audio/flac" | "audio/ogg"
            | "audio/wav" | "audio/x-wav" | "audio/x-aiff" | "audio/m4a" | "audio/midi"
            | "audio/x-midi" => FileType::Audio,
            // --- documents ----------------------------------------------
            "application/pdf" => FileType::Pdf,
            "application/msword"
            | "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => {
                FileType::Docx
            }
            "application/vnd.ms-powerpoint"
            | "application/vnd.openxmlformats-officedocument.presentationml.presentation" => {
                FileType::Pptx
            }
            "application/vnd.ms-excel"
            | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => FileType::Xlsx,
            // --- SFX ----------------------------------------------------
            "application/vnd.microsoft.portable-executable" => {
                // Likely an SFX — scan the body for a payload signature.
                detect_sfx(path).unwrap_or(FileType::Unknown)
            }
            _ => FileType::Unknown,
        },
        Ok(None) => detect_via_file_cmd(path).unwrap_or(FileType::Unknown),
        Err(_) => FileType::Unknown,
    }
}

/// Search the first [`SFX_SCAN_BYTES`] of `path` for a 7z / RAR / ZIP magic
/// signature. Returns [`FileType::Sfx`] on any hit so the file is routed to
/// the `unar` subprocess, which handles SFX binaries natively.
fn detect_sfx(path: &Path) -> Option<FileType> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; SFX_SCAN_BYTES];
    // `read` may return short; that's fine — we just search what we got.
    let n = file.read(&mut buf).ok()?;
    let window = &buf[..n];

    // 7z:  37 7A BC AF 27 1C
    // RAR4: "Rar!" 1A 07 00
    // RAR5: "Rar!" 1A 07 01 00
    // ZIP:  "PK" 03 04
    const SEVENZ: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
    const RAR: &[u8] = b"Rar!\x1A\x07";
    const ZIP: &[u8] = b"PK\x03\x04";

    if contains(window, SEVENZ) || contains(window, RAR) || contains(window, ZIP) {
        Some(FileType::Sfx)
    } else {
        None
    }
}

/// Plain substring search — small enough that the standard library's naive
/// scan is fine for our ~4 MiB window.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Fallback that invokes `file -I -b <path>` to spot formats `infer` misses.
///
/// Handles MPEG-TS streams and plain text / source code (anything reported as
/// a `text/*` mime). Returns `None` if the binary is missing, exits non-zero,
/// or emits non-UTF-8 data; in those cases the caller treats the file as
/// [`FileType::Unknown`].
fn detect_via_file_cmd(path: &Path) -> Option<FileType> {
    let output = std::process::Command::new("file")
        .arg("-I")
        .arg("-b")
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = std::str::from_utf8(&output.stdout).ok()?;
    let lower = stdout.to_lowercase();
    if lower.starts_with("video/mp2t") {
        Some(FileType::TS)
    } else if lower.starts_with("text/") && !lower.contains("charset=binary") {
        // `file -I -b` returns `text/plain; charset=binary` for any
        // unrecognised binary blob. We only treat it as real text when the
        // charset is a textual one (utf-8 / us-ascii / iso-8859-* / etc.).
        Some(FileType::Text)
    } else {
        None
    }
}

/// Returns `true` when the file is one of the supported archive formats.
pub fn is_type_archive(t: FileType) -> bool {
    matches!(
        t,
        FileType::Zip | FileType::Rar | FileType::SevenZ | FileType::Multi | FileType::Sfx
    )
}

/// Returns `true` for the video formats the pipeline can post-process.
pub fn is_type_video(t: FileType) -> bool {
    matches!(t, FileType::Mp4 | FileType::Mov | FileType::TS)
}

/// Returns `true` for the non-archive, non-video media formats the scanner
/// merely *reports* (it never renames or rewrites them). Kept as a single
/// bucket so the runner can surface an aggregate count in the plan.
pub fn is_type_document(t: FileType) -> bool {
    matches!(
        t,
        FileType::Audio
            | FileType::Pdf
            | FileType::Docx
            | FileType::Pptx
            | FileType::Xlsx
            | FileType::Text
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    // --- Magic-byte fixtures -------------------------------------------------
    const ZIP_MAGIC: &[u8] = b"PK\x03\x04";
    const SEVENZ_MAGIC: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
    const RAR4_MAGIC: &[u8] = b"Rar!\x1A\x07\x00";
    const QUICKTIME_MAGIC: &[u8] = b"\x00\x00\x00\x14ftypqt  \x00\x00\x00\x00qt  ";
    // Just enough of a PE header for `infer` to classify the file as
    // application/vnd.microsoft.portable-executable.
    const PE_STUB: &[u8] = b"MZ\x90\x00";

    /// Build a file named `name` inside `dir` whose contents are `bytes` plus
    /// 64 zero bytes of padding (so `infer` always has enough to sniff).
    fn write_file(dir: &TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(bytes).unwrap();
        f.write_all(&[0u8; 64]).unwrap();
        path
    }

    /// Variant of [`write_file`] without the trailing zero padding — used by
    /// text-fallback tests, where those NUL bytes would make `file(1)` report
    /// `charset=binary` and break the heuristic.
    fn write_file_raw(dir: &TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(bytes).unwrap();
        path
    }

    // --- Pure helpers --------------------------------------------------------

    #[test]
    fn is_type_archive_covers_all_archive_variants() {
        assert!(is_type_archive(FileType::Zip));
        assert!(is_type_archive(FileType::Rar));
        assert!(is_type_archive(FileType::SevenZ));
        assert!(is_type_archive(FileType::Multi));
        assert!(is_type_archive(FileType::Sfx));
        assert!(!is_type_archive(FileType::Mp4));
        assert!(!is_type_archive(FileType::Mov));
        assert!(!is_type_archive(FileType::TS));
        assert!(!is_type_archive(FileType::Unknown));
    }

    #[test]
    fn is_type_video_covers_video_variants() {
        assert!(is_type_video(FileType::Mp4));
        assert!(is_type_video(FileType::Mov));
        assert!(is_type_video(FileType::TS));
        assert!(!is_type_video(FileType::Zip));
        assert!(!is_type_video(FileType::Unknown));
    }

    #[test]
    fn is_type_document_covers_all_document_variants() {
        assert!(is_type_document(FileType::Audio));
        assert!(is_type_document(FileType::Pdf));
        assert!(is_type_document(FileType::Docx));
        assert!(is_type_document(FileType::Pptx));
        assert!(is_type_document(FileType::Xlsx));
        assert!(is_type_document(FileType::Text));
        // Archives / videos / unknown must stay out of the document bucket so
        // the runner never starts renaming or reporting them in that branch.
        assert!(!is_type_document(FileType::Zip));
        assert!(!is_type_document(FileType::Rar));
        assert!(!is_type_document(FileType::SevenZ));
        assert!(!is_type_document(FileType::Multi));
        assert!(!is_type_document(FileType::Sfx));
        assert!(!is_type_document(FileType::Mp4));
        assert!(!is_type_document(FileType::Mov));
        assert!(!is_type_document(FileType::TS));
        assert!(!is_type_document(FileType::Unknown));
    }

    #[test]
    fn contains_matches_needle_inside_haystack() {
        let haystack = b"prefix\x00\x01PK\x03\x04suffix";
        assert!(contains(haystack, ZIP_MAGIC));
        assert!(!contains(haystack, SEVENZ_MAGIC));
    }

    // --- get_file_type: archives --------------------------------------------

    #[test]
    fn plain_zip_is_zip() {
        let dir = TempDir::new().unwrap();
        let p = write_file(&dir, "foo.zip", ZIP_MAGIC);
        assert_eq!(get_file_type(&p), FileType::Zip);
    }

    #[test]
    fn zip_with_z01_extension_is_multi() {
        let dir = TempDir::new().unwrap();
        let p = write_file(&dir, "foo.z01", ZIP_MAGIC);
        assert_eq!(get_file_type(&p), FileType::Multi);
    }

    #[test]
    fn zip_with_uppercase_z01_extension_is_multi() {
        let dir = TempDir::new().unwrap();
        let p = write_file(&dir, "foo.Z01", ZIP_MAGIC);
        assert_eq!(get_file_type(&p), FileType::Multi);
    }

    #[test]
    fn zip_with_001_extension_is_multi() {
        let dir = TempDir::new().unwrap();
        let p = write_file(&dir, "foo.001", ZIP_MAGIC);
        assert_eq!(get_file_type(&p), FileType::Multi);
    }

    #[test]
    fn zip_with_unrelated_extension_is_still_zip() {
        // The binary content wins over a misleading extension for the base case.
        let dir = TempDir::new().unwrap();
        let p = write_file(&dir, "foo.txt", ZIP_MAGIC);
        assert_eq!(get_file_type(&p), FileType::Zip);
    }

    #[test]
    fn plain_7z_is_sevenz() {
        let dir = TempDir::new().unwrap();
        let p = write_file(&dir, "foo.7z", SEVENZ_MAGIC);
        assert_eq!(get_file_type(&p), FileType::SevenZ);
    }

    #[test]
    fn sevenz_with_001_extension_is_multi() {
        // Regression guard: .7z.001 used to be classified as SevenZ and then
        // fail in the native 7z backend with UnexpectedEof.
        let dir = TempDir::new().unwrap();
        let p = write_file(&dir, "foo.7z.001", SEVENZ_MAGIC);
        assert_eq!(get_file_type(&p), FileType::Multi);
    }

    #[test]
    fn rar_is_rar() {
        let dir = TempDir::new().unwrap();
        let p = write_file(&dir, "foo.rar", RAR4_MAGIC);
        assert_eq!(get_file_type(&p), FileType::Rar);
    }

    #[test]
    fn quicktime_with_pdf_extension_is_mov() {
        let dir = TempDir::new().unwrap();
        let p = write_file(&dir, "disguised.pdf", QUICKTIME_MAGIC);
        assert_eq!(get_file_type(&p), FileType::Mov);
    }

    // --- get_file_type: SFX detection ---------------------------------------

    #[test]
    fn pe_with_embedded_sevenz_is_sfx() {
        let dir = TempDir::new().unwrap();
        let mut body = PE_STUB.to_vec();
        body.extend_from_slice(&[0u8; 256]); // fake PE stub padding
        body.extend_from_slice(SEVENZ_MAGIC);
        let p = write_file(&dir, "installer.exe", &body);
        assert_eq!(get_file_type(&p), FileType::Sfx);
    }

    #[test]
    fn pe_with_embedded_rar_is_sfx() {
        let dir = TempDir::new().unwrap();
        let mut body = PE_STUB.to_vec();
        body.extend_from_slice(&[0u8; 256]);
        body.extend_from_slice(RAR4_MAGIC);
        let p = write_file(&dir, "installer.exe", &body);
        assert_eq!(get_file_type(&p), FileType::Sfx);
    }

    #[test]
    fn pe_with_embedded_zip_is_sfx() {
        let dir = TempDir::new().unwrap();
        let mut body = PE_STUB.to_vec();
        body.extend_from_slice(&[0u8; 256]);
        body.extend_from_slice(ZIP_MAGIC);
        let p = write_file(&dir, "installer.exe", &body);
        assert_eq!(get_file_type(&p), FileType::Sfx);
    }

    #[test]
    fn pe_without_archive_payload_is_unknown() {
        let dir = TempDir::new().unwrap();
        let mut body = PE_STUB.to_vec();
        body.extend_from_slice(&[0xAAu8; 1024]); // no archive magic anywhere
        let p = write_file(&dir, "harmless.exe", &body);
        assert_eq!(get_file_type(&p), FileType::Unknown);
    }

    // --- get_file_type: documents ------------------------------------------
    //
    // We stick to magic-byte signatures `infer` definitely recognises and
    // skip Office docx/xlsx/pptx: those require a fully-formed ZIP central
    // directory with specific `[Content_Types].xml`, which would mean
    // shipping real fixtures in the test module. Integration-level coverage
    // can exercise those via real files later if needed.

    #[test]
    fn pdf_magic_is_pdf() {
        // %PDF-1.4 header is enough for infer to return application/pdf.
        let dir = TempDir::new().unwrap();
        let p = write_file(&dir, "doc.pdf", b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
        assert_eq!(get_file_type(&p), FileType::Pdf);
    }

    #[test]
    fn mp3_id3_magic_is_audio() {
        // ID3v2 header: "ID3" + version + flags + 4-byte synchsafe size.
        let dir = TempDir::new().unwrap();
        let p = write_file(&dir, "track.mp3", b"ID3\x03\x00\x00\x00\x00\x00\x00");
        assert_eq!(get_file_type(&p), FileType::Audio);
    }

    #[test]
    fn flac_magic_is_audio() {
        let dir = TempDir::new().unwrap();
        let p = write_file(&dir, "track.flac", b"fLaC");
        assert_eq!(get_file_type(&p), FileType::Audio);
    }

    #[test]
    fn ogg_magic_is_audio() {
        // OggS + version (0) + header type + granule position + ...
        let dir = TempDir::new().unwrap();
        let p = write_file(
            &dir,
            "track.ogg",
            b"OggS\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00",
        );
        assert_eq!(get_file_type(&p), FileType::Audio);
    }

    #[test]
    fn wav_magic_is_audio() {
        // RIFF + size (4B placeholder) + WAVE + fmt  chunk start.
        let dir = TempDir::new().unwrap();
        let p = write_file(&dir, "track.wav", b"RIFF\x00\x00\x00\x00WAVEfmt ");
        assert_eq!(get_file_type(&p), FileType::Audio);
    }

    #[test]
    fn plain_text_falls_back_to_text_via_file_cmd() {
        // Plain ASCII has no magic bytes, so infer returns None and the
        // `file -I -b` fallback should classify it as text/*.
        let dir = TempDir::new().unwrap();
        let p = write_file_raw(
            &dir,
            "notes.txt",
            b"hello world, this is a plain text file.\n",
        );
        assert_eq!(get_file_type(&p), FileType::Text);
    }

    // --- get_file_type: unrecognised ----------------------------------------

    #[test]
    fn random_bytes_are_unknown() {
        // Deliberately non-text, non-archive binary noise: stays Unknown even
        // though the `file -I -b` fallback now recognises `text/*`.
        let dir = TempDir::new().unwrap();
        let p = write_file(
            &dir,
            "mystery.bin",
            &[0xFFu8, 0xFE, 0x00, 0x01, 0x80, 0x81, 0x82, 0x83],
        );
        assert_eq!(get_file_type(&p), FileType::Unknown);
    }

    #[test]
    fn missing_file_is_unknown() {
        assert_eq!(
            get_file_type(std::path::Path::new("/definitely/does/not/exist.zip")),
            FileType::Unknown
        );
    }
}
