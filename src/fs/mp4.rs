//! ISO-BMFF (MP4 / MOV / M4V) top-level box-chain parsing.
//!
//! Some files pair a fully playable video with an independent payload
//! appended after the last valid top-level box. By walking the box chain we
//! find where the container ends; if the remaining bytes start with an
//! archive signature (ZIP / RAR / 7z) or a PE image, the appended part can
//! be carved out for normal archive processing.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::fs::FileType;

/// Maximum number of top-level boxes we walk before giving up. Real files
/// have well under a hundred; the cap only stops absurd adversarial input
/// from turning the scan into an unbounded loop.
const MAX_TOP_LEVEL_BOXES: usize = 4096;

/// Longest archive signature we probe for (7z and RAR5 are 6 bytes).
const LONGEST_MAGIC: usize = 6;

/// How many bytes of non-signature padding may sit between the end of the
/// box chain and the archive signature. Some tools align or pad the appended
/// payload; anything beyond this is treated as ordinary trailing junk and the
/// file keeps its video classification.
const TAIL_PADDING_MAX: usize = 64;

/// The payload family found appended behind a media box chain.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TailKind {
    Zip,
    Rar,
    SevenZ,
    /// A Windows PE executable — in practice a self-extracting (SFX) carrier
    /// whose embedded archive sits behind the program stub. Carved as
    /// `<name>.tail.exe` and routed through the existing SFX classification;
    /// a PE without any embedded archive is reported, never carved or run.
    Pe,
}

impl TailKind {
    /// Match an archive signature at the start of `bytes`.
    pub fn from_magic(bytes: &[u8]) -> Option<Self> {
        // ZIP local-file-header; the end-of-central-directory sits at the host
        // file's EOF, which the ZIP backends locate by scanning backwards.
        if bytes.starts_with(ZIP_SIG) {
            return Some(TailKind::Zip);
        }
        // Covers both RAR4 (…\x07\x00) and RAR5 (…\x07\x01\x00).
        if bytes.starts_with(RAR_SIG) {
            return Some(TailKind::Rar);
        }
        if bytes.starts_with(SEVENZ_SIG) {
            return Some(TailKind::SevenZ);
        }
        None
    }

    /// Canonical file extension for the carved tail.
    pub fn extension(self) -> &'static str {
        match self {
            TailKind::Zip => "zip",
            TailKind::Rar => "rar",
            TailKind::SevenZ => "7z",
            TailKind::Pe => "exe",
        }
    }

    /// Short tag used in plan output (`mp4+zip`, `mov+rar`, `mp4+exe`, …).
    pub fn tag(self) -> &'static str {
        self.extension()
    }
}

/// Archive signatures probed at the tail head and inside SFX stubs.
pub(crate) const ZIP_SIG: &[u8] = b"PK\x03\x04";
pub(crate) const RAR_SIG: &[u8] = b"Rar!\x1A\x07";
pub(crate) const SEVENZ_SIG: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// Substring search for any supported archive signature — used to tell an
/// SFX carrier (program stub + embedded archive) from a plain executable.
pub fn contains_archive_signature(window: &[u8]) -> bool {
    [ZIP_SIG, RAR_SIG, SEVENZ_SIG]
        .iter()
        .any(|sig| window.windows(sig.len()).any(|w| w == *sig))
}

/// Whether a genuine PE image starts at absolute `offset`: `MZ` magic plus a
/// `PE\0\0` signature located via the DOS header's `e_lfanew` pointer. Random
/// trailing data — or a renamed archive that merely happens to contain the
/// letters `MZ` — fails this check.
fn is_genuine_pe_at(file: &mut File, offset: u64) -> bool {
    let mut dos = [0u8; 0x40];
    if read_at(file, offset, &mut dos).is_none() || &dos[..2] != b"MZ" {
        return false;
    }
    let e_lfanew = u32::from_le_bytes(dos[0x3C..0x40].try_into().expect("4 bytes")) as u64;
    // Real stubs keep the PE header within the first megabyte; anything more
    // absurd is treated as "not a PE".
    if e_lfanew > 1024 * 1024 {
        return false;
    }
    let mut sig = [0u8; 4];
    read_at(file, offset + e_lfanew, &mut sig).is_some_and(|_| &sig == b"PE\0\0")
}

/// Everything needed to carve (and talk about) a media-embedded archive tail.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct MediaTailInfo {
    /// The container the payload was appended to.
    pub host: FileType,
    /// Absolute offset of the first archive byte (after any tolerated padding).
    pub tail_start: u64,
    /// Bytes from `tail_start` to end of file.
    pub tail_len: u64,
    /// Which archive family the tail is.
    pub kind: TailKind,
}

/// Detect an archive tail behind a valid MP4/MOV box chain.
///
/// Returns `None` unless *every* gate passes: `infer` must classify the file
/// as an ISO-BMFF video, the top-level box chain must parse cleanly and end
/// before EOF, and an archive signature must appear within
/// [`TAIL_PADDING_MAX`] bytes of that end. Anything else keeps the ordinary
/// video classification — a normal (or merely truncated) media file is never
/// mistaken for a carrier.
pub fn media_tail_info(path: &Path) -> Option<MediaTailInfo> {
    let host = match infer::get_from_path(path) {
        Ok(Some(kind)) => match kind.mime_type() {
            "video/mp4" | "video/x-m4v" => FileType::Mp4,
            "video/quicktime" => FileType::Mov,
            _ => return None,
        },
        _ => return None,
    };

    let mut file = File::open(path).ok()?;
    let file_size = file.metadata().ok()?.len();
    if file_size < 8 {
        return None;
    }

    let chain_end = box_chain_end(&mut file, file_size)?;
    let remaining = file_size - chain_end;
    if remaining == 0 {
        return None;
    }

    // Probe [chain_end, chain_end + TAIL_PADDING_MAX + magic) for a payload
    // signature: an archive header, or a genuine PE image (SFX carrier).
    let window_len = (TAIL_PADDING_MAX + LONGEST_MAGIC).min(remaining as usize);
    let mut window = vec![0u8; window_len];
    file.seek(SeekFrom::Start(chain_end)).ok()?;
    file.read_exact(&mut window).ok()?;
    for pos in 0..=window_len.saturating_sub(4) {
        if pos > TAIL_PADDING_MAX {
            break;
        }
        if let Some(kind) = TailKind::from_magic(&window[pos..]).or_else(|| {
            (window[pos..].starts_with(b"MZ")
                && is_genuine_pe_at(&mut file, chain_end + pos as u64))
            .then_some(TailKind::Pe)
        }) {
            let tail_start = chain_end + pos as u64;
            return Some(MediaTailInfo {
                host,
                tail_start,
                tail_len: file_size - tail_start,
                kind,
            });
        }
    }
    None
}

/// Walk the top-level box chain and return the offset where the run of
/// consecutive valid boxes ends — either EOF (a complete container) or the
/// end of the last box whose successor no longer parses (a candidate tail).
///
/// Each box is a 4-byte big-endian size followed by a 4-byte type:
/// - `size == 0`: the box extends to EOF;
/// - `size == 1`: the following 8 bytes are a 64-bit `largesize` giving the
///   total box length (which must cover its own 12-byte header);
/// - otherwise `size >= 8` counts the header itself.
///
/// When the walk stops early it reports the end of the last complete box; the
/// caller then decides via the archive-signature gate whether the leftover
/// bytes are a hidden tail or just ordinary trailing data. `None` is returned
/// only when not even the first box parses (no valid structure at all) or the
/// chain exceeds [`MAX_TOP_LEVEL_BOXES`] boxes.
fn box_chain_end(file: &mut File, file_size: u64) -> Option<u64> {
    let mut offset: u64 = 0; // always the end of the last complete box
    for _ in 0..MAX_TOP_LEVEL_BOXES {
        if offset == file_size {
            return Some(offset);
        }
        let mut header = [0u8; 8];
        if read_at(file, offset, &mut header).is_none() {
            // Truncated header: the chain ended at `offset`.
            return (offset > 0).then_some(offset);
        }
        let btype: [u8; 4] = header[4..8].try_into().ok()?;
        if !plausible_box_type(&btype) {
            return (offset > 0).then_some(offset);
        }
        let end = match u32::from_be_bytes(header[0..4].try_into().ok()?) {
            0 => return Some(file_size),
            1 => {
                let mut largesize = [0u8; 8];
                if read_at(file, offset + 8, &mut largesize).is_none() {
                    return (offset > 0).then_some(offset);
                }
                let largesize = u64::from_be_bytes(largesize);
                if largesize < 12 {
                    return (offset > 0).then_some(offset);
                }
                offset.checked_add(largesize)?
            }
            size if size >= 8 => offset.checked_add(size as u64)?,
            _ => return (offset > 0).then_some(offset),
        };
        if end > file_size {
            return (offset > 0).then_some(offset);
        }
        if end == file_size {
            return Some(end);
        }
        offset = end;
    }
    None
}

/// Read exactly `buf.len()` bytes at absolute `offset`.
fn read_at(file: &mut File, offset: u64, buf: &mut [u8]) -> Option<()> {
    file.seek(SeekFrom::Start(offset)).ok()?;
    file.read_exact(buf).ok()
}

/// Box types are four printable ASCII characters (padding with spaces is
/// common, e.g. `qt  `). QuickTime additionally reserves `0xA9` (©) as the
/// first byte of its metadata atoms, so that byte is accepted there too.
fn plausible_box_type(btype: &[u8; 4]) -> bool {
    btype
        .iter()
        .enumerate()
        .all(|(i, &b)| (0x20..=0x7E).contains(&b) || (i == 0 && b == 0xA9))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    const ZIP_MAGIC: &[u8] = b"PK\x03\x04";
    const RAR5_MAGIC: &[u8] = b"Rar!\x1A\x07\x01\x00";
    const SEVENZ_MAGIC: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

    /// One box: 4-byte big-endian size + type + payload.
    fn box_bytes(btype: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + payload.len());
        out.extend_from_slice(&((8 + payload.len()) as u32).to_be_bytes());
        out.extend_from_slice(btype);
        out.extend_from_slice(payload);
        out
    }

    /// ftyp(isom) + free + mdat + moov — the minimal legal chain used across tests.
    fn minimal_mp4() -> Vec<u8> {
        let mut out = box_bytes(
            b"ftyp",
            b"isom\x00\x00\x00\x00isomiso2mp41", // brand + version + compat
        );
        out.extend(box_bytes(b"free", b""));
        out.extend(box_bytes(b"mdat", b"0123456789abcdef"));
        out.extend(box_bytes(b"moov", b"mvhdFaked"));
        out
    }

    fn write(dir: &TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(bytes).unwrap();
        path
    }

    fn detect(dir: &TempDir, name: &str, bytes: &[u8]) -> Option<MediaTailInfo> {
        media_tail_info(&write(dir, name, bytes))
    }

    // --- happy paths ---------------------------------------------------------

    #[test]
    fn zip_tail_after_clean_chain_is_detected() {
        let dir = TempDir::new().unwrap();
        let mp4 = minimal_mp4();
        let mut bytes = mp4.clone();
        bytes.extend_from_slice(ZIP_MAGIC);
        bytes.extend_from_slice(b"central-directory-bytes PK\x05\x06");

        let info = detect(&dir, "host.mp4", &bytes).expect("tail must be detected");
        assert_eq!(info.kind, TailKind::Zip);
        assert_eq!(info.host, FileType::Mp4);
        assert_eq!(info.tail_start, mp4.len() as u64);
        assert_eq!(info.tail_len, (bytes.len() - mp4.len()) as u64);
    }

    #[test]
    fn rar5_tail_is_detected() {
        let dir = TempDir::new().unwrap();
        let mut bytes = minimal_mp4();
        bytes.extend_from_slice(RAR5_MAGIC);
        bytes.extend_from_slice(&[0u8; 64]);

        let info = detect(&dir, "host.mp4", &bytes).expect("tail must be detected");
        assert_eq!(info.kind, TailKind::Rar);
    }

    #[test]
    fn sevenz_tail_is_detected() {
        let dir = TempDir::new().unwrap();
        let mut bytes = minimal_mp4();
        bytes.extend_from_slice(SEVENZ_MAGIC);
        bytes.extend_from_slice(&[0u8; 32]);

        let info = detect(&dir, "host.mp4", &bytes).expect("tail must be detected");
        assert_eq!(info.kind, TailKind::SevenZ);
    }

    #[test]
    fn quicktime_host_is_reported_as_mov() {
        let dir = TempDir::new().unwrap();
        // Same chain shape, but the ftyp brand makes `infer` say quicktime.
        let mut bytes = box_bytes(b"ftyp", b"qt  \x00\x00\x00\x00qt  ");
        bytes.extend(box_bytes(b"mdat", b"wide"));
        bytes.extend(box_bytes(b"moov", b"mvhd"));
        bytes.extend_from_slice(ZIP_MAGIC);

        let info = detect(&dir, "host.mov", &bytes).expect("tail must be detected");
        assert_eq!(info.host, FileType::Mov);
        assert_eq!(info.kind, TailKind::Zip);
    }

    #[test]
    fn tolerated_padding_before_the_signature_is_skipped() {
        let dir = TempDir::new().unwrap();
        let mp4 = minimal_mp4();
        let padding = [0x00u8; 10];
        let mut bytes = mp4.clone();
        bytes.extend_from_slice(&padding);
        bytes.extend_from_slice(ZIP_MAGIC);
        bytes.extend_from_slice(&[0u8; 16]);

        let info = detect(&dir, "host.mp4", &bytes).expect("padded tail must be detected");
        assert_eq!(info.tail_start, (mp4.len() + padding.len()) as u64);
        assert_eq!(info.tail_len, 20);
    }

    #[test]
    fn padding_over_the_limit_keeps_video_classification() {
        let dir = TempDir::new().unwrap();
        let mut bytes = minimal_mp4();
        bytes.extend_from_slice(&[0x00u8; TAIL_PADDING_MAX + 1]);
        bytes.extend_from_slice(ZIP_MAGIC);

        assert!(detect(&dir, "host.mp4", &bytes).is_none());
    }

    // --- conservative paths ---------------------------------------------------

    #[test]
    fn clean_mp4_has_no_tail() {
        let dir = TempDir::new().unwrap();
        assert!(detect(&dir, "clean.mp4", &minimal_mp4()).is_none());
    }

    #[test]
    fn junk_after_the_chain_keeps_video_classification() {
        let dir = TempDir::new().unwrap();
        let mut bytes = minimal_mp4();
        bytes.extend_from_slice(&[0xEEu8; 100]);
        assert!(detect(&dir, "host.mp4", &bytes).is_none());
    }

    #[test]
    fn truncated_box_header_keeps_video_classification() {
        let dir = TempDir::new().unwrap();
        let mut bytes = minimal_mp4();
        bytes.extend_from_slice(&[0x00u8, 0x00, 0x00]); // partial size+type
        assert!(detect(&dir, "host.mp4", &bytes).is_none());
    }

    #[test]
    fn box_size_below_eight_stops_the_chain() {
        let dir = TempDir::new().unwrap();
        let mut bytes = box_bytes(b"ftyp", b"isom\x00\x00\x00\x00isom");
        // A 4-byte "box" cannot even hold its own header, so the chain ends
        // after ftyp. Without an archive signature behind it, no tail.
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x04, b'm', b'd', b'a', b't']);
        bytes.extend_from_slice(&[0xEEu8; 40]);
        assert!(detect(&dir, "host.mp4", &bytes).is_none());
    }

    #[test]
    fn corrupt_box_before_the_tail_magic_still_carves() {
        let dir = TempDir::new().unwrap();
        // A broken box between the video and the appended archive is just
        // tolerated padding from the chain's point of view: the payload is
        // still carved so the user does not lose real content to a glitch in
        // the host's middle box.
        let mut bytes = box_bytes(b"ftyp", b"isom\x00\x00\x00\x00isom");
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x04, b'm', b'd', b'a', b't']);
        bytes.extend_from_slice(ZIP_MAGIC);
        bytes.extend_from_slice(&[0u8; 32]);
        let info = detect(&dir, "host.mp4", &bytes).expect("tail must be detected");
        assert_eq!(info.tail_start, 28); // after ftyp (20) + broken box (8)
    }

    #[test]
    fn non_printable_box_type_stops_the_chain() {
        let dir = TempDir::new().unwrap();
        let mut bytes = box_bytes(b"ftyp", b"isom\x00\x00\x00\x00isom");
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x0A, 0xFF, 0x00, 0x81, 0xC3]);
        bytes.extend_from_slice(&[0xEEu8; 40]);
        assert!(detect(&dir, "host.mp4", &bytes).is_none());
    }

    #[test]
    fn quicktime_copyright_atom_type_is_accepted() {
        let dir = TempDir::new().unwrap();
        // 0xA9 in the first byte is the QuickTime ©-atom prefix; it must not
        // fail the plausibility check when it appears after the ftyp box.
        let mut bytes = box_bytes(b"ftyp", b"qt  \x00\x00\x00\x00qt  ");
        bytes.extend(box_bytes(b"\xA9too", b"handbrake"));
        bytes.extend(box_bytes(b"mdat", b"junk"));
        bytes.extend_from_slice(ZIP_MAGIC);
        assert!(detect(&dir, "host.mov", &bytes).is_some());
    }

    // --- largesize and size==0 semantics --------------------------------------

    #[test]
    fn size_zero_box_extends_to_eof_and_absorbs_the_tail() {
        let dir = TempDir::new().unwrap();
        // mdat declares size 0 = "to EOF", so appended bytes live *inside*
        // the box: a well-formed container, no tail.
        let mut bytes = box_bytes(b"ftyp", b"isom\x00\x00\x00\x00isom");
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // size == 0
        bytes.extend_from_slice(b"mdat");
        bytes.extend_from_slice(ZIP_MAGIC);
        bytes.extend_from_slice(&[0u8; 32]);

        assert!(detect(&dir, "host.mp4", &bytes).is_none());
    }

    #[test]
    fn largesize_box_is_walked_correctly() {
        let dir = TempDir::new().unwrap();
        let mut bytes = box_bytes(b"ftyp", b"isom\x00\x00\x00\x00isom");
        // size==1 header: 4-byte size, 4-byte type, 8-byte largesize, payload.
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        bytes.extend_from_slice(b"mdat");
        bytes.extend_from_slice(&20u64.to_be_bytes()); // largesize = 12-byte header + 8 payload
        bytes.extend_from_slice(b"payl"); // payload lives inside the box
        let chain_end = bytes.len();
        assert_eq!(chain_end, 20 + 20); // ftyp (20) + largesize box (20)
        bytes.extend_from_slice(ZIP_MAGIC);
        bytes.extend_from_slice(&[0u8; 8]);

        let info = detect(&dir, "host.mp4", &bytes).expect("largesize chain must parse");
        assert_eq!(info.tail_start, chain_end as u64);
    }

    #[test]
    fn largesize_below_header_size_stops_the_chain() {
        let dir = TempDir::new().unwrap();
        let mut bytes = box_bytes(b"ftyp", b"isom\x00\x00\x00\x00isom");
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        bytes.extend_from_slice(b"mdat");
        bytes.extend_from_slice(&8u64.to_be_bytes()); // cannot cover 12-byte header
        bytes.extend_from_slice(&[0xEEu8; 40]);
        assert!(detect(&dir, "host.mp4", &bytes).is_none());
    }

    #[test]
    fn box_running_past_eof_is_malformed() {
        let dir = TempDir::new().unwrap();
        let mut bytes = box_bytes(b"ftyp", b"isom\x00\x00\x00\x00isom");
        // mdat claims 4 KiB but the file ends long before that.
        bytes.extend_from_slice(&[0x00, 0x00, 0x10, 0x00]);
        bytes.extend_from_slice(b"mdat");
        bytes.extend_from_slice(b"short");
        assert!(detect(&dir, "host.mp4", &bytes).is_none());
    }

    // --- PE (SFX) tails --------------------------------------------------------

    /// A structurally valid PE image: `MZ`, `e_lfanew` pointing at `PE\0\0`.
    fn fake_pe(payload: &[u8]) -> Vec<u8> {
        let mut pe = vec![0u8; 0x100];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        let at = 0x44;
        pe.resize(at + payload.len(), 0);
        pe[at..].copy_from_slice(payload);
        pe
    }

    #[test]
    fn pe_tail_is_detected_as_kind_pe() {
        let dir = TempDir::new().unwrap();
        let mp4 = minimal_mp4();
        let mut bytes = mp4.clone();
        bytes.extend(fake_pe(SEVENZ_MAGIC)); // SFX carrier shape

        let info = detect(&dir, "host.mp4", &bytes).expect("PE tail must be detected");
        assert_eq!(info.kind, TailKind::Pe);
        assert_eq!(info.host, FileType::Mp4);
        assert_eq!(info.tail_start, mp4.len() as u64);
        assert_eq!(info.tail_len, (bytes.len() - mp4.len()) as u64);
        assert_eq!(TailKind::Pe.extension(), "exe");
        assert_eq!(TailKind::Pe.tag(), "exe");
    }

    #[test]
    fn pe_tail_after_padding_is_tolerated() {
        let dir = TempDir::new().unwrap();
        let mp4 = minimal_mp4();
        let mut bytes = mp4.clone();
        bytes.extend_from_slice(&[0x00u8; 5]);
        bytes.extend(fake_pe(&[]));
        bytes.extend_from_slice(&[0u8; 64]);

        let info = detect(&dir, "host.mp4", &bytes).expect("padded PE tail must be found");
        assert_eq!(info.kind, TailKind::Pe);
        assert_eq!(info.tail_start, (mp4.len() + 5) as u64);
    }

    #[test]
    fn mz_without_pe_signature_is_not_a_tail() {
        let dir = TempDir::new().unwrap();
        let mut bytes = minimal_mp4();
        bytes.extend_from_slice(b"MZ");
        bytes.extend_from_slice(&[0xEEu8; 200]); // DOS stub garbage, no PE\0\0
        assert!(detect(&dir, "host.mp4", &bytes).is_none());
    }

    #[test]
    fn pe_header_pointer_past_the_file_is_not_a_tail() {
        let dir = TempDir::new().unwrap();
        let mut pe = vec![0u8; 0x40];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3C..0x40].copy_from_slice(&0x0000_FFFFu32.to_le_bytes()); // points way out
        let mut bytes = minimal_mp4();
        bytes.extend(pe);
        assert!(detect(&dir, "host.mp4", &bytes).is_none());
    }

    #[test]
    fn contains_archive_signature_finds_embedded_magics() {
        let stub = fake_pe(RAR5_MAGIC);
        assert!(contains_archive_signature(&stub));
        // fake_pe with no payload is all zeros after the headers: no magic.
        assert!(!contains_archive_signature(&fake_pe(&[])));
        assert!(contains_archive_signature(b"junkjunkPK\x03\x04junk"));
    }

    // --- TailKind -------------------------------------------------------------

    #[test]
    fn tail_kind_magic_matching() {
        assert_eq!(TailKind::from_magic(ZIP_MAGIC), Some(TailKind::Zip));
        assert_eq!(
            TailKind::from_magic(b"Rar!\x1A\x07\x00"),
            Some(TailKind::Rar)
        );
        assert_eq!(TailKind::from_magic(RAR5_MAGIC), Some(TailKind::Rar));
        assert_eq!(TailKind::from_magic(SEVENZ_MAGIC), Some(TailKind::SevenZ));
        assert_eq!(TailKind::from_magic(b"PK\x05\x06"), None);
        assert_eq!(TailKind::from_magic(b""), None);
        assert_eq!(TailKind::from_magic(b"PK\x03"), None);
    }

    #[test]
    fn non_bmff_files_are_rejected_before_box_parsing() {
        let dir = TempDir::new().unwrap();
        // A ZIP with the signature at offset 0 is not a media host, even
        // though bytes further in might look like a box chain.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(ZIP_MAGIC);
        bytes.extend_from_slice(&[0u8; 128]);
        assert!(detect(&dir, "plain.zip", &bytes).is_none());
    }

    #[test]
    fn missing_file_is_none() {
        assert!(media_tail_info(Path::new("/definitely/not/a/video.mp4")).is_none());
    }
}
