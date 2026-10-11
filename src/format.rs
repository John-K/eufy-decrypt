//! On-disk format constants for eufy `.dat`/`.zxvideo` recordings.
//!
//! These are known-good for the eufy Indoor Cam 2K (T8400) on firmware 2.2.0.0,
//! as documented by Christian Guevara (thedveloper.com) and the USENIX WOOT'24
//! paper "Reverse Engineering the Eufy Ecosystem" (Goeman et al.).
//!
//! Every constant that describes the container lives here so the parser can be
//! retargeted to another eufy model by editing one file. Run `eufy-decrypt
//! inspect <file>` first to confirm these match your camera before trusting a
//! decrypt.

/// Magic bytes at the start of every record.
pub const MAGIC: &[u8; 4] = b"XZYH";

// --- field offsets, measured from the start of the magic ---
/// u8 stream type.
pub const OFF_STREAM_TYPE: usize = 4;
/// u32 little-endian: record size minus 16 (next record = this + 16).
pub const OFF_SIZE_FIELD: usize = 6;
/// u16 little-endian frame type.
pub const OFF_FRAME_TYPE: usize = 10;
/// u32 little-endian payload length.
pub const OFF_PAYLOAD_LEN: usize = 16;
/// u16 little-endian fields in a video record header (present when the record
/// is long enough to include them).
pub const OFF_FPS: usize = 24;
pub const OFF_WIDTH: usize = 26;
pub const OFF_HEIGHT: usize = 28;

/// Record size field is this much smaller than the real record size.
pub const SIZE_FIELD_BIAS: u32 = 16;

/// Minimum bytes we need present after a magic to read all header fields.
pub const MIN_HEADER_PROBE: usize = OFF_PAYLOAD_LEN + 4;

// --- stream types (OFF_STREAM_TYPE) ---
pub const STREAM_VIDEO: u8 = 0x14;
pub const STREAM_AUDIO: u8 = 0x15;

// --- frame types (low byte of OFF_FRAME_TYPE) ---
#[allow(dead_code)]
pub const FRAME_PFRAME: u16 = 1;
#[allow(dead_code)]
pub const FRAME_AUDIO: u16 = 2;
pub const FRAME_IFRAME: u16 = 3;
/// OR'd into the frame type when more fragments of the same frame follow.
pub const FRAME_MORE_FRAGMENTS: u16 = 0x100;

/// Only the first this-many bytes of each keyframe fragment are AES encrypted;
/// the remainder of the fragment is plaintext video.
pub const KF_ENC_PREFIX: usize = 128;

/// AES-128 block size and key size in bytes.
pub const AES_BLOCK: usize = 16;
pub const AES_KEY_LEN: usize = 16;

/// Default video frame rate used when remuxing (the T8400 records 15 fps).
pub const DEFAULT_FPS: u32 = 15;

/// Annex-B 4-byte start code (H.264 and HEVC).
pub const ANNEXB_START: &[u8; 4] = b"\x00\x00\x00\x01";
