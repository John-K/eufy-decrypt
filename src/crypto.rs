//! AES-128-ECB decryption of eufy keyframe fragments.
//!
//! Only the first `KF_ENC_PREFIX` bytes of each keyframe fragment are
//! encrypted; the rest is plaintext video. ECB has no IV and we never pad, so
//! only whole 16-byte blocks within the prefix are decrypted and any trailing
//! bytes pass through untouched (matching the author's reference script).

use crate::container::VideoFrame;
use crate::format::*;
use aes::Aes128;
use aes::cipher::{Array, BlockCipherDecrypt, KeyInit};
use anyhow::{Context, Result, bail};

/// A 16-byte AES-128 key.
#[derive(Clone, Copy)]
pub struct Key(pub [u8; AES_KEY_LEN]);

impl Key {
    /// Parse a key given either as 32 hex chars or as 16 raw ASCII bytes
    /// (the eufy key is itself 16 ASCII characters, e.g. `89DD11D2DF09ED7D`).
    pub fn parse(s: &str) -> Result<Key> {
        if s.len() == AES_KEY_LEN {
            let mut k = [0u8; AES_KEY_LEN];
            k.copy_from_slice(s.as_bytes());
            return Ok(Key(k));
        }
        let bytes = hex::decode(s).with_context(|| {
            format!("key must be 16 ASCII chars or 32 hex chars, got {} chars", s.len())
        })?;
        if bytes.len() != AES_KEY_LEN {
            bail!("hex key must decode to {AES_KEY_LEN} bytes, got {}", bytes.len());
        }
        let mut k = [0u8; AES_KEY_LEN];
        k.copy_from_slice(&bytes);
        Ok(Key(k))
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

/// Decrypt the whole-block portion of `blob` in place-style, returning a new
/// buffer: decrypted leading blocks followed by any trailing partial block
/// verbatim.
pub fn aes_ecb_decrypt(key: &Key, blob: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(&Array::from(key.0));
    let whole = blob.len() - (blob.len() % AES_BLOCK);
    let mut out = Vec::with_capacity(blob.len());
    let mut i = 0;
    while i < whole {
        let mut block = Array::from(<[u8; AES_BLOCK]>::try_from(&blob[i..i + AES_BLOCK]).unwrap());
        cipher.decrypt_block(&mut block);
        out.extend_from_slice(&block);
        i += AES_BLOCK;
    }
    out.extend_from_slice(&blob[whole..]);
    out
}

/// A fragment is encrypted iff it does NOT already begin with an Annex-B start
/// code. This is the model-agnostic test: plaintext video fragments (P-frames,
/// and on some models whole frames tagged as keyframes) begin with
/// `00 00 00 01`, while an AES-encrypted keyframe prefix is ciphertext and does
/// not. It is correct for both the T8400 (every keyframe fragment's prefix is
/// encrypted) and the T8416 (only true keyframe records are encrypted, though
/// all video records share one frame-type tag).
pub fn fragment_is_encrypted(frag: &[u8]) -> bool {
    frag.len() >= 4 && &frag[..4] != ANNEXB_START
}

/// Decrypt a keyframe: for each fragment that is encrypted, decrypt its first
/// `KF_ENC_PREFIX` bytes and leave the rest; pass plaintext fragments through.
pub fn decrypt_iframe(key: &Key, fragments: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for frag in fragments {
        if fragment_is_encrypted(frag) {
            let n = frag.len().min(KF_ENC_PREFIX);
            out.extend_from_slice(&aes_ecb_decrypt(key, &frag[..n]));
            out.extend_from_slice(&frag[n..]);
        } else {
            out.extend_from_slice(frag);
        }
    }
    out
}

/// Reconstruct the full video elementary stream (H.264 or HEVC) for a parsed
/// file. With a key, every encrypted fragment is decrypted; plaintext fragments
/// pass through.
pub fn build_video_stream(video: &[VideoFrame], key: Option<&Key>) -> Vec<u8> {
    let mut es = Vec::new();
    for frame in video {
        for f in &frame.fragments {
            match key {
                Some(k) if fragment_is_encrypted(f) => {
                    let n = f.len().min(KF_ENC_PREFIX);
                    es.extend_from_slice(&aes_ecb_decrypt(k, &f[..n]));
                    es.extend_from_slice(&f[n..]);
                }
                _ => es.extend_from_slice(f),
            }
        }
    }
    // A file can begin mid-keyframe; drop anything before the first NAL start.
    if let Some(s) = find_start_code(&es)
        && s > 0
    {
        es.drain(..s);
    }
    es
}

/// One decoded access unit for the muxer: Annex-B bytes, a sync flag, and the
/// source record's presentation timestamp (ms) when the container carried one.
pub struct Frame {
    pub is_keyframe: bool,
    pub annexb: Vec<u8>,
    pub ts_ms: Option<u32>,
}

/// Reconstruct per-frame Annex-B access units (one `Frame` per video frame),
/// decrypting encrypted keyframe fragments. A frame is a keyframe iff it had an
/// encrypted fragment (eufy only encrypts true keyframes). Frames are trimmed to
/// start at a NAL start code; any without one are dropped.
pub fn build_frames(video: &[VideoFrame], key: Option<&Key>) -> Vec<Frame> {
    let mut out = Vec::new();
    for frame in video {
        let mut annexb = Vec::new();
        let mut is_keyframe = false;
        for f in &frame.fragments {
            if fragment_is_encrypted(f) {
                is_keyframe = true;
                match key {
                    Some(k) => {
                        let n = f.len().min(KF_ENC_PREFIX);
                        annexb.extend_from_slice(&aes_ecb_decrypt(k, &f[..n]));
                        annexb.extend_from_slice(&f[n..]);
                    }
                    None => annexb.extend_from_slice(f),
                }
            } else {
                annexb.extend_from_slice(f);
            }
        }
        let ts_ms = frame.ts_ms;
        match find_start_code(&annexb) {
            Some(0) => out.push(Frame { is_keyframe, annexb, ts_ms }),
            Some(s) => {
                annexb.drain(..s);
                out.push(Frame { is_keyframe, annexb, ts_ms });
            }
            None => {} // no NAL start code: drop (e.g. undecrypted keyframe)
        }
    }
    out
}

/// Count how many video fragments look encrypted (no leading start code).
pub fn count_encrypted_fragments(video: &[VideoFrame]) -> usize {
    video
        .iter()
        .flat_map(|f| f.fragments.iter())
        .filter(|f| fragment_is_encrypted(f))
        .count()
}

/// Find the first 4-byte Annex-B start code.
pub fn find_start_code(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == ANNEXB_START)
}

/// Does this decrypted keyframe prefix look like a valid video start? It must
/// open with an Annex-B start code whose following NAL is a parameter set or
/// keyframe slice for H.264 or H.265/HEVC. eufy models use either codec.
pub fn looks_like_keyframe(plaintext: &[u8]) -> bool {
    if plaintext.len() < 6 || &plaintext[..4] != ANNEXB_START {
        return false;
    }
    // H.264: nal_unit_type = byte4 & 0x1f; SPS=7, PPS=8, IDR=5, SEI=6, AUD=9.
    let h264 = plaintext[4] & 0x1f;
    // HEVC: nal_unit_type = (byte4 >> 1) & 0x3f; VPS=32, SPS=33, PPS=34,
    // IDR_W_RADL=19, IDR_N_LP=20, CRA=21.
    let hevc = (plaintext[4] >> 1) & 0x3f;
    matches!(h264, 5 | 7 | 8) || matches!(hevc, 32 | 33 | 34 | 19 | 20 | 21)
}

/// Detect the codec from the first decrypted keyframe's parameter sets.
/// Returns "hevc"/"h264", or None when no keyframe decrypted to a recognizable
/// header (the usual signal that the key is wrong or missing). Inspecting the
/// keyframe directly avoids rebuilding the whole elementary stream just to
/// sniff the codec, and never falls back to a guessed codec.
pub fn frames_codec(frames: &[Frame]) -> Option<&'static str> {
    let kf = frames.iter().find(|f| f.is_keyframe)?;
    detect_codec(&kf.annexb)
}

/// Detect the codec of a reconstructed Annex-B stream from its first NAL.
/// Returns "hevc", "h264", or None if it can't tell.
pub fn detect_codec(stream: &[u8]) -> Option<&'static str> {
    let s = find_start_code(stream)?;
    let b = *stream.get(s + 4)?;
    let hevc = (b >> 1) & 0x3f;
    if matches!(hevc, 32..=34) {
        return Some("hevc");
    }
    let h264 = b & 0x1f;
    if matches!(h264, 7 | 8 | 5) {
        return Some("h264");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_parse_ascii_and_hex() {
        let a = Key::parse("89DD11D2DF09ED7D").unwrap();
        assert_eq!(&a.0, b"89DD11D2DF09ED7D");
        let h = Key::parse(&hex::encode(b"0123456789abcdef")).unwrap();
        assert_eq!(&h.0, b"0123456789abcdef");
        assert!(Key::parse("tooshort").is_err());
    }

    #[test]
    fn ecb_roundtrip_nist_vector() {
        // FIPS-197 AES-128 example.
        let key = Key::parse("000102030405060708090a0b0c0d0e0f").unwrap();
        let ct = hex::decode("69c4e0d86a7b0430d8cdb78070b4c55a").unwrap();
        let pt = aes_ecb_decrypt(&key, &ct);
        assert_eq!(hex::encode(pt), "00112233445566778899aabbccddeeff");
    }

    #[test]
    fn decrypt_iframe_only_touches_prefix() {
        let key = Key::parse("000102030405060708090a0b0c0d0e0f").unwrap();
        // 200-byte fragment: first 128 "encrypted", rest plaintext marker.
        let mut frag = vec![0u8; 128];
        frag.extend_from_slice(&[0xAB; 72]);
        let out = decrypt_iframe(&key, &[frag.clone()]);
        // tail beyond 128 must be byte-identical
        assert_eq!(&out[128..], &[0xAB; 72]);
        // prefix must have been transformed
        assert_ne!(&out[..128], &frag[..128]);
    }
}
