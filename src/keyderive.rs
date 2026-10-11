//! Pure-Rust reconstruction of the eufy media key (`gen_pic_code_v1`).
//!
//! Reverse-engineered from `libcrypto-security.so` (eufy app 6.1.10_30612),
//! functions `gen_pic_code_v1`, `gen_rand_seed`, `gen_pic_base_code`,
//! `cal_ppcs_id_suffix`, and `gen_check_code_v1`. The algorithm:
//!
//! ```text
//! sfx      = cal_ppcs_id_suffix(ppcs_id)             # small int, device-constant
//! offset   = f(hex(serial[l-1]) + 10)                # device-constant (serial-derived)
//! baseCode = serial[offset..l] + str(sfx)
//! rndStr   = str(1000 - sfx) + str(rand)             # rand = atoi(code[2..10])
//! seed     = HEXUPPER( MD5(rndStr) )                 # 32 ASCII chars  (Obfuscate1)
//! h        = SHA256( "01" + baseCode + seed )        # 32 bytes
//! d        = obfuscate2(h)                           # in-place byte mixing
//! key      = HEXUPPER( d[16..24] )                   # 16 ASCII chars = AES-128 key
//! ```
//!
//! `sfx` and `offset` are constants of a given camera (they depend only on the
//! PPCS id and the serial, not on the per-file `rand`). Rather than reproduce
//! `cal_ppcs_id_suffix` / `f` exactly for every model, [`calibrate`] recovers
//! the `(offset, sfx)` pair once by trying the small space against a real
//! encrypted keyframe, then every file's key follows from its own `rand`.

use crate::container::split;
use crate::crypto::{Key, decrypt_iframe, looks_like_h264};
use crate::format::KF_ENC_PREFIX;
use md5::Md5;
use sha2::{Digest, Sha256};

/// Device constants recovered once per camera.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub offset: usize,
    pub sfx: u32,
}

/// `gen_check_code_v1`'s in-place digest mixing (Obfuscate2).
fn obfuscate2(h: [u8; 32]) -> [u8; 32] {
    let mut d = h;
    for i in 0..32usize {
        let cur = d[i] as i32;
        let nxt = if i == 31 { d[10] } else { d[i + 1] } as i32;
        if i % 2 == 0 {
            // even: skip iff (cur >= 0x7d && nxt > 0x7c), else cur + nxt
            if !(cur >= 0x7d && nxt > 0x7c) {
                d[i] = ((cur + nxt) & 0xff) as u8;
            }
        } else {
            // odd: skip iff (cur <= 0x7e && nxt < 0x7f), else |cur - nxt|
            if !(cur <= 0x7e && nxt < 0x7f) {
                d[i] = (cur - nxt).unsigned_abs() as u8;
            }
        }
    }
    d
}

fn hex_upper(bytes: &[u8]) -> String {
    hex::encode_upper(bytes)
}

/// Derive the AES-128 key from the camera serial, the per-file `rand`, and the
/// device constants.
pub fn derive(serial: &str, rand: u64, p: Params) -> Key {
    let l = 16usize;
    let base_prefix: String = serial.chars().skip(p.offset.min(l)).take(l - p.offset.min(l)).collect();
    let base_code = format!("{base_prefix}{}", p.sfx);

    let rnd_str = format!("{}{}", 1000u32.wrapping_sub(p.sfx), rand);
    let seed = hex_upper(&Md5::digest(rnd_str.as_bytes()));

    let mut hasher = Sha256::new();
    hasher.update(b"01");
    hasher.update(base_code.as_bytes());
    hasher.update(seed.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();

    let d = obfuscate2(digest);
    let key_ascii = hex_upper(&d[16..24]); // 16 ASCII chars

    let mut k = [0u8; crate::format::AES_KEY_LEN];
    k.copy_from_slice(&key_ascii.as_bytes()[..crate::format::AES_KEY_LEN]);
    Key(k)
}

/// Verify a key by decrypting the first encrypted keyframe fragment in `dat`
/// and checking it begins with a valid H.264 header.
pub fn verify_against_keyframe(key: &Key, dat: &[u8]) -> bool {
    let (video, _) = split(dat);
    for frame in video.iter().filter(|f| f.is_iframe) {
        let Some(frag0) = frame.fragments.first() else { continue };
        if crate::crypto::fragment_is_encrypted(frag0) {
            let n = frag0.len().min(KF_ENC_PREFIX);
            let pt = decrypt_iframe(key, &[frag0[..n].to_vec()]);
            return looks_like_h264(&pt);
        }
    }
    false
}

/// Recover `(offset, sfx)` for a camera by trying the small constant space
/// against a real keyframe. `rand` is that sample file's own rand.
pub fn calibrate(serial: &str, rand: u64, sample_dat: &[u8], max_sfx: u32) -> Option<Params> {
    let l = serial.chars().count().min(16);
    for offset in 0..=l {
        for sfx in 0..=max_sfx {
            let p = Params { offset, sfx };
            let key = derive(serial, rand, p);
            if verify_against_keyframe(&key, sample_dat) {
                return Some(p);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfuscate2_is_deterministic() {
        let h = [0x11u8; 32];
        assert_eq!(obfuscate2(h), obfuscate2(h));
    }

    #[test]
    fn derive_is_deterministic() {
        let p = Params { offset: 3, sfx: 12 };
        let a = derive("T8416P0000000000", 15060042, p);
        let b = derive("T8416P0000000000", 15060042, p);
        assert_eq!(a.0, b.0);
        assert_eq!(a.0.len(), 16);
    }

    /// Known-answer test: a real T8416 clip (serial T8416P0000000000,
    /// rand 15060042) with its recovered constants produces the key that
    /// decrypts its keyframe. Pins the whole derivation against regressions.
    #[test]
    fn known_answer_t8416() {
        let key = derive("T8416P0000000000", 15060042, Params { offset: 3, sfx: 12 });
        assert_eq!(&key.0, b"0ADD5A67A51A0762");
    }
}
