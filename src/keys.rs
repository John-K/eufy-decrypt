//! Key management: `keys.json`, `continuefilelink.dat`, and per-file selection.

use crate::container::split;
use crate::crypto::{Key, decrypt_iframe, looks_like_keyframe};
use crate::format::KF_ENC_PREFIX;
use crate::keyderive::{self, Params};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

/// One entry in `keys.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    /// 16 ASCII chars or 32 hex chars.
    pub key: String,
    /// Optional human label, e.g. the week code or date range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFile {
    pub keys: Vec<KeyEntry>,
}

impl KeyFile {
    pub fn load(path: &Path) -> Result<KeyFile> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let kf: KeyFile =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        Ok(kf)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let text = serde_json::to_string_pretty(self)?;
        std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    /// Parse every entry's key once.
    pub fn parsed(&self) -> Result<Vec<(Key, Option<String>)>> {
        self.keys
            .iter()
            .map(|e| Ok((Key::parse(&e.key)?, e.label.clone())))
            .collect()
    }
}

/// Decide which of `keys` decrypts `dat` by probing its first keyframe.
pub fn select_key<'a>(keys: &'a [(Key, Option<String>)], dat: &[u8]) -> Option<&'a Key> {
    let (video, _) = split(dat);
    let frame = video.iter().find(|f| f.is_iframe)?;
    let frag0 = frame.fragments.first()?;
    let n = frag0.len().min(KF_ENC_PREFIX);
    let probe = &frag0[..n];
    for (key, _) in keys {
        let pt = decrypt_iframe(key, &[probe.to_vec()]);
        if looks_like_keyframe(&pt) {
            return Some(key);
        }
    }
    None
}

/// A parsed `eufysecurity:<serial>:<code>:<ciphertext...>` media header, as
/// found at the start of encrypted snapshot/crop JPEGs (and described in the
/// WOOT'24 paper). The `code` is `"01" + rand`; the same rand keys that event's
/// video keyframes, so the snapshot gives us the per-file rand directly.
#[derive(Debug, Clone)]
pub struct EufyHeader {
    pub serial: String,
    pub code: String,
    /// Byte offset where the encrypted payload begins (after the third colon).
    #[allow(dead_code)] // offset where ciphertext begins; used when decrypting the JPEG itself
    pub payload_offset: usize,
}

impl EufyHeader {
    pub fn rand(&self) -> Option<u64> {
        self.code.strip_prefix("01").unwrap_or(&self.code).parse().ok()
    }
}

/// Parse a `eufysecurity:...` header from the start of `data`, if present.
pub fn parse_eufy_header(data: &[u8]) -> Option<EufyHeader> {
    const PREFIX: &[u8] = b"eufysecurity:";
    if !data.starts_with(PREFIX) {
        return None;
    }
    // Find the next two colons after the prefix: serial, then code.
    let rest = &data[PREFIX.len()..];
    let c1 = rest.iter().position(|&b| b == b':')?;
    let serial = String::from_utf8_lossy(&rest[..c1]).into_owned();
    let after_serial = &rest[c1 + 1..];
    let c2 = after_serial.iter().position(|&b| b == b':')?;
    let code = String::from_utf8_lossy(&after_serial[..c2]).into_owned();
    let payload_offset = PREFIX.len() + c1 + 1 + c2 + 1;
    Some(EufyHeader { serial, code, payload_offset })
}

/// Given a `.zxvideo`/`.dat` path, find the per-event `rand` from a sibling
/// `*_snapshot.jpg` (or any sibling eufysecurity-headered JPEG with the same
/// timestamp stem).
pub fn rand_for_video(video_path: &Path) -> Option<(String, u64)> {
    let dir = video_path.parent()?;
    let stem = video_path.file_stem()?.to_string_lossy().into_owned();
    // Preferred: "<stem>_snapshot.jpg"; fall back to any "<stem>*.jpg".
    let candidates = [
        dir.join(format!("{stem}_snapshot.jpg")),
        dir.join(format!("{stem}.jpg")),
    ];
    let mut paths: Vec<std::path::PathBuf> = candidates.to_vec();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().map(|x| x == "jpg").unwrap_or(false)
                && p.file_name()
                    .map(|n| n.to_string_lossy().starts_with(&stem))
                    .unwrap_or(false)
            {
                paths.push(p);
            }
        }
    }
    for p in paths {
        if let Ok(head) = read_head(&p, 64)
            && let Some(h) = parse_eufy_header(&head)
            && let Some(rand) = h.rand()
        {
            return Some((h.serial, rand));
        }
    }
    None
}

fn read_head(path: &Path, n: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; n];
    let got = f.read(&mut buf)?;
    buf.truncate(got);
    Ok(buf)
}

/// An entry parsed from `continuefilelink.dat`.
#[derive(Debug, Clone)]
pub struct LinkEntry {
    pub dat_name: String,
    /// 10-digit code, `"01" + rand`.
    pub code: String,
}

impl LinkEntry {
    /// The weekly `rand` = the code with its leading `"01"` stripped.
    pub fn rand(&self) -> Option<u64> {
        self.code.strip_prefix("01")?.parse().ok()
    }
}

/// Parse `continuefilelink.dat`, mapping each recording to its 10-digit code.
///
/// The file is text-ish: each line references a `.dat` path and a trailing
/// 10-digit code. We scan tolerantly rather than assume a fixed field width,
/// so a slightly different layout on another model still yields the codes.
pub fn parse_link_file(data: &[u8]) -> Vec<LinkEntry> {
    let text = String::from_utf8_lossy(data);
    let mut out = Vec::new();
    for line in text.lines() {
        let dat = line
            .split_whitespace()
            .find(|t| t.ends_with(".dat"))
            .map(|t| {
                Path::new(t)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| t.to_string())
            });
        // last 10-digit run on the line, starting with "01"
        let code = line
            .split(|c: char| !c.is_ascii_digit())
            .rfind(|t| t.len() == 10 && t.starts_with("01"))
            .map(|s| s.to_string());
        if let (Some(dat_name), Some(code)) = (dat, code) {
            out.push(LinkEntry { dat_name, code });
        }
    }
    out
}

/// Distinct week codes across a link file, sorted.
pub fn distinct_codes(entries: &[LinkEntry]) -> Vec<String> {
    entries
        .iter()
        .map(|e| e.code.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Build a `keys.json` by deriving one AES key per distinct weekly code in a
/// parsed `continuefilelink.dat`. The derivation is identical to the event-clip
/// path; only the `rand` source differs (the weekly code instead of a snapshot).
/// Each entry is labelled with the earliest recording date seen for that code.
pub fn derive_key_file(entries: &[LinkEntry], serial: &str, params: Params) -> KeyFile {
    let mut keys = Vec::new();
    for code in distinct_codes(entries) {
        let Some(rand) = code.strip_prefix("01").and_then(|s| s.parse::<u64>().ok()) else {
            continue;
        };
        let key = keyderive::derive(serial, rand, params);
        let date = entries
            .iter()
            .filter(|e| e.code == code)
            .filter_map(|e| e.dat_name.get(..8))
            .min()
            .map(str::to_string);
        let label = match date {
            Some(d) => format!("{d} code {code}"),
            None => format!("code {code}"),
        };
        keys.push(KeyEntry {
            key: String::from_utf8_lossy(&key.0).into_owned(),
            label: Some(label),
        });
    }
    KeyFile { keys }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_parsing() {
        let sample =
            b"/media/mmcblk0p1/video/continue/20261007105210.dat   0163419399\n\njunk line\n";
        let entries = parse_link_file(sample);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dat_name, "20261007105210.dat");
        assert_eq!(entries[0].code, "0163419399");
        assert_eq!(entries[0].rand(), Some(63419399));
    }

    #[test]
    fn distinct() {
        let e = vec![
            LinkEntry { dat_name: "a.dat".into(), code: "0111".into() },
            LinkEntry { dat_name: "b.dat".into(), code: "0111".into() },
            LinkEntry { dat_name: "c.dat".into(), code: "0122".into() },
        ];
        assert_eq!(distinct_codes(&e), vec!["0111".to_string(), "0122".into()]);
    }

    /// One key per distinct weekly code, derived via the same algorithm as the
    /// event-clip path. Pinned against the known-answer vector (serial
    /// T8416P0000000000, code 0115060042 -> key 0ADD5A67A51A0762): the leading
    /// "01" is stripped to rand 15060042, so `keys` and `derive` agree.
    #[test]
    fn derive_key_file_one_per_code() {
        let entries = vec![
            LinkEntry { dat_name: "20260814090000.dat".into(), code: "0115060042".into() },
            LinkEntry { dat_name: "20260813101151.dat".into(), code: "0115060042".into() },
        ];
        let kf = derive_key_file(&entries, "T8416P0000000000", Params { offset: 3, sfx: 12 });
        assert_eq!(kf.keys.len(), 1); // deduplicated by code
        assert_eq!(kf.keys[0].key, "0ADD5A67A51A0762");
        // labelled with the earliest recording date for that code
        assert_eq!(kf.keys[0].label.as_deref(), Some("20260813 code 0115060042"));
    }
}

#[cfg(test)]
mod header_tests {
    use super::*;
    #[test]
    fn parse_eufy_header_fields() {
        let h = parse_eufy_header(b"eufysecurity:T8416P0000000000:0115060042:\xee\xca\xdf").unwrap();
        assert_eq!(h.serial, "T8416P0000000000");
        assert_eq!(h.code, "0115060042");
        assert_eq!(h.rand(), Some(15060042));
        assert_eq!(h.payload_offset, 41);
        assert_eq!(&b"eufysecurity:T8416P0000000000:0115060042:\xee\xca\xdf"[h.payload_offset..], b"\xee\xca\xdf");
    }
    #[test]
    fn rejects_plain_jpeg() {
        assert!(parse_eufy_header(b"\xff\xd8\xff\xe0JFIF").is_none());
    }
}
