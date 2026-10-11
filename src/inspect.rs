//! Format study: describe a `.dat` file's record chain and test which regions
//! look like plaintext H.264 vs ciphertext.
//!
//! This is the first command to run on an unfamiliar camera. The reliable
//! encrypted-vs-plaintext test (per the reference post) is the count of
//! `00 00 00/01/02` escape sequences: plaintext H.264 slice data is full of
//! them, AES ciphertext has them only at random. Entropy is NOT used because a
//! dense CABAC keyframe is also near-8-bit entropy.

use crate::container::{records, split};

/// Confirm the video codec by decrypting one keyframe. Needs a key, so this
/// auto-calibrates from the file's own sibling snapshot (serial + rand). Returns
/// "h264" / "hevc", or None if no key could be obtained or the codec is unclear.
pub fn detect_codec(data: &[u8], file: &std::path::Path) -> Option<&'static str> {
    let (serial, rand) = crate::keys::rand_for_video(file)?;
    let params = crate::keyderive::calibrate(&serial, rand, data, 256)?;
    let key = crate::keyderive::derive(&serial, rand, params);
    let (video, _) = split(data);
    let frame = video
        .iter()
        .find(|f| f.fragments.first().is_some_and(|fr| crate::crypto::fragment_is_encrypted(fr)))?;
    let frag0 = frame.fragments.first()?;
    let n = frag0.len().min(crate::format::KF_ENC_PREFIX);
    let pt = crate::crypto::decrypt_iframe(&key, &[frag0[..n].to_vec()]);
    crate::crypto::detect_codec(&pt)
}

/// Count `00 00 00`, `00 00 01`, `00 00 02` occurrences (the H.264 escape /
/// start-code prefixes that cannot appear inside encrypted data).
pub fn escape_count(data: &[u8]) -> usize {
    data.windows(3)
        .filter(|w| w[0] == 0 && w[1] == 0 && (0..=2).contains(&w[2]))
        .count()
}

pub struct Report {
    pub records: usize,
    pub video_records: usize,
    pub audio_records: usize,
    pub frames: usize,
    pub iframes: usize,
    pub pframes: usize,
    pub encrypted_fragments: usize,
    /// (fps, width, height) from the first video record header, if present.
    pub dimensions: Option<(u16, u16, u16)>,
    pub audio_bytes: usize,
    /// (region label, byte length, escape count, zero-byte %) per sampled region.
    pub regions: Vec<(String, usize, usize, f64)>,
    pub first_record_dump: String,
}

fn zero_pct(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let zeros = data.iter().filter(|&&b| b == 0).count();
    100.0 * zeros as f64 / data.len() as f64
}

pub fn inspect(data: &[u8]) -> Report {
    let recs = records(data);
    let video_records = recs.iter().filter(|r| r.is_video()).count();
    let audio_records = recs.iter().filter(|r| r.is_audio()).count();

    let (video, audio) = split(data);
    let iframes = video.iter().filter(|f| f.is_iframe).count();
    let pframes = video.len() - iframes;

    // Sample regions for the escape-sequence test, classified by the
    // start-code heuristic (not the frame-type tag), since some models tag
    // every record as an I-frame.
    let all_frags: Vec<&Vec<u8>> = video.iter().flat_map(|f| f.fragments.iter()).collect();
    let mut regions = Vec::new();
    // A plaintext reference fragment (begins with a start code).
    if let Some(d) = all_frags
        .iter()
        .find(|f| !crate::crypto::fragment_is_encrypted(f))
    {
        regions.push(("plaintext frame (ref)".into(), d.len(), escape_count(d), zero_pct(d)));
    }
    // The first encrypted fragment: whole, first 128 bytes, and the tail.
    if let Some(d) = all_frags
        .iter()
        .find(|f| crate::crypto::fragment_is_encrypted(f))
    {
        let d: &[u8] = d;
        regions.push(("encrypted frame whole".into(), d.len(), escape_count(d), zero_pct(d)));
        let n = d.len().min(crate::format::KF_ENC_PREFIX);
        let head = &d[..n];
        regions.push(("encrypted frame first128".into(), head.len(), escape_count(head), zero_pct(head)));
        if d.len() > n {
            let tail = &d[n..];
            regions.push(("encrypted frame past128".into(), tail.len(), escape_count(tail), zero_pct(tail)));
        }
    }

    let encrypted_fragments = crate::crypto::count_encrypted_fragments(&video);
    let dimensions = crate::container::video_dimensions(data);
    let first_record_dump = dump_first_records(&recs, data, 4);

    Report {
        records: recs.len(),
        video_records,
        audio_records,
        frames: video.len(),
        iframes,
        pframes,
        encrypted_fragments,
        dimensions,
        audio_bytes: audio.len(),
        regions,
        first_record_dump,
    }
}

fn dump_first_records(recs: &[crate::container::Record<'_>], _data: &[u8], n: usize) -> String {
    let mut s = String::new();
    for r in recs.iter().take(n) {
        s.push_str(&format!(
            "  @{:#010x} stream={:#04x} frame={:#06x} payload={} first8={}\n",
            r.offset,
            r.stream_type,
            r.frame_type,
            r.payload.len(),
            hex::encode(&r.payload[..r.payload.len().min(8)]),
        ));
    }
    s
}
