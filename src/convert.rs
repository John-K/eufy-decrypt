//! Single-file and batch conversion orchestration.

use crate::container::split;
use crate::crypto::{Key, build_video_stream};
use crate::keyderive::{self, Params};
use crate::keys::{self, select_key};
use crate::remux;
use anyhow::{Context, Result, anyhow};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Outcome of converting one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    AudioOnly,
    NoKey,
    SkippedExisting,
    MuxError(String),
    ReadError(String),
}

impl Outcome {
    fn tag(&self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::AudioOnly => "audio-only",
            Outcome::NoKey => "no-key",
            Outcome::SkippedExisting => "skipped-existing",
            Outcome::MuxError(_) => "mux-error",
            Outcome::ReadError(_) => "read-error",
        }
    }
}

/// Convert one `.dat`/`.zxvideo` to MP4 with an explicit key (or raw streams / audio-only).
pub fn convert_file(path: &Path, out: &Path, key: Option<&Key>, fps: u32, raw: bool) -> Result<()> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let (video, audio) = split(&data);
    if raw {
        let es = build_video_stream(&video, key);
        let codec = crate::crypto::detect_codec(&es).unwrap_or("h264");
        remux::write_raw(&es, &audio, &out.with_extension(""), codec)?;
        return Ok(());
    }
    let frames = crate::crypto::build_frames(&video, key);
    let codec = crate::crypto::frames_codec(&frames).ok_or_else(|| {
        anyhow!(
            "no decryptable keyframe in {} — the key is wrong or missing, so the video \
             cannot be built. Audio can still be recovered with `extract-audio`.",
            path.display()
        )
    })?;
    remux::mux_mp4(&frames, &audio, out, fps, codec, recording_unix_time(path))?;
    Ok(())
}

/// Parse a recording's wall-clock time from its `YYYYMMDDHHMMSS` filename stem,
/// as seconds since the Unix epoch. eufy filenames carry no zone, so the time is
/// interpreted in the machine's local timezone (DST-aware, resolved per clip),
/// matching the camera's own clock. It stamps the output's modification time and
/// the MP4 creation time so recovered clips carry the time they were filmed
/// rather than when they were converted. Returns None if the stem isn't a
/// recognizable datetime (or falls in a DST spring-forward gap).
pub fn recording_unix_time(path: &Path) -> Option<u64> {
    use chrono::{LocalResult, NaiveDate, TimeZone};
    let stem = path.file_stem()?.to_str()?;
    let d = stem.get(..14)?;
    if !d.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let naive = NaiveDate::from_ymd_opt(
        d[0..4].parse().ok()?,
        d[4..6].parse().ok()?,
        d[6..8].parse().ok()?,
    )?
    .and_hms_opt(
        d[8..10].parse().ok()?,
        d[10..12].parse().ok()?,
        d[12..14].parse().ok()?,
    )?;
    let ts = match chrono::Local.from_local_datetime(&naive) {
        // Unambiguous, or a DST fall-back repeat (take the earlier instant).
        LocalResult::Single(dt) | LocalResult::Ambiguous(dt, _) => dt.timestamp(),
        // Nonexistent local time (DST spring-forward gap): can't place it.
        LocalResult::None => return None,
    };
    u64::try_from(ts).ok()
}

/// How batch obtains each file's key.
pub enum KeySource {
    /// Probe every key against the file's first keyframe.
    Probe(Vec<(Key, Option<String>)>),
    /// Derive a per-file key from the sibling snapshot's serial + rand and the
    /// calibrated constants. `serial` overrides the snapshot's when set.
    Derive {
        serial: Option<String>,
        params: Params,
    },
}

impl KeySource {
    fn key_for(&self, path: &Path, data: &[u8]) -> Option<Key> {
        match self {
            KeySource::Probe(keys) => select_key(keys, data).copied(),
            KeySource::Derive { serial, params } => {
                let (hdr_serial, rand) = keys::rand_for_video(path)?;
                let serial = serial.clone().unwrap_or(hdr_serial);
                Some(keyderive::derive(&serial, rand, *params))
            }
        }
    }
    fn len(&self) -> usize {
        match self {
            KeySource::Probe(k) => k.len(),
            KeySource::Derive { .. } => 0,
        }
    }
}

/// One batch item worker: pick a key, decrypt, remux. Pure enough to run under
/// rayon; all I/O is confined to the given paths.
fn convert_one(
    path: &Path,
    out: &Path,
    keysrc: &KeySource,
    fps: u32,
    audio_only_fallback: bool,
) -> Outcome {
    if out.exists() {
        return Outcome::SkippedExisting;
    }
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return Outcome::ReadError(e.to_string()),
    };
    let (video, audio) = split(&data);
    let when = recording_unix_time(path);
    // A key decrypts a usable keyframe iff `frames_codec` recognizes one; a
    // wrong key leaves only garbage, which is handled exactly like no key.
    let codec = keysrc.key_for(path, &data).and_then(|k| {
        let frames = crate::crypto::build_frames(&video, Some(&k));
        crate::crypto::frames_codec(&frames).map(|c| (frames, c))
    });
    match codec {
        Some((frames, codec)) => match remux::mux_mp4(&frames, &audio, out, fps, codec, when) {
            Ok(()) => Outcome::Ok,
            Err(e) => Outcome::MuxError(e.to_string()),
        },
        None => {
            if audio_only_fallback && !audio.is_empty() {
                let m4a = out.with_extension("m4a");
                match remux::mux_audio_only(&audio, &m4a, when) {
                    Ok(()) => Outcome::AudioOnly,
                    Err(e) => Outcome::MuxError(e.to_string()),
                }
            } else {
                Outcome::NoKey
            }
        }
    }
}

#[derive(Debug, Serialize)]
pub struct BatchSummary {
    pub stats: BTreeMap<String, usize>,
    pub failures: Vec<(String, String)>,
    pub keys_used: usize,
}

pub struct BatchOptions {
    pub jobs: usize,
    pub fps: u32,
    pub audio_only_fallback: bool,
    pub limit: usize,
}

/// Convert every `.dat`/`.zxvideo` under `source` into `dest`, laid out as
/// `dest/<YYYYMMDD>/<YYYYMMDDHHMMSS>.mp4`. Resumable: existing outputs are
/// skipped. Writes `convert_summary.json` into `dest`.
pub fn batch(
    source: &Path,
    dest: &Path,
    keysrc: &KeySource,
    opts: &BatchOptions,
) -> Result<BatchSummary> {
    let mut names: Vec<PathBuf> = walkdir::WalkDir::new(source)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| {
            p.extension()
                .map(|x| x == "dat" || x == "zxvideo")
                .unwrap_or(false)
        })
        .filter(|p| {
            p.file_name()
                .map(|n| n != "continuefilelink.dat")
                .unwrap_or(true)
        })
        .collect();
    names.sort();
    if opts.limit > 0 {
        names.truncate(opts.limit);
    }

    let out_path = |p: &Path| -> PathBuf {
        let stem = p
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let day = stem.get(..8).unwrap_or(&stem).to_string();
        dest.join(day).join(format!("{stem}.mp4"))
    };

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(if opts.jobs == 0 {
            rayon::current_num_threads()
        } else {
            opts.jobs
        })
        .build()?;

    let pb = ProgressBar::new(names.len() as u64);
    pb.set_style(
        ProgressStyle::with_template("{bar:40} {pos}/{len} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar()),
    );

    let stats = Mutex::new(BTreeMap::<String, usize>::new());
    let failures = Mutex::new(Vec::<(String, String)>::new());

    pool.install(|| {
        names.par_iter().for_each(|p| {
            let out = out_path(p);
            let outcome = convert_one(p, &out, keysrc, opts.fps, opts.audio_only_fallback);
            let tag = outcome.tag().to_string();
            {
                let mut s = stats.lock().unwrap();
                *s.entry(tag.clone()).or_insert(0) += 1;
            }
            match &outcome {
                Outcome::Ok | Outcome::AudioOnly | Outcome::SkippedExisting => {}
                Outcome::NoKey => failures
                    .lock()
                    .unwrap()
                    .push((p.display().to_string(), "no-key".into())),
                Outcome::MuxError(e) | Outcome::ReadError(e) => failures
                    .lock()
                    .unwrap()
                    .push((p.display().to_string(), e.clone())),
            }
            pb.inc(1);
        });
    });
    pb.finish_and_clear();

    let summary = BatchSummary {
        stats: stats.into_inner().unwrap(),
        failures: failures.into_inner().unwrap(),
        keys_used: keysrc.len(),
    };
    std::fs::create_dir_all(dest).ok();
    std::fs::write(
        dest.join("convert_summary.json"),
        serde_json::to_string_pretty(&summary)?,
    )
    .ok();
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_unix_time_parses_and_rejects() {
        // A real clip name parses to some instant (exact value is TZ-dependent).
        assert!(recording_unix_time(Path::new("/x/20260813101151.zxvideo")).is_some());
        // Extra suffix after the 14 datetime digits is fine.
        assert!(recording_unix_time(Path::new("/x/20260813101151_02.dat")).is_some());
        // Too short, non-numeric, or out-of-range fields are rejected.
        assert!(recording_unix_time(Path::new("/x/2026081310115.dat")).is_none());
        assert!(recording_unix_time(Path::new("/x/snapshot.jpg")).is_none());
        assert!(recording_unix_time(Path::new("/x/20261345101151.dat")).is_none()); // month 13
        assert!(recording_unix_time(Path::new("/x/20260813256199.dat")).is_none()); // 25:61:99
    }
}
