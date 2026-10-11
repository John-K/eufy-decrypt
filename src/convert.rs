//! Single-file and batch conversion orchestration.

use crate::container::split;
use crate::crypto::{Key, build_h264};
use crate::keyderive::{self, Params};
use crate::keys::{self, select_key};
use crate::remux;
use anyhow::{Context, Result};
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
pub fn convert_file(
    path: &Path,
    out: &Path,
    key: Option<&Key>,
    fps: u32,
    raw: bool,
) -> Result<()> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let (video, audio) = split(&data);
    let es = build_h264(&video, key);
    let codec = crate::crypto::detect_codec(&es).unwrap_or("h264");
    if raw {
        remux::write_raw(&es, &audio, &out.with_extension(""), codec)?;
    } else {
        let frames = crate::crypto::build_frames(&video, key);
        remux::mux_mp4(&frames, &audio, out, fps, codec)?;
    }
    Ok(())
}

/// How batch obtains each file's key.
pub enum KeySource {
    /// Probe every key against the file's first keyframe.
    Probe(Vec<(Key, Option<String>)>),
    /// Derive a per-file key from the sibling snapshot's serial + rand and the
    /// calibrated constants. `serial` overrides the snapshot's when set.
    Derive { serial: Option<String>, params: Params },
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
    let key = keysrc.key_for(path, &data);
    match key {
        Some(k) => {
            let es = build_h264(&video, Some(&k));
            let codec = crate::crypto::detect_codec(&es).unwrap_or("h264");
            let frames = crate::crypto::build_frames(&video, Some(&k));
            match remux::mux_mp4(&frames, &audio, out, fps, codec) {
                Ok(()) => Outcome::Ok,
                Err(e) => Outcome::MuxError(e.to_string()),
            }
        }
        None => {
            if audio_only_fallback && !audio.is_empty() {
                let m4a = out.with_extension("m4a");
                match remux::mux_audio_only(&audio, &m4a) {
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
        .filter(|p| p.file_name().map(|n| n != "continuefilelink.dat").unwrap_or(true))
        .collect();
    names.sort();
    if opts.limit > 0 {
        names.truncate(opts.limit);
    }

    let out_path = |p: &Path| -> PathBuf {
        let stem = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let day = stem.get(..8).unwrap_or(&stem).to_string();
        dest.join(day).join(format!("{stem}.mp4"))
    };

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(if opts.jobs == 0 { rayon::current_num_threads() } else { opts.jobs })
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
