//! eufy-decrypt: decrypt eufy camera SD-card `.dat`/`.zxvideo` recordings to MP4, offline.
//!
//! See the README. Workflow: `inspect` a file to confirm the format, obtain the
//! weekly AES keys (`derive`/`keys`, or paste from the reference angr script),
//! then `convert` one file or `batch` the whole card.

mod container;
mod convert;
mod crypto;
mod format;
mod inspect;
mod keyderive;
mod keys;
mod remux;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use crypto::Key;
use keyderive::Params;
use keys::KeyFile;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "eufy-decrypt",
    about = "Decrypt eufy camera SD-card recordings to MP4 (offline).",
    long_about = "Decrypt eufy camera SD-card .dat/.zxvideo recordings to MP4, fully offline.\n\n\
                  SAFETY: the card is usually the only copy. Image it read-only and verify \
                  with sha256 BEFORE running anything. This tool only reads sources and only \
                  writes to the destinations you name.",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Describe a .dat/.zxvideo file's record chain and test encrypted vs plaintext regions.
    Inspect {
        file: PathBuf,
    },
    /// Recover this camera's key-derivation constants (offset, sfx) once, by
    /// trying the small constant space against a real encrypted keyframe.
    Calibrate {
        /// A sample encrypted .zxvideo/.dat to calibrate against.
        sample: PathBuf,
        /// Camera serial. Optional; recovered from the sibling snapshot if omitted.
        #[arg(long)]
        serial: Option<String>,
        /// This sample's rand. If omitted, read from its sibling snapshot.
        #[arg(long)]
        rand: Option<u64>,
        #[arg(long, default_value_t = 256)]
        max_sfx: u32,
    },
    /// Derive one AES key from serial + rand + calibrated constants.
    Derive {
        /// Camera serial. Optional if --from points at a clip with a snapshot.
        #[arg(long)]
        serial: Option<String>,
        /// The rand. Optional if --from points at a clip with a snapshot.
        #[arg(long)]
        rand: Option<u64>,
        /// A .zxvideo/.dat to recover serial+rand from its sibling snapshot.
        #[arg(long)]
        from: Option<PathBuf>,
        #[arg(long)]
        offset: usize,
        #[arg(long)]
        sfx: u32,
    },
    /// Convert a single .dat/.zxvideo to MP4.
    Convert {
        file: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// AES key as 16 ASCII chars or 32 hex chars.
        #[arg(long)]
        key: Option<String>,
        /// keys.json to auto-select the right key for this file.
        #[arg(long)]
        keys: Option<PathBuf>,
        /// Write raw .h264/.aac instead of invoking ffmpeg.
        #[arg(long)]
        raw: bool,
        #[arg(long, default_value_t = format::DEFAULT_FPS)]
        fps: u32,
    },
    /// Batch convert every .dat/.zxvideo under a directory.
    ///
    /// For event-clip cameras, `batch --source <dir> --dest <dir>` is enough:
    /// it auto-calibrates the derivation constants from the first encrypted clip
    /// and derives each file's key from its own snapshot. Pass --offset/--sfx to
    /// skip calibration, or --keys to probe a keys.json instead.
    Batch {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        dest: PathBuf,
        /// keys.json (probed per file) instead of deriving keys.
        #[arg(long)]
        keys: Option<PathBuf>,
        /// Camera serial. Optional; recovered from each clip's snapshot.
        #[arg(long)]
        serial: Option<String>,
        /// Calibrated offset. Optional; auto-calibrated if omitted.
        #[arg(long)]
        offset: Option<usize>,
        /// Calibrated sfx. Optional; auto-calibrated if omitted.
        #[arg(long)]
        sfx: Option<u32>,
        #[arg(long, default_value_t = 0)]
        jobs: usize,
        #[arg(long, default_value_t = format::DEFAULT_FPS)]
        fps: u32,
        /// Write .m4a for files whose key is unknown.
        #[arg(long)]
        audio_only_fallback: bool,
        #[arg(long, default_value_t = 0)]
        limit: usize,
    },
    /// Extract just the (plaintext) AAC audio; no key required.
    ExtractAudio {
        file: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Inspect { file } => cmd_inspect(&file),
        Cmd::Calibrate { serial, sample, rand, max_sfx } => {
            cmd_calibrate(serial.as_deref(), &sample, rand, max_sfx)
        }
        Cmd::Derive { serial, rand, from, offset, sfx } => {
            cmd_derive(serial.as_deref(), rand, from.as_deref(), offset, sfx)
        }
        Cmd::Convert { file, out, key, keys, raw, fps } => {
            cmd_convert(&file, &out, key.as_deref(), keys.as_deref(), raw, fps)
        }
        Cmd::Batch { source, dest, keys, serial, offset, sfx, jobs, fps, audio_only_fallback, limit } => {
            cmd_batch(&source, &dest, keys.as_deref(), serial.as_deref(), offset, sfx, jobs, fps, audio_only_fallback, limit)
        }
        Cmd::ExtractAudio { file, out } => cmd_extract_audio(&file, &out),
    }
}

fn cmd_inspect(file: &std::path::Path) -> Result<()> {
    let data = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let r = inspect::inspect(&data);
    println!("file: {} ({} bytes)", file.display(), data.len());
    println!(
        "records: {} (video {}, audio {})",
        r.records, r.video_records, r.audio_records
    );
    println!(
        "frames: {} (tagged I-frames {}, P-frames {}), audio: {} bytes",
        r.frames, r.iframes, r.pframes, r.audio_bytes
    );
    let codec = inspect::detect_codec(&data, file);
    let codec_str = match codec {
        Some("hevc") => "H.265/HEVC",
        Some("h264") => "H.264",
        _ => "unknown (needs a snapshot to decrypt a keyframe)",
    };
    match r.dimensions {
        Some((fps, w, h)) if w != 0 && h != 0 => {
            println!("video: {codec_str}, {w}x{h}, {fps} fps")
        }
        _ => println!("video: {codec_str}, resolution/fps not in header"),
    }
    match r.audio_info {
        Some((codec, rate, ch)) => {
            let ch_str = match ch {
                1 => "mono".to_string(),
                2 => "stereo".to_string(),
                n => format!("{n} ch"),
            };
            println!("audio: {codec}, {rate} Hz, {ch_str}");
        }
        None if r.audio_bytes > 0 => println!("audio: present ({} bytes), format unrecognized", r.audio_bytes),
        None => println!("audio: none"),
    }
    println!(
        "encrypted fragments (no leading start code): {} of {} video fragments",
        r.encrypted_fragments, r.frames
    );
    // If a sibling snapshot carries a eufysecurity header, surface serial+rand.
    if let Some((serial, rand)) = keys::rand_for_video(file) {
        println!("sibling snapshot header: serial {serial}, rand {rand}");
    }
    println!("\nfirst records:\n{}", r.first_record_dump);
    println!("region escape-sequence test (plaintext H.264 has many; ciphertext ~none):");
    println!("  {:<28} {:>10} {:>10} {:>8}", "region", "bytes", "escapes", "zero%");
    for (name, len, esc, zp) in &r.regions {
        println!("  {name:<28} {len:>10} {esc:>10} {zp:>7.2}%");
    }
    println!(
        "\nIf 'encrypted frame first128' has ~0 escapes while 'past128' has many,\n\
         the 128-byte encrypted-prefix model holds for this camera."
    );
    Ok(())
}

/// Resolve `(serial, rand)` from explicit flags, falling back to the sample's
/// sibling snapshot header. An explicit value always overrides the sidecar.
fn resolve_identity(
    serial: Option<&str>,
    rand: Option<u64>,
    sample: &std::path::Path,
) -> Result<(String, u64)> {
    if let (Some(s), Some(r)) = (serial, rand) {
        return Ok((s.to_string(), r));
    }
    let sidecar = keys::rand_for_video(sample);
    if let Some((hs, _)) = &sidecar
        && let Some(s) = serial
        && hs != s
    {
        eprintln!("note: snapshot serial {hs} differs from --serial {s}");
    }
    let final_serial = serial
        .map(str::to_string)
        .or_else(|| sidecar.as_ref().map(|(s, _)| s.clone()))
        .context("no serial given and none found in a sibling snapshot; pass --serial")?;
    let final_rand = rand
        .or_else(|| sidecar.as_ref().map(|(_, r)| *r))
        .context("no rand given and none found in a sibling snapshot; pass --rand")?;
    Ok((final_serial, final_rand))
}

fn cmd_calibrate(
    serial: Option<&str>,
    sample: &std::path::Path,
    rand: Option<u64>,
    max_sfx: u32,
) -> Result<()> {
    let data = std::fs::read(sample).with_context(|| format!("reading {}", sample.display()))?;
    let (serial, rand) = resolve_identity(serial, rand, sample)?;
    println!("calibrating serial {serial}, sample rand {rand} ...");
    match keyderive::calibrate(&serial, rand, &data, max_sfx) {
        Some(p) => {
            let key = keyderive::derive(&serial, rand, p);
            println!("VERIFIED. Camera constants:");
            println!("  offset : {}", p.offset);
            println!("  sfx    : {}", p.sfx);
            println!("  sample key (ascii): {}", String::from_utf8_lossy(&key.0));
            println!("  sample key (hex)  : {}", key.to_hex());
            println!(
                "\nReuse these for the whole card:\n  \
                 eufy-decrypt batch --source <dir> --dest <out> --offset {} --sfx {}",
                p.offset, p.sfx
            );
        }
        None => bail!(
            "no (offset, sfx) in the searched space decrypted the sample.\n\
             Try a larger --max-sfx, confirm the serial, or check the sample really has an encrypted keyframe (inspect it)."
        ),
    }
    Ok(())
}

fn cmd_derive(
    serial: Option<&str>,
    rand: Option<u64>,
    from: Option<&std::path::Path>,
    offset: usize,
    sfx: u32,
) -> Result<()> {
    let (serial, rand) = match from {
        Some(sample) => resolve_identity(serial, rand, sample)?,
        None => {
            let s = serial.context("pass --serial, or --from <clip> to recover it")?;
            let r = rand.context("pass --rand, or --from <clip> to recover it")?;
            (s.to_string(), r)
        }
    };
    let key = keyderive::derive(&serial, rand, keyderive::Params { offset, sfx });
    println!("key (ascii): {}", String::from_utf8_lossy(&key.0));
    println!("key (hex)  : {}", key.to_hex());
    Ok(())
}

fn cmd_convert(
    file: &std::path::Path,
    out: &std::path::Path,
    key: Option<&str>,
    keys_path: Option<&std::path::Path>,
    raw: bool,
    fps: u32,
) -> Result<()> {
    let selected: Option<Key> = match (key, keys_path) {
        (Some(k), _) => Some(Key::parse(k)?),
        (None, Some(p)) => {
            let data = std::fs::read(file)?;
            let kf = KeyFile::load(p)?;
            let parsed = kf.parsed()?;
            keys::select_key(&parsed, &data).copied().or_else(|| {
                eprintln!("warning: no key in {} decrypts this file; video will be garbled", p.display());
                None
            })
        }
        (None, None) => {
            eprintln!("warning: no key given; keyframes will stay encrypted (audio + P-frames only)");
            None
        }
    };
    convert::convert_file(file, out, selected.as_ref(), fps, raw)?;
    println!("wrote {}", if raw { out.with_extension("h264").display().to_string() } else { out.display().to_string() });
    Ok(())
}

/// Find the first clip under `source` that has an encrypted keyframe and a
/// recoverable rand, and calibrate `(offset, sfx)` against it. Returns the
/// params and the serial used.
fn auto_calibrate(
    source: &std::path::Path,
    serial: Option<&str>,
    max_sfx: u32,
) -> Result<(keyderive::Params, String)> {
    let mut files: Vec<std::path::PathBuf> = walkdir::WalkDir::new(source)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| {
            p.extension()
                .map(|x| x == "dat" || x == "zxvideo")
                .unwrap_or(false)
        })
        .collect();
    files.sort();

    for p in &files {
        let Some((hdr_serial, rand)) = keys::rand_for_video(p) else { continue };
        let serial = serial.unwrap_or(&hdr_serial).to_string();
        let Ok(data) = std::fs::read(p) else { continue };
        let (video, _) = container::split(&data);
        if crypto::count_encrypted_fragments(&video) == 0 {
            continue;
        }
        if let Some(params) = keyderive::calibrate(&serial, rand, &data, max_sfx) {
            return Ok((params, serial));
        }
    }
    bail!(
        "could not auto-calibrate: no clip under {} had both an encrypted keyframe and a \
         recoverable rand that verified. Pass --offset/--sfx (from `calibrate`), or --keys.",
        source.display()
    )
}

#[allow(clippy::too_many_arguments)]
fn cmd_batch(
    source: &std::path::Path,
    dest: &std::path::Path,
    keys_path: Option<&std::path::Path>,
    serial: Option<&str>,
    offset: Option<usize>,
    sfx: Option<u32>,
    jobs: usize,
    fps: u32,
    audio_only_fallback: bool,
    limit: usize,
) -> Result<()> {
    let keysrc = match (keys_path, offset, sfx) {
        // Explicit constants: derive directly.
        (_, Some(offset), Some(sfx)) => convert::KeySource::Derive {
            serial: serial.map(str::to_string),
            params: Params { offset, sfx },
        },
        // keys.json: probe known keys.
        (Some(p), ..) => {
            let kf = KeyFile::load(p)?;
            convert::KeySource::Probe(kf.parsed()?)
        }
        // Nothing supplied: auto-calibrate from the first encrypted clip.
        _ => {
            let (params, used_serial) = auto_calibrate(source, serial, 256)?;
            println!(
                "auto-calibrated from {used_serial}: offset {}, sfx {}",
                params.offset, params.sfx
            );
            convert::KeySource::Derive {
                serial: serial.map(str::to_string),
                params,
            }
        }
    };
    let opts = convert::BatchOptions { jobs, fps, audio_only_fallback, limit };
    let summary = convert::batch(source, dest, &keysrc, &opts)?;
    println!("done: {:?}", summary.stats);
    if !summary.failures.is_empty() {
        println!("{} failure(s); see {}", summary.failures.len(), dest.join("convert_summary.json").display());
    }
    Ok(())
}

fn cmd_extract_audio(file: &std::path::Path, out: &std::path::Path) -> Result<()> {
    let data = std::fs::read(file)?;
    let (_, audio) = container::split(&data);
    if audio.is_empty() {
        bail!("no audio records found in {}", file.display());
    }
    remux::remux_audio_only(&audio, out)?;
    println!("wrote {} ({} bytes of AAC)", out.display(), audio.len());
    Ok(())
}
