//! Remux decrypted elementary streams into an MP4 via ffmpeg (stream copy, no
//! re-encode).

use crate::format::DEFAULT_FPS;
use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

/// Write the video and (optional) AAC streams next to `out_mp4` and mux them.
/// `codec` is "h264" or "hevc" (the ffmpeg demuxer/extension for the elementary
/// stream). Returns the ffmpeg stderr on failure.
pub fn remux(video: &[u8], aac: &[u8], out_mp4: &Path, fps: u32, codec: &str) -> Result<()> {
    if let Some(parent) = out_mp4.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let ext = if codec == "hevc" { "hevc" } else { "h264" };
    let stem = out_mp4.with_extension("");
    let v = stem.with_extension(ext);
    let a = stem.with_extension("aac");

    std::fs::write(&v, video).with_context(|| format!("writing {}", v.display()))?;
    let have_audio = !aac.is_empty();
    if have_audio {
        std::fs::write(&a, aac).with_context(|| format!("writing {}", a.display()))?;
    }

    let fps = if fps == 0 { DEFAULT_FPS } else { fps };
    let mut cmd = Command::new("ffmpeg");
    cmd.args(["-y", "-loglevel", "error", "-r", &fps.to_string(), "-f", codec, "-i"]);
    cmd.arg(&v);
    if have_audio {
        cmd.arg("-i").arg(&a);
    }
    cmd.args(["-c:v", "copy"]);
    if have_audio {
        cmd.args(["-c:a", "copy"]);
    }
    cmd.args(["-movflags", "+faststart"]);
    cmd.arg(out_mp4);

    let output = cmd.output().context("failed to launch ffmpeg (is it installed?)")?;
    let _ = std::fs::remove_file(&v);
    let _ = std::fs::remove_file(&a);
    if !output.status.success() {
        bail!("ffmpeg failed: {}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(())
}

/// Write just the AAC audio to an `.m4a` (no key needed).
pub fn remux_audio_only(aac: &[u8], out_m4a: &Path) -> Result<()> {
    if let Some(parent) = out_m4a.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let a = out_m4a.with_extension("aac");
    std::fs::write(&a, aac).with_context(|| format!("writing {}", a.display()))?;
    let output = Command::new("ffmpeg")
        .args(["-y", "-loglevel", "error", "-i"])
        .arg(&a)
        .args(["-c:a", "copy"])
        .arg(out_m4a)
        .output()
        .context("failed to launch ffmpeg (is it installed?)")?;
    let _ = std::fs::remove_file(&a);
    if !output.status.success() {
        bail!("ffmpeg failed: {}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(())
}

/// Write the raw elementary streams without invoking ffmpeg.
pub fn write_raw(video: &[u8], aac: &[u8], out_base: &Path, codec: &str) -> Result<()> {
    if let Some(parent) = out_base.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let ext = if codec == "hevc" { "hevc" } else { "h264" };
    let v = out_base.with_extension(ext);
    std::fs::write(&v, video).with_context(|| format!("writing {}", v.display()))?;
    if !aac.is_empty() {
        let a = out_base.with_extension("aac");
        std::fs::write(&a, aac).with_context(|| format!("writing {}", a.display()))?;
    }
    Ok(())
}
