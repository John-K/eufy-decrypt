//! Author an MP4 in-process from the decrypted elementary streams, with no
//! external tools. Uses `shiguredo_mp4` (pure Rust) to build hvcC/avcC and esds
//! sample entries from the Annex-B parameter sets and ADTS headers, then writes
//! a faststart MP4 file. No re-encoding.

use crate::crypto::Frame;
use crate::format::DEFAULT_FPS;
use anyhow::{Context, Result, anyhow, bail};
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::num::NonZeroU32;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use shiguredo_mp4::TrackKind;
use shiguredo_mp4::bitstream::aac::{
    self, AudioSpecificConfig, Mp4aSampleEntryConfig, SamplingFrequency,
};
use shiguredo_mp4::bitstream::h264::{self, H264SampleEntryConfig};
use shiguredo_mp4::bitstream::h265::{self, H265ConstantFrameRate, H265SampleEntryConfig, LengthSize};
use shiguredo_mp4::boxes::SampleEntry;
use shiguredo_mp4::mux::{Mp4FileMuxer, Mp4FileMuxerOptions, Sample, estimate_maximum_moov_box_size};

/// Map any shiguredo_mp4 error into anyhow with a prefix.
fn me<E: std::fmt::Display>(ctx: &str) -> impl FnOnce(E) -> anyhow::Error + '_ {
    move |e| anyhow!("{ctx}: {e}")
}

/// An audio sample: raw AAC payload (ADTS header stripped).
struct AudioTrack {
    entry: SampleEntry,
    rate: u32,
    samples: Vec<Vec<u8>>,
}

/// Parse concatenated ADTS audio into raw AAC samples plus an mp4a sample entry.
fn parse_audio(aac_bytes: &[u8]) -> Result<Option<AudioTrack>> {
    if aac_bytes.is_empty() {
        return Ok(None);
    }
    let mut samples = Vec::new();
    let mut asc: Option<AudioSpecificConfig> = None;
    let mut rate = 0u32;
    let mut pos = 0usize;
    while pos < aac_bytes.len() {
        let (hdr, payload) =
            aac::parse_adts_frame(&aac_bytes[pos..]).map_err(me("parsing ADTS frame"))?;
        if asc.is_none() {
            let hz = sfi_to_hz(hdr.sampling_frequency_index)
                .ok_or_else(|| anyhow!("unknown AAC sampling frequency index"))?;
            rate = hz;
            asc = Some(AudioSpecificConfig {
                audio_object_type: hdr.audio_object_type,
                sampling_frequency: SamplingFrequency::from_hz(hz).map_err(me("AAC sample rate"))?,
                channel_configuration: hdr.channel_configuration,
            });
        }
        samples.push(payload.to_vec());
        let flen = hdr.frame_length as usize;
        if flen == 0 {
            break;
        }
        pos += flen;
    }
    let asc = match asc {
        Some(a) => a,
        None => return Ok(None),
    };
    let mp4a = aac::build_mp4a_box(
        &asc,
        &Mp4aSampleEntryConfig { es_id: 1, buffer_size_db: 0, max_bitrate: 0, avg_bitrate: 0 },
    )
    .map_err(me("building mp4a box"))?;
    Ok(Some(AudioTrack { entry: SampleEntry::Mp4a(mp4a), rate, samples }))
}

fn sfi_to_hz(i: u8) -> Option<u32> {
    const RATES: [u32; 13] = [
        96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350,
    ];
    RATES.get(i as usize).copied()
}

/// Decide video sample timing. Prefer the container's per-frame millisecond
/// timestamps — exact and tolerant of dropped frames — and fall back to a
/// constant `fps` when they are absent or implausible. Returns the video
/// timescale, each sample's duration in that timescale, and each sample's
/// presentation start in seconds (used to interleave with audio).
fn video_timing(frames: &[Frame], fps: u32) -> (NonZeroU32, Vec<u32>, Vec<f64>) {
    const MAX_GAP_MS: u32 = 10_000;
    let n = frames.len();
    let ts: Option<Vec<u32>> = frames.iter().map(|f| f.ts_ms).collect();
    if let Some(ts) = ts {
        let sane = ts.windows(2).all(|w| w[1] >= w[0] && w[1] - w[0] <= MAX_GAP_MS);
        if n >= 2 && sane && ts[n - 1] > ts[0] {
            let scale = NonZeroU32::new(1000).unwrap();
            let mut durations: Vec<u32> = (0..n - 1).map(|i| (ts[i + 1] - ts[i]).max(1)).collect();
            durations.push(*durations.last().unwrap()); // last frame: reuse prior delta
            let t0 = ts[0] as f64;
            let starts = ts.iter().map(|&t| (t as f64 - t0) / 1000.0).collect();
            return (scale, durations, starts);
        }
    }
    let fps = if fps == 0 { DEFAULT_FPS } else { fps };
    let scale = NonZeroU32::new(fps).unwrap_or(NonZeroU32::new(DEFAULT_FPS).unwrap());
    let starts = (0..n).map(|i| i as f64 / fps as f64).collect();
    (scale, vec![1u32; n], starts)
}

/// Build the video sample entry and length-prefixed per-frame samples.
fn build_video(frames: &[Frame], codec: &str) -> Result<(SampleEntry, Vec<Vec<u8>>)> {
    let kf = frames
        .iter()
        .find(|f| f.is_keyframe)
        .ok_or_else(|| anyhow!("no keyframe to build the video sample entry"))?;
    let (entry, samples) = if codec == "hevc" {
        let cfg = H265SampleEntryConfig {
            length_size: LengthSize::FourBytes,
            avg_frame_rate: 0,
            constant_frame_rate: H265ConstantFrameRate::Unknown,
        };
        let hev1 =
            h265::build_hev1_box_from_annexb(&kf.annexb, &cfg).map_err(me("building hev1 box"))?;
        let samples = frames
            .iter()
            .map(|f| h265::annexb_to_length_prefixed(&f.annexb, LengthSize::FourBytes))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(me("converting HEVC frame to length-prefixed"))?;
        (SampleEntry::Hev1(hev1), samples)
    } else {
        let cfg = H264SampleEntryConfig { length_size: LengthSize::FourBytes };
        let avc1 =
            h264::build_avc1_box_from_annexb(&kf.annexb, &cfg).map_err(me("building avc1 box"))?;
        let samples = frames
            .iter()
            .map(|f| h264::annexb_to_length_prefixed(&f.annexb, LengthSize::FourBytes))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(me("converting H.264 frame to length-prefixed"))?;
        (SampleEntry::Avc1(avc1), samples)
    };
    Ok((entry, samples))
}

/// Set a file's modification time to the clip's recording time, so recovered
/// clips sort by when they were filmed. Best-effort: a failure here never fails
/// the conversion.
fn stamp_mtime(file: &File, creation_unix: Option<u64>) {
    if let Some(secs) = creation_unix {
        let _ = file.set_modified(UNIX_EPOCH + Duration::from_secs(secs));
    }
}

/// Author `out` as an MP4 from decrypted video frames and ADTS audio.
/// `creation_unix`, when set, stamps the MP4 creation time and the file mtime.
pub fn mux_mp4(
    frames: &[Frame],
    aac_bytes: &[u8],
    out: &Path,
    fps: u32,
    codec: &str,
    creation_unix: Option<u64>,
) -> Result<()> {
    if frames.is_empty() {
        bail!("no video frames to mux");
    }
    let fps = if fps == 0 { DEFAULT_FPS } else { fps };
    let (video_entry, video_samples) = build_video(frames, codec)?;
    let audio = parse_audio(aac_bytes)?;

    let (v_ts, v_durations, v_starts) = video_timing(frames, fps);
    let mut counts = vec![video_samples.len()];
    if let Some(a) = &audio {
        counts.push(a.samples.len());
    }
    let reserved = estimate_maximum_moov_box_size(&counts);
    let muxer_opts = Mp4FileMuxerOptions {
        reserved_moov_box_size: reserved,
        creation_timestamp: Duration::from_secs(creation_unix.unwrap_or(0)),
        ..Default::default()
    };
    let mut muxer = Mp4FileMuxer::with_options(muxer_opts).map_err(me("creating muxer"))?;

    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut file = File::create(out).with_context(|| format!("creating {}", out.display()))?;
    let init = muxer.initial_boxes_bytes().to_vec();
    file.write_all(&init)?;
    let mut pos = init.len() as u64;

    // Interleave video and audio by presentation time for progressive playback.
    let a_rate = audio.as_ref().map(|a| a.rate).unwrap_or(1);
    let a_samples = audio.as_ref().map(|a| a.samples.as_slice()).unwrap_or(&[]);
    let (mut vi, mut ai) = (0usize, 0usize);
    let mut first_v = true;
    let mut first_a = true;
    while vi < video_samples.len() || ai < a_samples.len() {
        // time in seconds of the next sample of each track
        let v_time = if vi < video_samples.len() {
            v_starts[vi]
        } else {
            f64::INFINITY
        };
        let a_time = if ai < a_samples.len() {
            (ai as f64 * 1024.0) / a_rate as f64
        } else {
            f64::INFINITY
        };
        if v_time <= a_time {
            let data = &video_samples[vi];
            file.write_all(data)?;
            let sample = Sample {
                track_kind: TrackKind::Video,
                sample_entry: first_v.then(|| video_entry.clone()),
                keyframe: frames[vi].is_keyframe,
                timescale: v_ts,
                duration: v_durations[vi],
                composition_time_offset: None,
                data_offset: pos,
                data_size: data.len(),
            };
            muxer.append_sample(&sample).map_err(me("appending video sample"))?;
            pos += data.len() as u64;
            first_v = false;
            vi += 1;
        } else {
            let data = &a_samples[ai];
            file.write_all(data)?;
            let sample = Sample {
                track_kind: TrackKind::Audio,
                sample_entry: first_a.then(|| audio.as_ref().unwrap().entry.clone()),
                keyframe: true,
                timescale: NonZeroU32::new(a_rate).unwrap_or(v_ts),
                duration: 1024,
                composition_time_offset: None,
                data_offset: pos,
                data_size: data.len(),
            };
            muxer.append_sample(&sample).map_err(me("appending audio sample"))?;
            pos += data.len() as u64;
            first_a = false;
            ai += 1;
        }
    }

    let finalized = muxer.finalize().map_err(me("finalizing moov"))?;
    for (offset, bytes) in finalized.offset_and_bytes_pairs() {
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(bytes)?;
    }
    file.flush()?;
    stamp_mtime(&file, creation_unix);
    Ok(())
}

/// Author an audio-only MP4 (`.m4a`) from ADTS audio; no key needed.
/// `creation_unix`, when set, stamps the MP4 creation time and the file mtime.
pub fn mux_audio_only(aac_bytes: &[u8], out: &Path, creation_unix: Option<u64>) -> Result<()> {
    let audio = parse_audio(aac_bytes)?.ok_or_else(|| anyhow!("no audio to mux"))?;
    let counts = [audio.samples.len()];
    let reserved = estimate_maximum_moov_box_size(&counts);
    let muxer_opts = Mp4FileMuxerOptions {
        reserved_moov_box_size: reserved,
        creation_timestamp: Duration::from_secs(creation_unix.unwrap_or(0)),
        ..Default::default()
    };
    let mut muxer = Mp4FileMuxer::with_options(muxer_opts).map_err(me("creating muxer"))?;

    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut file = File::create(out).with_context(|| format!("creating {}", out.display()))?;
    let init = muxer.initial_boxes_bytes().to_vec();
    file.write_all(&init)?;
    let mut pos = init.len() as u64;
    let a_ts = NonZeroU32::new(audio.rate).unwrap_or(NonZeroU32::new(DEFAULT_FPS).unwrap());
    let mut first = true;
    for data in &audio.samples {
        file.write_all(data)?;
        let sample = Sample {
            track_kind: TrackKind::Audio,
            sample_entry: first.then(|| audio.entry.clone()),
            keyframe: true,
            timescale: a_ts,
            duration: 1024,
            composition_time_offset: None,
            data_offset: pos,
            data_size: data.len(),
        };
        muxer.append_sample(&sample).map_err(me("appending audio sample"))?;
        pos += data.len() as u64;
        first = false;
    }
    let finalized = muxer.finalize().map_err(me("finalizing moov"))?;
    for (offset, bytes) in finalized.offset_and_bytes_pairs() {
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(bytes)?;
    }
    file.flush()?;
    stamp_mtime(&file, creation_unix);
    Ok(())
}

/// Write the raw elementary streams without building a container.
pub fn write_raw(video: &[u8], aac_bytes: &[u8], out_base: &Path, codec: &str) -> Result<()> {
    if let Some(parent) = out_base.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let ext = if codec == "hevc" { "hevc" } else { "h264" };
    let v = out_base.with_extension(ext);
    std::fs::write(&v, video).with_context(|| format!("writing {}", v.display()))?;
    if !aac_bytes.is_empty() {
        let a = out_base.with_extension("aac");
        std::fs::write(&a, aac_bytes).with_context(|| format!("writing {}", a.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shiguredo_mp4::{Decode, Mp4File};
    use shiguredo_mp4::bitstream::aac::{
        AdtsEncodeConfig, AdtsMpegVersion, AudioObjectType, ChannelConfiguration,
        wrap_raw_aac_in_adts,
    };

    fn frame(ts: Option<u32>) -> Frame {
        Frame { is_keyframe: false, annexb: Vec::new(), ts_ms: ts }
    }

    #[test]
    fn video_timing_uses_timestamps_including_a_dropped_frame() {
        // 1000,1067,1134 then a 134 ms gap (one frame dropped) to 1268.
        let frames = [1000, 1067, 1134, 1268].map(|t| frame(Some(t)));
        let (scale, durations, starts) = video_timing(&frames, 15);
        assert_eq!(scale.get(), 1000); // millisecond timescale
        assert_eq!(durations, vec![67, 67, 134, 134]); // gap honored; last reuses prior
        assert!((starts[2] - 0.134).abs() < 1e-9);
        assert!((starts[3] - 0.268).abs() < 1e-9);
    }

    #[test]
    fn video_timing_falls_back_to_cfr_without_timestamps() {
        let frames = [frame(None), frame(None)];
        let (scale, durations, starts) = video_timing(&frames, 15);
        assert_eq!(scale.get(), 15); // fps timescale
        assert_eq!(durations, vec![1, 1]);
        assert!((starts[1] - 1.0 / 15.0).abs() < 1e-9);
    }

    #[test]
    fn mux_audio_only_produces_valid_mp4() {
        // Build two valid ADTS frames (AAC-LC, 16 kHz, mono) from dummy payloads.
        let asc = AudioSpecificConfig {
            audio_object_type: AudioObjectType::AacLc,
            sampling_frequency: SamplingFrequency::from_hz(16000).unwrap(),
            channel_configuration: ChannelConfiguration::Mono,
        };
        let enc = AdtsEncodeConfig {
            mpeg_version: AdtsMpegVersion::Mpeg4,
            original_copy: false,
            home: false,
        };
        let mut adts = Vec::new();
        for _ in 0..2 {
            adts.extend(wrap_raw_aac_in_adts(&[0x21, 0x10, 0x05], &asc, &enc).unwrap());
        }

        let out = std::env::temp_dir().join(format!("eufy_test_{}.m4a", std::process::id()));
        mux_audio_only(&adts, &out, None).unwrap();
        let bytes = std::fs::read(&out).unwrap();
        std::fs::remove_file(&out).ok();

        // The output must be a parseable MP4 file.
        let (_file, size) = <Mp4File>::decode(&bytes[..]).expect("output is a valid MP4");
        assert!(size > 0);
    }
}
