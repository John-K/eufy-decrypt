//! Parsing of the `XZYH` record chain inside a eufy `.dat`/`.zxvideo` file.

use crate::format::*;

/// One parsed record: a slice of the file's payload plus its type tags.
#[derive(Debug, Clone)]
pub struct Record<'a> {
    pub stream_type: u8,
    pub frame_type: u16,
    pub payload: &'a [u8],
    /// Byte offset of the magic for this record within the file.
    pub offset: usize,
    /// Presentation timestamp in ms on the camera's monotonic clock, if the
    /// header carried one (see [`TS_BEFORE_PAYLOAD`]).
    pub ts_ms: Option<u32>,
}

impl Record<'_> {
    pub fn is_video(&self) -> bool {
        self.stream_type == STREAM_VIDEO
    }
    pub fn is_audio(&self) -> bool {
        self.stream_type == STREAM_AUDIO
    }
    pub fn is_iframe(&self) -> bool {
        self.is_video() && (self.frame_type & 0xff) == FRAME_IFRAME
    }
    pub fn more_fragments(&self) -> bool {
        self.frame_type & FRAME_MORE_FRAGMENTS != 0
    }
}

fn read_u16(data: &[u8], at: usize) -> Option<u16> {
    let b = data.get(at..at + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(data: &[u8], at: usize) -> Option<u32> {
    let b = data.get(at..at + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Iterate every `XZYH` record in `data`, resyncing on the magic so a corrupt
/// record cannot derail the whole file.
pub fn records(data: &[u8]) -> Vec<Record<'_>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(rel) = find_magic(&data[i..]) {
        let m = i + rel;
        if m + MIN_HEADER_PROBE > data.len() {
            break;
        }
        let size_field = read_u32(data, m + OFF_SIZE_FIELD).unwrap();
        let frame_type = read_u16(data, m + OFF_FRAME_TYPE).unwrap();
        let payload_len = read_u32(data, m + OFF_PAYLOAD_LEN).unwrap() as usize;
        let stream_type = data[m + OFF_STREAM_TYPE];

        // record_size = size_field + bias; payload sits at the tail of the
        // record, so the header size is (record_size - payload_len).
        let record_size = size_field as usize + SIZE_FIELD_BIAS as usize;
        let header = record_size.checked_sub(payload_len);

        let mut next = m + record_size;
        if let Some(hdr) = header {
            let start = m + hdr;
            if hdr <= record_size
                && start <= data.len()
                && start + payload_len <= data.len()
                && payload_len > 0
            {
                let ts_ms = start
                    .checked_sub(TS_BEFORE_PAYLOAD)
                    .and_then(|at| read_u32(data, at));
                out.push(Record {
                    stream_type,
                    frame_type,
                    payload: &data[start..start + payload_len],
                    offset: m,
                    ts_ms,
                });
            }
        }
        // Guard against zero/negative progress: always advance past this magic.
        if next <= m + 4 {
            next = m + 4;
        }
        i = next;
        if i >= data.len() {
            break;
        }
    }
    out
}

fn find_magic(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == MAGIC)
}

/// Read `(fps, width, height)` from the first video record's header, if the
/// record is long enough to carry those fields.
pub fn video_dimensions(data: &[u8]) -> Option<(u16, u16, u16)> {
    let rec = records(data).into_iter().find(|r| r.is_video())?;
    let m = rec.offset;
    let fps = read_u16(data, m + OFF_FPS)?;
    let width = read_u16(data, m + OFF_WIDTH)?;
    let height = read_u16(data, m + OFF_HEIGHT)?;
    Some((fps, width, height))
}

/// A reassembled video frame: a P-frame carries one fragment; an I-frame may be
/// split across several fragments that must each be decrypted before joining.
#[derive(Debug, Clone)]
pub struct VideoFrame {
    pub is_iframe: bool,
    pub fragments: Vec<Vec<u8>>,
    /// Presentation timestamp (ms) of the frame's first record, if present.
    pub ts_ms: Option<u32>,
}

/// Split a file into its ordered video frames and its concatenated AAC audio.
pub fn split(data: &[u8]) -> (Vec<VideoFrame>, Vec<u8>) {
    let mut video: Vec<VideoFrame> = Vec::new();
    let mut audio: Vec<u8> = Vec::new();
    let mut pending: Vec<Vec<u8>> = Vec::new();
    let mut pending_ts: Option<u32> = None;

    for rec in records(data) {
        if rec.is_audio() {
            audio.extend_from_slice(rec.payload);
        } else if rec.is_video() {
            if rec.is_iframe() {
                if pending.is_empty() {
                    pending_ts = rec.ts_ms; // timestamp of the frame's first fragment
                }
                pending.push(rec.payload.to_vec());
                if !rec.more_fragments() {
                    video.push(VideoFrame {
                        is_iframe: true,
                        fragments: std::mem::take(&mut pending),
                        ts_ms: pending_ts.take(),
                    });
                }
            } else {
                video.push(VideoFrame {
                    is_iframe: false,
                    fragments: vec![rec.payload.to_vec()],
                    ts_ms: rec.ts_ms,
                });
            }
        }
    }
    // Flush any trailing keyframe that never saw its final fragment.
    if !pending.is_empty() {
        video.push(VideoFrame {
            is_iframe: true,
            fragments: pending,
            ts_ms: pending_ts,
        });
    }
    (video, audio)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one record with the documented header layout.
    fn rec(stream: u8, frame: u16, payload: &[u8]) -> Vec<u8> {
        // header is 38 bytes for video, 32 for audio; payload at the tail.
        let hdr = if stream == STREAM_VIDEO { 38usize } else { 32 };
        let record_size = hdr + payload.len();
        let size_field = (record_size - SIZE_FIELD_BIAS as usize) as u32;
        let mut r = vec![0u8; hdr];
        r[0..4].copy_from_slice(MAGIC);
        r[OFF_STREAM_TYPE] = stream;
        r[OFF_SIZE_FIELD..OFF_SIZE_FIELD + 4].copy_from_slice(&size_field.to_le_bytes());
        r[OFF_FRAME_TYPE..OFF_FRAME_TYPE + 2].copy_from_slice(&frame.to_le_bytes());
        r[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 4]
            .copy_from_slice(&(payload.len() as u32).to_le_bytes());
        r.extend_from_slice(payload);
        r
    }

    #[test]
    fn parses_mixed_stream() {
        let mut f = Vec::new();
        f.extend(rec(STREAM_AUDIO, FRAME_AUDIO, b"AAAA"));
        f.extend(rec(STREAM_VIDEO, FRAME_PFRAME, b"PPPP"));
        // keyframe split across two fragments
        f.extend(rec(
            STREAM_VIDEO,
            FRAME_IFRAME | FRAME_MORE_FRAGMENTS,
            b"frag0___",
        ));
        f.extend(rec(STREAM_VIDEO, FRAME_IFRAME, b"frag1"));
        f.extend(rec(STREAM_AUDIO, FRAME_AUDIO, b"BBBB"));

        let (video, audio) = split(&f);
        assert_eq!(audio, b"AAAABBBB");
        assert_eq!(video.len(), 2);
        assert!(!video[0].is_iframe);
        assert_eq!(video[0].fragments, vec![b"PPPP".to_vec()]);
        assert!(video[1].is_iframe);
        assert_eq!(
            video[1].fragments,
            vec![b"frag0___".to_vec(), b"frag1".to_vec()]
        );
    }
}
