# eufy-decrypt

Decrypt eufy camera SD-card recordings to MP4, fully offline. A pure-Rust tool
for recovering **your own footage** from **your own camera and card**, based on
the method documented by Christian Guevara
([thedveloper.com](https://thedveloper.com/blog/eufy-t8400-sdcard-decryption))
and the USENIX WOOT'24 paper *"Reverse Engineering the Eufy Ecosystem"* (Goeman
et al.). The key derivation was reverse-engineered from the app's native library
and reimplemented in Rust, and the MP4 is authored in-process, so no external
tools are needed: no Python, no angr, no ffmpeg.

## Safety first

The SD card is usually the only copy of your footage. **Image it read-only and
verify the copy before running anything**, then work only against the backup:

```bash
sudo dd if=/dev/sdX of=card.img bs=4M status=progress   # or cp the files
sha256sum card.img > card.sha256 && sha256sum -c card.sha256
```

`eufy-decrypt` only reads the sources you name and only writes to the
destinations you name.

## How the format works

Two on-card layouts are supported, both built from the same `XZYH` record
container:

- **Continuous (`.dat`, e.g. T8400):** files under `video/continue/`, named
  `YYYYMMDDHHMMSS.dat`, with a sibling `continuefilelink.dat` mapping each to a
  10-digit week code (`"01" + rand`), one key per weekly rotation.
- **Event clips (`.zxvideo`, e.g. T8416):** files under
  `Camera00/event/YYYYMM/YYYYMMDD/`, each with a `.zxmap`, a `.txt`, and encrypted
  snapshot JPEGs. Each snapshot begins `eufysecurity:<serial>:01<rand>:`, so the
  per-clip `rand` is read straight from the sibling snapshot. One key per clip.

In both, audio and inter-frames are plaintext; only the **first 128 bytes of each
keyframe fragment** are AES-128-ECB encrypted. The tool decides what to decrypt
by the Annex-B start code, so it also handles cameras that tag every record as a
keyframe. Video is H.264 or H.265/HEVC; the codec is auto-detected before remux. Each
record carries a millisecond timestamp, so frames are timed exactly in the MP4
(tolerating dropped frames) instead of assuming a constant rate; `--fps` is only
a fallback for clips whose records lack timestamps.
Format constants live in `src/format.rs`; **run `inspect` first on any other
model** to confirm the layout before trusting a decrypt.

## Workflow

```bash
# 0. build
cargo build --release

# 1. confirm the format and read serial/rand from an event clip
eufy-decrypt inspect /backup/Camera00/event/202608/20260813/20260813101151.zxvideo

# 2. convert the whole card in parallel. For event-clip cameras this is all you
#    need: it auto-calibrates the derivation constants from the first encrypted
#    clip and derives each file's key from its own snapshot. Resumable; skips
#    existing. Add --offset/--sfx to skip calibration, or --keys to use a
#    keys.json of known keys.
eufy-decrypt batch --source /backup/Camera00/event --dest ~/eufy_mp4 \
    --audio-only-fallback

# optional one-offs:
#   recover the constants explicitly (prints offset + sfx):
eufy-decrypt calibrate /backup/.../20260813101151.zxvideo
#   convert one clip with an explicit key:
eufy-decrypt convert in.zxvideo --out out.mp4 --key 0ADD5A67A51A0762
#   derive one key, recovering serial+rand from the clip's snapshot:
eufy-decrypt derive --from in.zxvideo --offset 3 --sfx 12

# for a continuous (T8400) card, first derive a keys.json of weekly keys from
# continuefilelink.dat (one key per weekly code). The serial is required (no
# snapshot); --offset/--sfx auto-calibrate against a sibling .dat when omitted:
eufy-decrypt keys /backup/video/continue/continuefilelink.dat \
    --serial T8400XXXXXXXXXXXX --out keys.json
# then batch against that keys.json of known keys
eufy-decrypt batch --source /backup/video/continue --dest ~/eufy_mp4 --keys keys.json

# audio needs no key at all:
eufy-decrypt extract-audio in.zxvideo --out audio.m4a
```

Output is laid out as `dest/<YYYYMMDD>/<YYYYMMDDHHMMSS>.mp4`. `batch` writes a
`convert_summary.json` and skips already-converted files, so it is safe to re-run.

## Key derivation

The key is the first 16 ASCII bytes of `gen_pic_code_v1(serial, ppcs_id, rand)`,
reverse-engineered from `libcrypto-security.so` and reimplemented in pure Rust in
`src/keyderive.rs`:

```text
sfx      = cal_ppcs_id_suffix(ppcs_id)        # small int, device-constant
offset   = f(serial)                          # device-constant (serial-derived)
baseCode = serial[offset..16] + str(sfx)
seed     = UPPERHEX( MD5( str(1000-sfx) + str(rand) ) )
digest   = SHA256( "01" + baseCode + seed )
digest'  = obfuscate2(digest)                 # in-place neighbour add / abs-diff
key      = UPPERHEX( digest'[16..24] )        # 16 ASCII chars = AES-128 key
```

`sfx` and `offset` depend only on the camera (not the per-file `rand`), so
`calibrate` recovers them once by trying the small space against a real keyframe,
and every file's key then follows from its own `rand`. Derivation self-verifies
against the keyframe (for H.264 and HEVC), so a wrong constant fails loudly
instead of producing garbled video.

The `serial` and per-clip `rand` are read from the sibling snapshot's
`eufysecurity:<serial>:01<rand>:` header, so `--serial` is optional on
`calibrate`, `derive` (with `--from <clip>`), and `batch`; pass it explicitly
only for files that have no snapshot, such as `.dat` continuous recordings.

Verified against a real T8416 (serial `T8416P0000000000`): `offset 3`, `sfx 12`,
rand `15060042` -> key `0ADD5A67A51A0762`, which decrypts to a clean 2304x1296
HEVC keyframe. This case is pinned as a regression test.

## keys.json format

```json
{ "keys": [ { "key": "89DD11D2DF09ED7D", "label": "2024-10-07" } ] }
```

`key` is 16 ASCII chars or 32 hex chars. `batch --keys` / `convert --keys` try
every key against each file's first keyframe and use whichever yields a valid
video header, so you can keep all your keys in one file. `keys.json` is
gitignored: the keys are specific to your camera.

## Requirements

- Rust (edition 2024) only. The MP4 is authored in-process (pure Rust, via the
  `shiguredo_mp4` crate), so **ffmpeg is not required**. `--raw` skips the
  container and writes the raw `.h264`/`.hevc` + `.aac` elementary streams.

## Credits

Method and reference scripts by Christian Guevara (thedveloper.com); key-
derivation research by Goeman, de Ruck, Cordemans, Lapon, and Naessens
(USENIX WOOT'24). This is an independent Rust reimplementation.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Unless you explicitly state
otherwise, any contribution intentionally submitted for inclusion in this work
by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.
