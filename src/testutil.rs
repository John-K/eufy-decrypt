//! Test-only helpers.
//!
//! The camera serial is a private device identifier, so it is never stored in
//! source. Known-answer tests recover it at runtime from the real sample
//! recordings — the `eufysecurity:<serial>:...` header in a clip's sibling
//! snapshot — and skip when those files are not present (e.g. in CI or a fresh
//! checkout). Point the tests at the recordings with the `EUFY_TEST_DATA`
//! environment variable; absent that, `$HOME/Kitchen_Eufy_Recordings` is tried.

use std::path::PathBuf;

/// Directory expected to hold the sample recordings, or None if we can't guess.
fn data_dir() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("EUFY_TEST_DATA") {
        return Some(PathBuf::from(d));
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Kitchen_Eufy_Recordings"))
}

/// Recover the camera serial from the first sample clip with a readable
/// `eufysecurity:` snapshot header. None when no sample data is available, so
/// callers skip the test rather than fail.
pub fn sample_serial() -> Option<String> {
    let dir = data_dir()?;
    for entry in walkdir::WalkDir::new(dir).into_iter().flatten() {
        let p = entry.path();
        if p.extension().is_some_and(|x| x == "zxvideo" || x == "dat")
            && let Some((serial, _rand)) = crate::keys::rand_for_video(p)
        {
            return Some(serial);
        }
    }
    None
}
