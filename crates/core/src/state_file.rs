//! Bounded reads for on-disk KeyHog state artifacts (calibration cache,
//! merkle index, etc.).

use std::io::Read;
use std::path::Path;

/// Maximum on-disk calibration cache (`calibration.json`) size.
///
/// The artifact holds one `{alpha, beta}` pair per detector id — control-plane
/// data, not scan input. Multi-megabyte calibration files are corrupt or hostile.
pub(crate) const CALIBRATION_CACHE_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum size of a user-authored config file read wholesale into memory —
/// suppression rules (`.keyhogignore`/rule-filter TOML) and allowlists. These are
/// hand-authored control-plane data; a multi-megabyte one is corrupt or a
/// resource-exhaustion vector, so the wholesale read is bounded like the caches.
pub(crate) const RULE_CONFIG_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum on-disk merkle index cache file size.
///
/// The JSON index stores `(path, chunk_offset, mtime, size, hash)` rows. Large
/// monorepo caches can reach hundreds of MB; this bound still refuses
/// multi-gigabyte hostile files in the state directory.
pub(crate) const MERKLE_INDEX_CACHE_FILE_BYTES: u64 = 512 * 1024 * 1024;

/// Read a state artifact through a metadata pre-check and a TOCTOU-safe cap.
pub(crate) fn read_capped(path: &Path, cap: u64, kind: &str) -> std::io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{kind} {} exceeds {cap} byte cap; delete the cache file and rerun",
                path.display()
            ),
        ));
    }

    let mut data = Vec::with_capacity(len as usize);
    file.take(cap.saturating_add(1)).read_to_end(&mut data)?;
    if data.len() as u64 > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{kind} {} grew past {cap} byte cap while reading; retry after the file is stable",
                path.display()
            ),
        ));
    }
    Ok(data)
}

/// Atomically replace `path` with `bytes` via a same-directory temp file.
///
/// Single owner for the create-dir / prefixed-tempfile / fsync / rename dance
/// that the calibration cache and the merkle index both persist through. The
/// `prefix` is the temp-file name prefix so each caller's stale-tmp sweep can
/// still recognize its own orphans by name. A parentless or empty path resolves
/// to the current directory so a bare `calibration.json` filename saves cleanly
/// instead of failing `create_dir_all("")`.
pub(crate) fn write_atomically(path: &Path, prefix: &str, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut tmp = tempfile::Builder::new()
        .prefix(prefix)
        .tempfile_in(parent)?;
    std::io::Write::write_all(&mut tmp, bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// Best-effort sweep of stale temp files left beside `cache_path` by a
/// SIGKILL'd process (`tempfile`'s Drop cleans up on panic but not on signal).
///
/// Single owner for the sweep both the calibration cache and the merkle index
/// perform. Deliberately conservative: only files whose name starts with one of
/// the keyhog-owned `prefixes` AND older than `cutoff_secs` are removed, so a
/// peer process's in-flight save or an unrelated file is never touched. Returns
/// the number of files removed; callers own their summary logging.
pub(crate) fn sweep_stale_tmp_siblings(
    cache_path: &Path,
    prefixes: &[&str],
    cutoff_secs: u64,
) -> usize {
    let Some(parent) = cache_path.parent() else {
        return 0;
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return 0;
    };
    let now = std::time::SystemTime::now();
    let mut swept = 0usize;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            // Best-effort maintenance: a failed dir-entry read drops no scan
            // coverage, so skip the entry rather than aborting the sweep.
            Err(error) => {
                tracing::debug!(dir = %parent.display(), %error, "skip unreadable tmp dir entry");
                continue;
            }
        };
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if !prefixes.iter().any(|p| name_str.starts_with(p)) {
            continue;
        }
        let path = entry.path();
        if path == cache_path {
            continue;
        }
        let Ok(meta) = path.metadata() else {
            continue;
        };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        // A future mtime (clock skew) means "don't delete this one yet".
        let Ok(age) = now.duration_since(modified) else {
            continue;
        };
        if age.as_secs() < cutoff_secs {
            continue;
        }
        if std::fs::remove_file(&path).is_ok() {
            swept += 1;
        }
    }
    swept
}
