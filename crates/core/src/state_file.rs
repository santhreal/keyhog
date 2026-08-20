//! Bounded reads and atomic durable writes for on-disk KeyHog state artifacts
//! (calibration cache, merkle index, compiled matcher artifacts, etc.).

use fs2::FileExt;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Exclusive advisory lock held across a state file's read/merge/write cycle.
///
/// The sibling `<filename>.lock` file is stable; the operating-system lock is
/// released automatically when this value is dropped, including after a panic
/// or process exit. Keeping one implementation here prevents state caches from
/// independently reintroducing lost-update races.
pub struct StateFileWriteLock {
    file: File,
}

impl StateFileWriteLock {
    /// Acquire the canonical sibling lock for `state_path`.
    pub fn acquire(state_path: &Path) -> std::io::Result<Self> {
        let lock_path = state_file_lock_path(state_path)?;
        let parent = lock_path.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "state-file lock path has no parent directory",
            )
        })?;
        std::fs::create_dir_all(parent)?;
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        loop {
            let file = options.open(&lock_path)?;
            file.lock_exclusive()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if let (Ok(meta1), Ok(meta2)) = (file.metadata(), std::fs::metadata(&lock_path)) {
                    if meta1.ino() == meta2.ino() && meta1.dev() == meta2.dev() && meta1.nlink() > 0
                    {
                        return Ok(Self { file });
                    }
                    let _ = FileExt::unlock(&file); // LAW10: the retained handle is dropped on the next iteration, which releases the OS lock; no runtime effect
                    continue;
                }
            }
            return Ok(Self { file });
        }
    }
}

impl Drop for StateFileWriteLock {
    fn drop(&mut self) {
        if let Err(error) = FileExt::unlock(&self.file) {
            tracing::warn!(%error, "failed to unlock KeyHog state file; closing the lock file will release the OS lock");
        }
    }
}

/// Canonical sibling lock filename for a KeyHog state artifact.
pub fn state_file_lock_path(state_path: &Path) -> std::io::Result<PathBuf> {
    let Some(base_name) = state_path.file_name() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("state path '{}' has no file name", state_path.display()),
        ));
    };
    let mut file_name = OsString::from(base_name);
    file_name.push(".lock");
    Ok(state_path.with_file_name(file_name))
}

/// Default temp-file name prefix for atomic state writes.
pub const DEFAULT_TMP_PREFIX: &str = ".tmp.keyhog-";

/// Maximum on-disk calibration cache (`calibration.json`) size.
///
/// The artifact holds one `{alpha, beta}` pair per detector id, control-plane
/// data, not scan input. Multi-megabyte calibration files are corrupt or hostile.
pub(crate) const CALIBRATION_CACHE_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum size of a user-authored config file read wholesale into memory
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
pub fn read_capped(path: &Path, cap: u64, kind: &str) -> std::io::Result<Vec<u8>> {
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
/// Single owner for the create-dir / prefixed-tempfile / sync / rename dance
/// that all KeyHog state artifacts, caches, and scanner artifacts persist through.
/// A parentless or empty path resolves to the current directory (`.`) so a bare
/// output filename saves cleanly instead of failing `create_dir_all("")`.
pub fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_atomically_with_prefix(path, DEFAULT_TMP_PREFIX, bytes)
}

/// Atomically replace `path` with `bytes` using a custom temp-file prefix.
pub fn write_atomically_with_prefix(
    path: &Path,
    prefix: &str,
    bytes: &[u8],
) -> std::io::Result<()> {
    write_atomically_with_writer_and_prefix(path, prefix, |tmp| {
        use std::io::Write as _;
        tmp.write_all(bytes)
    })
}

/// Atomically create or replace `path` by executing a writer closure against a
/// same-directory temp file.
///
/// The temp file is synced to disk via [`std::fs::File::sync_all`] before atomic
/// rename onto `path`. If `writer` returns an error or panics, the temporary file
/// is automatically dropped and unlinked by [`tempfile::NamedTempFile`]'s `Drop`
/// implementation, preventing partially-written files from corrupting state or
/// leaking stale artifacts.
pub fn write_atomically_with_writer<F>(path: &Path, writer: F) -> std::io::Result<()>
where
    F: FnOnce(&mut tempfile::NamedTempFile) -> std::io::Result<()>,
{
    write_atomically_with_writer_and_prefix(path, DEFAULT_TMP_PREFIX, writer)
}

/// Atomically create or replace `path` with a custom temp-file prefix via a writer closure.
pub fn write_atomically_with_writer_and_prefix<F>(
    path: &Path,
    prefix: &str,
    writer: F,
) -> std::io::Result<()>
where
    F: FnOnce(&mut tempfile::NamedTempFile) -> std::io::Result<()>,
{
    let parent = match path.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(parent) => parent,
        None => Path::new("."),
    };
    std::fs::create_dir_all(parent)?;
    let mut tmp = tempfile::Builder::new()
        .prefix(prefix)
        .tempfile_in(parent)?;
    writer(&mut tmp)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map(drop).map_err(|e| e.error)
}

/// Best-effort sweep of stale temp files left beside `cache_path` by a
/// SIGKILL'd process (`tempfile`'s Drop cleans up on panic but not on signal).
///
/// Single owner for the sweep both the calibration cache and the merkle index
/// perform. Deliberately conservative: only files whose name starts with one of
/// the keyhog-owned `prefixes` AND older than `cutoff_secs` are removed, so a
/// peer process's in-flight save or an unrelated file is never touched. Returns
/// the number of files removed; callers own their summary logging.
pub fn sweep_stale_tmp_siblings(cache_path: &Path, prefixes: &[&str], cutoff_secs: u64) -> usize {
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
                tracing::warn!(dir = %parent.display(), %error, "skip unreadable tmp dir entry during stale-state sweep");
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
