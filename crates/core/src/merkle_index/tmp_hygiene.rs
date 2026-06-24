//! Stale-tmp-file hygiene for the merkle index cache directory.
//!
//! This responsibility is orthogonal to indexing: the [`super::MerkleIndex`]
//! load/save logic only needs the directory swept of orphaned temp files
//! before it reads the cache. `tempfile::NamedTempFile`'s `Drop` cleans up on
//! panic but NOT on `SIGKILL`/`SIGTERM` - those leak a random-named tmp file
//! beside the real `merkle.idx`. The sweep below is the only thing that
//! reclaims them, and it is deliberately conservative (name-prefix + age gated)
//! so it can never touch a peer process's in-flight save or an unrelated file.

use std::path::Path;

const TMP_STEM_FALLBACK: &str = "merkle";
pub(super) const MERKLE_TMP_PREFIX: &str = ".tmp.keyhog-merkle-";

/// Stale-tmp-file age cutoff. `tempfile::NamedTempFile`'s Drop impl
/// cleans up on panic but NOT on SIGKILL/SIGTERM - those leak a
/// random-named tmp file in the cache directory. Older than this
/// cutoff means "no chance an in-flight save by another keyhog
/// process is still using it." 1 hour is generous; the longest
/// merkle save in observed runs is < 1 second on a fully-loaded
/// 100k-file scan.
const STALE_TMP_CUTOFF_SECS: u64 = 60 * 60;

/// Best-effort sweep of stale tmp files left behind by SIGKILL'd
/// keyhog processes. Called from `load`/`load_with_spec` before
/// reading the cache so stale tmps don't accumulate forever next
/// to the real `merkle.idx`. Logged at debug level only since
/// failure is non-fatal.
pub(super) fn sweep_stale_tmp_files(cache_path: &Path) {
    let Some(parent) = cache_path.parent() else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    let legacy_tmp_prefix = legacy_cache_tmp_prefix(cache_path);
    let now = std::time::SystemTime::now();
    let mut swept = 0usize;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::debug!(
                    dir = %parent.display(),
                    %error,
                    "cannot read cache tmp directory entry while sweeping stale files; skipping entry"
                );
                continue;
            }
        };
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let path = entry.path();
        if path == cache_path {
            continue;
        }
        // Current saves use a fixed keyhog-owned prefix. Keep matching the
        // old `<stem>.tmp*` prefix, but do not sweep arbitrary anonymous
        // `.tmp*` files from a shared cache directory.
        let is_tmp_sibling =
            name_str.starts_with(MERKLE_TMP_PREFIX) || name_str.starts_with(&legacy_tmp_prefix);
        if !is_tmp_sibling {
            continue;
        }
        let Ok(meta) = path.metadata() else {
            tracing::debug!(
                path = %path.display(),
                "cannot stat cache tmp candidate while sweeping stale files; skipping entry"
            );
            continue;
        };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        let age = match now.duration_since(modified) {
            Ok(d) => d,
            // Best-effort cleanup of our OWN stale `.tmp` siblings; a future
            // mtime (clock skew) only means "don't delete this one yet".
            Err(_) => continue, // LAW10: future mtime, skip our own tmp; no recall impact
        };
        if age.as_secs() < STALE_TMP_CUTOFF_SECS {
            continue;
        }
        if std::fs::remove_file(&path).is_ok() {
            swept += 1;
        }
    }
    if swept > 0 {
        tracing::debug!(
            count = swept,
            dir = %parent.display(),
            "swept stale cache tmp files left by an interrupted save"
        );
    }
}

fn legacy_cache_tmp_prefix(cache_path: &Path) -> String {
    // `file_stem` is `None`/non-UTF8 only for an unnamed or non-UTF8 path.
    // Falling back to "merkle" keeps cleanup best-effort and recall-neutral.
    let stem = cache_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(TMP_STEM_FALLBACK); // LAW10: best-effort temp filename prefix only; cleanup remains conservative and recall-neutral
    format!("{stem}.tmp")
}
