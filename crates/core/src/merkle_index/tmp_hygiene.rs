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

// Stale-tmp-file age cutoff (one owner in `crate::STALE_TMP_CUTOFF_SECS`).
// `tempfile::NamedTempFile`'s Drop cleans up on panic but NOT on
// SIGKILL/SIGTERM - those leak a random-named tmp file in the cache dir.
// Older than the cutoff means "no chance an in-flight save by another keyhog
// process is still using it." 1 hour is generous; the longest merkle save in
// observed runs is < 1 second on a fully-loaded 100k-file scan.
use crate::STALE_TMP_CUTOFF_SECS;

/// Best-effort sweep of stale tmp files left behind by SIGKILL'd
/// keyhog processes. Called from `load`/`load_with_spec` before
/// reading the cache so stale tmps don't accumulate forever next
/// to the real `merkle.idx`. Logged at debug level only since
/// failure is non-fatal.
pub(super) fn sweep_stale_tmp_files(cache_path: &Path) {
    // Current saves use a fixed keyhog-owned prefix; also match the legacy
    // `<stem>.tmp*` prefix. The shared sweeper refuses to touch anything that
    // does not start with one of these, so unrelated files in a shared cache
    // directory are never removed.
    let legacy_tmp_prefix = legacy_cache_tmp_prefix(cache_path);
    let swept = crate::state_file::sweep_stale_tmp_siblings(
        cache_path,
        &[MERKLE_TMP_PREFIX, &legacy_tmp_prefix],
        STALE_TMP_CUTOFF_SECS,
    );
    if swept > 0 {
        if let Some(parent) = cache_path.parent() {
            tracing::debug!(
                count = swept,
                dir = %parent.display(),
                "swept stale cache tmp files left by an interrupted save"
            );
        }
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
