//! Cross-chunk fragment cache for secret-fragment reassembly.
//!
//! This allows KeyHog to detect secrets split across different files or
//! distant locations within a large file that exceed the chunk window.

use lru::LruCache;
use parking_lot::Mutex;
use std::cell::RefCell;
use std::num::NonZeroUsize;
use std::sync::Arc;
use zeroize::Zeroizing;

const SHARD_COUNT: usize = 64;
const MAX_FRAGMENTS_PER_SCOPE: usize = 8;

/// A potential fragment of a secret (variable assignment part).
///
/// `value` is wrapped in `Zeroizing<String>` so that fragment text gets
/// scrubbed from the heap when an entry is evicted from the LRU or the
/// cache is dropped. kimi-wave1 audit finding 1.HIGH: previously the
/// credential text lived in a plain `String` for the lifetime of the
/// scan, and reassembled candidates were materialized into a `Chunk`
/// that re-embedded the secret in a `format!`-built synthetic line. The
/// `Debug` derive is also intentionally NOT wired through `value`
/// - `Zeroizing<String>` prints redacted in `{:?}`.
#[derive(Clone)]
pub(crate) struct SecretFragment {
    pub prefix: String,
    pub var_name: String,
    pub value: Zeroizing<String>,
    pub line: usize,
    pub path: Option<Arc<str>>,
}

impl std::fmt::Debug for SecretFragment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretFragment")
            .field("prefix", &self.prefix)
            .field("var_name", &self.var_name)
            .field(
                "value",
                &format_args!("<redacted {} bytes>", self.value.len()),
            )
            .field("line", &self.line)
            .field("path", &self.path)
            .finish()
    }
}

/// A reassembled credential candidate plus the provenance of the
/// fragment that anchors it. The anchor is the *prefix* fragment of
/// the join (`f1` below): reassembled findings must be stamped with the
/// real contributing file's path and line, NOT the path of whatever
/// chunk happened to be scanning when the join completed. Without this,
/// a join that fires while processing sibling file B was attributed to
/// B even though both fragments came from file A - the cross-file
/// mis-attribution half of the precision bug.
#[cfg(any(feature = "simd", test))]
pub(crate) struct ReassembledCandidate {
    /// Glued credential text. Zeroized on drop.
    pub value: Zeroizing<String>,
    /// Path of the anchoring (prefix) fragment, if known.
    pub path: Option<Arc<str>>,
    /// Source line of the anchoring (prefix) fragment.
    pub line: usize,
}

#[cfg(any(feature = "simd", test))]
impl std::fmt::Debug for ReassembledCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReassembledCandidate")
            .field(
                "value",
                &format_args!("<redacted {} bytes>", self.value.len()),
            )
            .field("path", &self.path)
            .field("line", &self.line)
            .finish()
    }
}

/// Deterministically evict one fragment when a scope exceeds
/// [`MAX_FRAGMENTS_PER_SCOPE`]. The previous `cluster.remove(0)` dropped the
/// EARLIEST-ARRIVED fragment, but under the parallel (rayon) scan the order in
/// which sibling chunks of the same file win the per-shard mutex is a thread
/// race — so once a scope filled past the cap, *which* fragment survived (and
/// therefore which reassembly joins, and which standalone findings they
/// cannibalize) varied run-to-run on identical input. Evicting the fragment
/// with the smallest `(line, value)` key is content/position-derived, hence
/// independent of arrival order; in a SEQUENTIAL scan fragments arrive in
/// increasing file position, so this is identical to the old `remove(0)`
/// ("drop oldest") behaviour — it only removes the nondeterminism (Law 7).
fn evict_one(cluster: &mut Vec<SecretFragment>) {
    if let Some(idx) = cluster
        .iter()
        .enumerate()
        .min_by_key(|(_, fragment)| fragment_eviction_key(fragment))
        .map(|(i, _)| i)
    {
        cluster.remove(idx);
    }
}

fn fragment_eviction_key(fragment: &SecretFragment) -> (usize, &[u8]) {
    (fragment.line, fragment.value.as_bytes())
}

/// Global cache for tracking fragmented secrets across the entire scan run.
pub(crate) struct FragmentCache {
    /// Maps normalized prefix (e.g. "aws_key") to a list of found fragments.
    /// Sharded to avoid a single global mutex becoming a bottleneck under rayon.
    shards: [Mutex<LruCache<String, Vec<SecretFragment>>>; SHARD_COUNT],
}

impl FragmentCache {
    pub(crate) fn new(capacity: usize) -> Self {
        let per_shard = (capacity / SHARD_COUNT).max(1);
        let nz = NonZeroUsize::new(per_shard).unwrap_or(NonZeroUsize::MIN); // LAW10: zero => NonZeroUsize::MIN floor; shard/size knob, perf-only
        Self {
            shards: std::array::from_fn(|_| Mutex::new(LruCache::new(nz))),
        }
    }

    /// Shared core of both reassembly entry points: record `fragment` into its
    /// `(prefix, scope)` cluster (dedup + deterministic eviction), then emit
    /// `make(f1, f2)` for every ORDERED near pair — same path and
    /// `abs_diff(line) < 100`. `record_and_reassemble` and its stamped variant
    /// differ ONLY in the per-pair output type and the final canonical sort, so
    /// this record/cluster/near-gate logic lives here in ONE owner (was two
    /// near-identical nested-loop copies — DEDUP).
    ///
    /// Reassembly is SAME-FILE only, within a 100-line window. Cross-file /
    /// distant joins were observed to cannibalize standalone findings: a
    /// cross-file `:reassembled` candidate replaces the legitimate singleton
    /// during downstream resolution and mis-attributes it to a sibling-file path
    /// (investigator evidence: mirror-pos-0000091.yaml AKIA glued to a sibling
    /// klaviyo `sk_`). The same-path + `abs_diff<100` gate preserves the
    /// file-boundary split case (chunked 1MB+ files) without manufacturing
    /// cross-file glue.
    fn record_and_collect<T>(
        &self,
        fragment: SecretFragment,
        make: impl Fn(&SecretFragment, &SecretFragment) -> T,
    ) -> Vec<T> {
        let scope = fragment.path.as_deref().unwrap_or(""); // LAW10: absent path/field => display placeholder; reporting-only, recall-safe
                                                            // Shard index is derived from the (prefix, scope) bytes directly via
                                                            // `shard_index_of`, so the joined key `String` no longer has to be
                                                            // materialized purely to pick a shard. The owned key is built once,
                                                            // only where `LruCache::get_or_insert_mut` actually needs to take
                                                            // ownership of it.
        let shard_idx = shard_index_of(&fragment.prefix, scope);
        let mut lock = self.shards[shard_idx].lock();

        let cluster = with_scoped_key(&fragment.prefix, scope, |key| {
            lock.get_or_insert_mut_ref(key, Vec::new)
        });

        // Don't add duplicate fragments (same path/line/value)
        if !cluster.iter().any(|f| {
            f.path == fragment.path && f.line == fragment.line && **f.value == **fragment.value
        }) {
            cluster.push(fragment);
            if cluster.len() > MAX_FRAGMENTS_PER_SCOPE {
                // Deterministic eviction (see `evict_one`). The Zeroizing<String>
                // drop impl scrubs the dropped fragment's bytes.
                evict_one(cluster);
            }
        }

        let mut candidates = Vec::new();
        if cluster.len() >= 2 {
            for i in 0..cluster.len() {
                for j in 0..cluster.len() {
                    if i == j {
                        continue;
                    }
                    let f1 = &cluster[i];
                    let f2 = &cluster[j];

                    // `abs_diff` on usize: the absolute line distance directly,
                    // no signed cast (which could overflow / panic in `abs()` on
                    // `isize::MIN` for pathological line numbers).
                    if f1.path == f2.path && f1.line.abs_diff(f2.line) < 100 {
                        candidates.push(make(f1, f2));
                    }
                }
            }
        }
        candidates
    }

    /// Record a fragment and return a list of "complete" candidates if any.
    /// The returned `Zeroizing<String>` lets the caller scope the
    /// reassembled credential's lifetime tightly - drop it (or pass it
    /// to a scan that consumes by reference) and the heap copy is zeroed.
    pub(crate) fn record_and_reassemble(&self, fragment: SecretFragment) -> Vec<Zeroizing<String>> {
        let mut candidates = self.record_and_collect(fragment, |f1, f2| {
            let mut joined = Zeroizing::new(String::with_capacity(f1.value.len() + f2.value.len()));
            joined.push_str(f1.value.as_str());
            joined.push_str(f2.value.as_str());
            joined
        });
        // Determinism: the pair enumeration above emits the same *set* of joins
        // in a run-to-run-varying order under a parallel (rayon) scan (the
        // `cluster` Vec is in race-dependent arrival order), and that order then
        // leaks downstream. Canonicalize on the glued bytes - content-derived, so
        // it is independent of arrival order. Join semantics are untouched.
        candidates.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        candidates
    }

    /// Path/line-stamped variant of [`record_and_reassemble`]. Returns
    /// each glued candidate together with the provenance of its anchor
    /// (prefix) fragment so the caller can attribute a reassembled
    /// finding to the file that actually contributed the credential,
    /// rather than to whatever chunk's metadata was in scope when the
    /// join fired. The join semantics (same-path, within-100-line
    /// window) are identical to `record_and_reassemble`; this just
    /// preserves the anchor's `path`/`line` on the way out.
    #[cfg(any(feature = "simd", test))]
    pub(crate) fn record_and_reassemble_stamped(
        &self,
        fragment: SecretFragment,
    ) -> Vec<ReassembledCandidate> {
        let mut candidates = self.record_and_collect(fragment, |f1, f2| {
            let mut joined = Zeroizing::new(String::with_capacity(f1.value.len() + f2.value.len()));
            joined.push_str(f1.value.as_str());
            joined.push_str(f2.value.as_str());
            // f1 is the prefix fragment - the anchor we stamp the finding with.
            // Cross-file pairs are impossible here (same key + f1.path==f2.path).
            ReassembledCandidate {
                value: joined,
                path: f1.path.clone(),
                line: f1.line,
            }
        });
        // Determinism (see `record_and_reassemble`): `cluster` is in
        // race-dependent arrival order under a parallel scan, so the anchor
        // (`line`) stamped onto each glue - and the emission order - varied run
        // to run for identical input. A symmetric pair yields two distinct
        // candidates (`A+B` anchored at A's line, `B+A` at B's line), so the sort
        // key must be the full (glued bytes, anchor line) tuple, not the bytes
        // alone. Within one full-path key every fragment shares a `path`, so
        // `path` need not enter the key.
        candidates.sort_unstable_by(|a, b| {
            a.value
                .as_bytes()
                .cmp(b.value.as_bytes())
                .then_with(|| a.line.cmp(&b.line))
        });
        candidates
    }

    pub(crate) fn clear(&self) {
        for shard in &self.shards {
            shard.lock().clear();
        }
    }
}

thread_local! {
    static SCOPED_KEY_SCRATCH: RefCell<String> = const { RefCell::new(String::new()) };
}

/// Scope clusters by the FULL file path, not the parent directory.
/// Coalesced scan batches several files under one rayon map and the per-chunk
/// `chunk.metadata.path` is the only provenance the fragment carries; pooling
/// by parent_dir let every AKIA assignment in dir X share a cluster with every
/// sibling assignment in dir X. Keying on the full path means fragments from
/// different files never pool in the first place; same-file chunk-seam splits
/// still land in one cluster and reassemble.
///
/// The LRU stores owned `String` keys, but `lru::LruCache::get_or_insert_mut_ref`
/// can query with `&str` and only `to_owned()` on a miss. A thread-local scratch
/// buffer gives the hot hit path a borrowed `prefix\0scope` key without
/// allocating a new joined `String` per fragment.
fn with_scoped_key<R>(prefix: &str, scope: &str, f: impl FnOnce(&str) -> R) -> R {
    SCOPED_KEY_SCRATCH.with(|scratch| {
        let mut key = scratch.borrow_mut();
        key.clear();
        key.reserve(prefix.len() + 1 + scope.len());
        key.push_str(prefix);
        key.push('\0');
        key.push_str(scope);
        f(key.as_str())
    })
}

/// Fold one more byte into the running shard hash. Single home for the
/// hash recurrence so the joined-key and slice-pair paths can never drift.
#[inline]
fn shard_fold(h: usize, b: u8) -> usize {
    h.wrapping_mul(31).wrapping_add(b as usize)
}

/// Shard index for a fragment without materializing the joined `prefix\0scope`
/// key as a `String`. Folds `prefix`, the `\0` separator, then `scope` in the
/// exact byte order `scoped_key` produces, so a fragment maps to the same shard
/// whether it is sharded from slices (the hot record path) or from the joined
/// key. Keeps the per-record heap allocation off the warm path.
fn shard_index_of(prefix: &str, scope: &str) -> usize {
    let mut h = 0usize;
    for &b in prefix.as_bytes() {
        h = shard_fold(h, b);
    }
    h = shard_fold(h, 0);
    for &b in scope.as_bytes() {
        h = shard_fold(h, b);
    }
    h % SHARD_COUNT
}

/// Test-only probe for the shard-hash drift invariant: returns
/// `(slice_pair_shard, joined_key_shard)` for `(prefix, scope)`. The hot
/// record path shards from slices via [`shard_index_of`] (no allocation); the
/// joined-key path folds the materialized `prefix\0scope` string. If these two
/// ever diverge, a fragment recorded under one shard would never be found under
/// the other, silently breaking reassembly. Exposed (doc-hidden) so the
/// equivalence test can live in `tests/unit/inline_migrated/` without leaking
/// the private `shard_fold` / `SHARD_COUNT` internals.
#[doc(hidden)]
pub(crate) fn shard_index_drift_probe(prefix: &str, scope: &str) -> (usize, usize) {
    with_scoped_key(prefix, scope, |joined| {
        let joined_key_shard = joined.bytes().fold(0usize, shard_fold) % SHARD_COUNT;
        (shard_index_of(prefix, scope), joined_key_shard)
    })
}
