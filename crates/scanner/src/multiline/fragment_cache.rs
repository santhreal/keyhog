//! Cross-chunk fragment cache for virtual secret reassembly.
//!
//! This allows KeyHog to detect secrets split across different files or
//! distant locations within a large file that exceed the chunk window.

use lru::LruCache;
use parking_lot::Mutex;
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
/// that re-embedded the secret in a `format!`-built dummy line. The
/// `Debug` derive is also intentionally NOT wired through `value`
/// - `Zeroizing<String>` prints redacted in `{:?}`.
#[derive(Clone)]
pub struct SecretFragment {
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
pub struct ReassembledCandidate {
    /// Glued credential text. Zeroized on drop.
    pub value: Zeroizing<String>,
    /// Path of the anchoring (prefix) fragment, if known.
    pub path: Option<Arc<str>>,
    /// Source line of the anchoring (prefix) fragment.
    pub line: usize,
}

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

/// Global cache for tracking fragmented secrets across the entire scan run.
pub struct FragmentCache {
    /// Maps normalized prefix (e.g. "aws_key") to a list of found fragments.
    /// Sharded to avoid a single global mutex becoming a bottleneck under rayon.
    shards: [Mutex<LruCache<String, Vec<SecretFragment>>>; SHARD_COUNT],
}

impl FragmentCache {
    pub fn new(capacity: usize) -> Self {
        let per_shard = (capacity / SHARD_COUNT).max(1);
        let nz = NonZeroUsize::new(per_shard).unwrap_or(NonZeroUsize::MIN);
        Self {
            shards: std::array::from_fn(|_| Mutex::new(LruCache::new(nz))),
        }
    }

    /// Record a fragment and return a list of "complete" candidates if any.
    /// The returned `Zeroizing<String>` lets the caller scope the
    /// reassembled credential's lifetime tightly - drop it (or pass it
    /// to a scan that consumes by reference) and the heap copy is zeroed.
    pub fn record_and_reassemble(&self, fragment: SecretFragment) -> Vec<Zeroizing<String>> {
        let scope = fragment.path.as_deref().unwrap_or("");
        // Shard index is derived from the (prefix, scope) bytes directly via
        // `shard_index_of`, so the joined key `String` no longer has to be
        // materialized purely to pick a shard. The owned key is built once,
        // only where `LruCache::get_or_insert_mut` actually needs to take
        // ownership of it.
        let shard_idx = shard_index_of(&fragment.prefix, scope);
        let mut lock = self.shards[shard_idx].lock();

        let key = scoped_key(&fragment);
        let cluster = lock.get_or_insert_mut(key, Vec::new);

        // Don't add duplicate fragments (same path/line/value)
        if !cluster.iter().any(|f| {
            f.path == fragment.path && f.line == fragment.line && **f.value == **fragment.value
        }) {
            cluster.push(fragment);
            if cluster.len() > MAX_FRAGMENTS_PER_SCOPE {
                // LRU-style: drop the oldest. The Zeroizing<String> drop
                // impl scrubs the bytes before the allocator gets them.
                cluster.remove(0);
            }
        }

        // Reassembly is SAME-FILE only. Cross-file joins (every AKIA/AIza
        // assignment in dir X paired with every other matching assignment
        // in dir X siblings) were observed to cannibalize the standalone
        // findings: the cross-file `:reassembled` candidate replaces the
        // legitimate singleton during downstream resolution, and the
        // synthesized credential gets attributed to a sibling-file path.
        // Investigator evidence (mirror-pos-0000091.yaml AKIA glued to a
        // sibling klaviyo sk_) confirmed the singleton was lost.
        //
        // Real split-credential patterns (AWS_ACCESS_KEY in one .env paired
        // with AWS_SECRET in another) are NOT in the corpus and the loss
        // they cause is concrete: the standalone finding is dropped.
        // Restrict reassembly to same-path fragments within 100 lines of
        // each other; preserves the file-boundary split case (chunked
        // 1MB+ files) without manufacturing cross-file glue.
        if cluster.len() >= 2 {
            let mut candidates = Vec::new();
            for i in 0..cluster.len() {
                for j in 0..cluster.len() {
                    if i == j {
                        continue;
                    }
                    let f1 = &cluster[i];
                    let f2 = &cluster[j];

                    let near =
                        f1.path == f2.path && (f1.line as isize - f2.line as isize).abs() < 100;

                    if near {
                        let mut joined = Zeroizing::new(String::new());
                        joined.push_str(f1.value.as_str());
                        joined.push_str(f2.value.as_str());
                        candidates.push(joined);
                    }
                }
            }
            // Determinism: the `cluster` Vec is ordered by fragment
            // *arrival*, and under a parallel (rayon) scan the order in
            // which sibling chunks win the per-shard mutex is a thread
            // race - so the (i, j) pair enumeration above emits the same
            // *set* of joins in a run-to-run-varying order. That order
            // then leaks downstream (synthesized match order, and via the
            // stamped variant the anchor line attached to each glue), so
            // identical input produced non-deterministic scan output.
            // Canonicalize on the glued bytes - content-derived, so it is
            // independent of arrival order - before returning. Join
            // semantics (which pairs are produced) are untouched.
            candidates.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            candidates
        } else {
            Vec::new()
        }
    }

    /// Path/line-stamped variant of [`record_and_reassemble`]. Returns
    /// each glued candidate together with the provenance of its anchor
    /// (prefix) fragment so the caller can attribute a reassembled
    /// finding to the file that actually contributed the credential,
    /// rather than to whatever chunk's metadata was in scope when the
    /// join fired. The join semantics (same-path, within-100-line
    /// window) are identical to `record_and_reassemble`; this just
    /// preserves the anchor's `path`/`line` on the way out.
    pub fn record_and_reassemble_stamped(
        &self,
        fragment: SecretFragment,
    ) -> Vec<ReassembledCandidate> {
        let scope = fragment.path.as_deref().unwrap_or("");
        // Same as `record_and_reassemble`: shard from the (prefix, scope)
        // bytes, allocate the owned key only at the insert point.
        let shard_idx = shard_index_of(&fragment.prefix, scope);
        let mut lock = self.shards[shard_idx].lock();

        let key = scoped_key(&fragment);
        let cluster = lock.get_or_insert_mut(key, Vec::new);

        if !cluster.iter().any(|f| {
            f.path == fragment.path && f.line == fragment.line && **f.value == **fragment.value
        }) {
            cluster.push(fragment);
            if cluster.len() > MAX_FRAGMENTS_PER_SCOPE {
                cluster.remove(0);
            }
        }

        if cluster.len() >= 2 {
            let mut candidates = Vec::new();
            for i in 0..cluster.len() {
                for j in 0..cluster.len() {
                    if i == j {
                        continue;
                    }
                    let f1 = &cluster[i];
                    let f2 = &cluster[j];

                    let near =
                        f1.path == f2.path && (f1.line as isize - f2.line as isize).abs() < 100;

                    if near {
                        let mut joined = Zeroizing::new(String::new());
                        joined.push_str(f1.value.as_str());
                        joined.push_str(f2.value.as_str());
                        candidates.push(ReassembledCandidate {
                            value: joined,
                            // f1 is the prefix fragment - the anchor we
                            // stamp the finding with. Cross-file pairs
                            // are already impossible here (same key +
                            // f1.path == f2.path), so f1.path == f2.path
                            // by construction.
                            path: f1.path.clone(),
                            line: f1.line,
                        });
                    }
                }
            }
            // Determinism (see `record_and_reassemble`): `cluster` is in
            // race-dependent arrival order under a parallel scan, so the
            // anchor (`line`) stamped onto each glue - and the emission
            // order - varied run to run for identical input. A symmetric
            // pair yields two distinct candidates (`A+B` anchored at A's
            // line, `B+A` at B's line), so the sort key must be the full
            // (glued bytes, anchor line) tuple, not the bytes alone, to
            // give a total content-derived order. Within one full-path
            // key every fragment shares a `path`, so `path` need not enter
            // the key.
            candidates.sort_unstable_by(|a, b| {
                a.value
                    .as_bytes()
                    .cmp(b.value.as_bytes())
                    .then_with(|| a.line.cmp(&b.line))
            });
            candidates
        } else {
            Vec::new()
        }
    }

    pub fn clear(&self) {
        for shard in &self.shards {
            shard.lock().clear();
        }
    }
}

fn scoped_key(fragment: &SecretFragment) -> String {
    // Scope clusters by the FULL file path, not the parent directory.
    // Coalesced scan batches several files under one rayon map and the
    // per-chunk `chunk.metadata.path` is the only provenance the
    // fragment carries; pooling by parent_dir let every AKIA assignment
    // in dir X share a cluster with every sibling assignment in dir X.
    // The `f1.path == f2.path` near-guard in `record_and_reassemble`
    // was then the SOLE defense against cross-file glue - and it leaked
    // whenever two fragments were recorded under one shared chunk path.
    // Keying on the full path means fragments from different files never
    // pool in the first place; same-file chunk-seam splits (a 1 MB+ file
    // chunked into windows that all carry the identical path) still land
    // in one cluster and reassemble. The near-guard stays as a redundant
    // safety net.
    let scope = fragment.path.as_deref().unwrap_or("");
    format!("{}\0{}", fragment.prefix, scope)
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
pub fn shard_index_drift_probe(prefix: &str, scope: &str) -> (usize, usize) {
    let joined = format!("{prefix}\0{scope}");
    let joined_key_shard = joined.bytes().fold(0usize, shard_fold) % SHARD_COUNT;
    (shard_index_of(prefix, scope), joined_key_shard)
}
