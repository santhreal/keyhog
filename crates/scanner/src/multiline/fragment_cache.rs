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

                    let near = f1.path == f2.path
                        && (f1.line as isize - f2.line as isize).abs() < 100;

                    if near {
                        let mut joined = Zeroizing::new(String::new());
                        joined.push_str(f1.value.as_str());
                        joined.push_str(f2.value.as_str());
                        candidates.push(joined);
                    }
                }
            }
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

                    let near = f1.path == f2.path
                        && (f1.line as isize - f2.line as isize).abs() < 100;

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

fn shard_index(key: &str) -> usize {
    key.bytes().fold(0usize, shard_fold) % SHARD_COUNT
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

#[cfg(test)]
mod tests {
    use super::*;

    fn frag(prefix: &str, var: &str, value: &str, line: usize, path: &str) -> SecretFragment {
        SecretFragment {
            prefix: prefix.to_string(),
            var_name: var.to_string(),
            value: Zeroizing::new(value.to_string()),
            line,
            path: Some(Arc::from(path)),
        }
    }

    /// Positive truth case: two fragments in the SAME file within 100
    /// lines must reassemble to a glued candidate. This is the legitimate
    /// file-boundary-split path used when a credential spans a chunk seam.
    #[test]
    fn same_file_fragments_within_window_reassemble() {
        let cache = FragmentCache::new(64);
        let dir = "/repo/.env.d";
        // First call seeds the cluster, no candidates yet.
        let first = cache.record_and_reassemble(frag(
            "awskey",
            "AWS_ACCESS_KEY_PART1",
            "AKIA0000000000000000", // keyhog:ignore detector=aws-access-key (synthetic test fixture)
            10,
            &format!("{dir}/keys.env"),
        ));
        assert!(
            first.is_empty(),
            "single-fragment scope must not yield candidates, got {} candidates",
            first.len()
        );

        // Second fragment in the SAME file, within 100 lines.
        let joined = cache.record_and_reassemble(frag(
            "awskey",
            "AWS_ACCESS_KEY_PART2",
            "BBBBBBBBBBBBBBBBBBBB",
            20,
            &format!("{dir}/keys.env"),
        ));
        // 2 fragments * (n-1) pairs = 2 ordered pairs yielded.
        let glued: Vec<String> = joined.iter().map(|z| z.to_string()).collect();
        assert!(
            glued
                .iter()
                .any(|g| g == "AKIA0000000000000000BBBBBBBBBBBBBBBBBBBB"), // keyhog:ignore detector=aws-access-key (synthetic test fixture)
            "expected forward AKIA||BBBB reassembly in {:?}",
            glued
        );
        assert!(
            glued
                .iter()
                .any(|g| g == "BBBBBBBBBBBBBBBBBBBBAKIA0000000000000000"), // keyhog:ignore detector=aws-access-key (synthetic test fixture)
            "expected reverse BBBB||AKIA reassembly in {:?}",
            glued
        );
        assert_eq!(
            glued.len(),
            2,
            "exactly two ordered pairs expected, got {}: {:?}",
            glued.len(),
            glued
        );
    }

    /// Adversarial negative twin: two fragments in DIFFERENT files under
    /// the same directory scope MUST NOT reassemble. This is the regression
    /// gate for the cross-file cannibalization bug. Before the fix, this
    /// case produced a glued AKIA||BBBB candidate.
    #[test]
    fn cross_file_fragments_do_not_reassemble() {
        let cache = FragmentCache::new(64);
        let dir = "/repo/.env.d";
        let _ = cache.record_and_reassemble(frag(
            "awskey",
            "AWS_ACCESS_KEY",
            "AKIA0000000000000000", // keyhog:ignore detector=aws-access-key (synthetic test fixture)
            6,
            &format!("{dir}/file_a.yaml"),
        ));
        let cross = cache.record_and_reassemble(frag(
            "awskey",
            "AWS_ACCESS_KEY",
            "BBBBBBBBBBBBBBBBBBBB",
            6,
            &format!("{dir}/file_b.sh"),
        ));
        assert!(
            cross.is_empty(),
            "cross-file reassembly must be suppressed, got {} candidates: {:?}",
            cross.len(),
            cross.iter().map(|z| z.to_string()).collect::<Vec<_>>()
        );
    }

    /// Same-file fragments separated by more than the 100-line window are
    /// not reassembled. This case proves the window gate is still
    /// load-bearing after the cross-file restriction.
    #[test]
    fn same_file_fragments_outside_window_do_not_reassemble() {
        let cache = FragmentCache::new(64);
        let path = "/repo/huge.env";
        let _ = cache.record_and_reassemble(frag(
            "awskey",
            "AWS_ACCESS_KEY_A",
            "AKIA0000000000000000", // keyhog:ignore detector=aws-access-key (synthetic test fixture)
            1,
            path,
        ));
        let far = cache.record_and_reassemble(frag(
            "awskey",
            "AWS_ACCESS_KEY_B",
            "BBBBBBBBBBBBBBBBBBBB",
            500,
            path,
        ));
        assert!(
            far.is_empty(),
            "out-of-window same-file reassembly must be suppressed, got {:?}",
            far.iter().map(|z| z.to_string()).collect::<Vec<_>>()
        );
    }

    /// The slice-pair shard hash (`shard_index_of`, hot record path, no
    /// joined-key allocation) must land a fragment on the SAME shard as the
    /// joined-key hash (`shard_index` over `scoped_key`). If these drift, a
    /// fragment could be recorded into one shard and never found again in
    /// another, silently breaking reassembly. Drives the equivalence over
    /// empty/short/long, separator-containing, and unicode inputs.
    #[test]
    fn shard_index_of_matches_joined_key_hash() {
        let cases = [
            ("", ""),
            ("awskey", ""),
            ("", "/repo/.env"),
            ("awskey", "/repo/.env.d/keys.env"),
            ("gh\0pat", "/a/b\0c/d"),
            ("prefix-with-emoji-\u{1f511}", "/path/\u{e9}t\u{e9}/clef"),
            ("a", "b"),
        ];
        for (prefix, scope) in cases {
            let joined = format!("{prefix}\0{scope}");
            assert_eq!(
                shard_index_of(prefix, scope),
                shard_index(&joined),
                "shard hash drift for prefix={prefix:?} scope={scope:?}"
            );
        }
    }
}
