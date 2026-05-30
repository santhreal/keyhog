//! Cross-chunk fragment cache for virtual secret reassembly.
//!
//! This allows KeyHog to detect secrets split across different files or
//! distant locations within a large file that exceed the chunk window.

use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::path::Path;
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
        let key = scoped_key(&fragment);
        let shard_idx = shard_index(&key);
        let mut lock = self.shards[shard_idx].lock();

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

    pub fn clear(&self) {
        for shard in &self.shards {
            shard.lock().clear();
        }
    }
}

fn scoped_key(fragment: &SecretFragment) -> String {
    let scope = fragment
        .path
        .as_deref()
        .and_then(|path| Path::new(path).parent())
        .and_then(Path::to_str)
        .unwrap_or("");
    format!("{}\0{}", fragment.prefix, scope)
}

fn shard_index(key: &str) -> usize {
    key.bytes()
        .fold(0usize, |h, b| h.wrapping_mul(31).wrapping_add(b as usize))
        % SHARD_COUNT
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
            "AKIA0000000000000000",
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
                .any(|g| g == "AKIA0000000000000000BBBBBBBBBBBBBBBBBBBB"),
            "expected forward AKIA||BBBB reassembly in {:?}",
            glued
        );
        assert!(
            glued
                .iter()
                .any(|g| g == "BBBBBBBBBBBBBBBBBBBBAKIA0000000000000000"),
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
            "AKIA0000000000000000",
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
            "AKIA0000000000000000",
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
}
