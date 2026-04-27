//! Cross-chunk fragment cache for virtual secret reassembly.
//!
//! This allows KeyHog to detect secrets split across different files or
//! distant locations within a large file that exceed the chunk window.

use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::path::Path;
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
/// — `Zeroizing<String>` prints redacted in `{:?}`.
#[derive(Clone)]
pub struct SecretFragment {
    pub prefix: String,
    pub var_name: String,
    pub value: Zeroizing<String>,
    pub line: usize,
    pub path: Option<String>,
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
    /// reassembled credential's lifetime tightly — drop it (or pass it
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

        // If we have multiple fragments for this prefix, try to reassemble
        if cluster.len() >= 2 {
            // Sort fragments by variable name suffix or order found
            // This is a heuristic - real reassembly might require more logic
            let mut ordered = cluster.clone();
            ordered.sort_by(|left, right| {
                left.var_name
                    .cmp(&right.var_name)
                    .then(left.path.cmp(&right.path))
                    .then(left.line.cmp(&right.line))
            });
            // Zeroizing-aware concat: build into a Zeroizing<String> so the
            // intermediate join buffer also gets scrubbed.
            let mut joined = Zeroizing::new(String::new());
            for f in &ordered {
                joined.push_str(f.value.as_str());
            }
            vec![joined]
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
