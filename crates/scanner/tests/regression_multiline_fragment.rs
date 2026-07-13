//! Regression tests for the cross-chunk fragment cache / reassembly path.
//!
//! Source under test: `crates/scanner/src/fragment_cache.rs`
//!   * `FragmentCache::record_and_reassemble`      (same-file join, dedup)
//!   * `FragmentCache::record_and_reassemble_stamped` (anchor path/line, simd)
//!   * `FragmentCache::clear`
//!   * `evict_one` / `MAX_FRAGMENTS_PER_SCOPE = 8`  (cluster size bound)
//!   * `shard_index_of` / `shard_index_drift_probe` (no shard drift)
//!
//! Reachable via the public `keyhog_scanner::testing::fragment_cache::*` shim.
//! Every expected value is derived by tracing the real source, not guessed.
//! Distinct from `regression_multiline_join.rs` (which drives the multiline
//! preprocessor) (this file exercises the FragmentCache primitive directly).

use keyhog_scanner::testing::fragment_cache::{
    shard_index_drift_probe, FragmentCache, SecretFragment,
};
use std::sync::Arc;
use zeroize::Zeroizing;

// Source constants (fragment_cache.rs) mirrored here so the assertions pin
// exact expected values.
const MAX_FRAGMENTS_PER_SCOPE: usize = 8;
const SHARD_COUNT: usize = 64;

fn frag(prefix: &str, value: &str, line: usize, path: Option<&str>) -> SecretFragment {
    SecretFragment {
        prefix: prefix.to_string(),
        var_name: "VAR".to_string(),
        value: Zeroizing::new(value.to_string()),
        line,
        path: path.map(Arc::from),
    }
}

fn joins(cache: &FragmentCache, f: SecretFragment) -> Vec<String> {
    cache
        .record_and_reassemble(f)
        .iter()
        .map(|z| z.to_string())
        .collect()
}

// Independent reimplementation of the source shard recurrence (shard_fold:
// h = h*31 + b, wrapping). Used to pin the exact shard index and to prove the
// two internal shard paths (slice-pair vs joined-key) agree.
fn expected_shard(prefix: &str, scope: &str) -> usize {
    let mut h: usize = 0;
    for &b in prefix.as_bytes() {
        h = h.wrapping_mul(31).wrapping_add(b as usize);
    }
    h = h.wrapping_mul(31).wrapping_add(0);
    for &b in scope.as_bytes() {
        h = h.wrapping_mul(31).wrapping_add(b as usize);
    }
    h % SHARD_COUNT
}

// ---------------------------------------------------------------------------
// Reassembly: a secret split across fragments glues to exact bytes
// ---------------------------------------------------------------------------

#[test]
fn split_secret_reassembles_to_exact_bytes() {
    let cache = FragmentCache::new(1024);
    // First fragment alone yields nothing (cluster.len() < 2).
    assert_eq!(
        joins(&cache, frag("aws_key", "AKIA1234", 1, Some("a.env"))),
        Vec::<String>::new()
    );
    // Second same-file fragment within the 100-line window completes the join.
    // Ordered pairs (i,j) i!=j emit both orders; output is sorted by glued bytes.
    // 'A'(0x41) < 'S'(0x53) so the AKIA-first glue sorts first.
    let got = joins(&cache, frag("aws_key", "SECRET5678", 2, Some("a.env")));
    assert_eq!(
        got,
        vec![
            "AKIA1234SECRET5678".to_string(),
            "SECRET5678AKIA1234".to_string(),
        ]
    );
}

#[test]
fn single_fragment_is_untouched() {
    let cache = FragmentCache::new(1024);
    // A lone fragment never reassembles: no partner in its scope.
    let got = joins(&cache, frag("aws_key", "AKIAONLYONE", 5, Some("solo.env")));
    assert_eq!(got.len(), 0);
    assert_eq!(got, Vec::<String>::new());
}

// ---------------------------------------------------------------------------
// Dedup: recording the same (path,line,value) twice does not grow the cluster
// ---------------------------------------------------------------------------

#[test]
fn duplicate_fragment_is_deduped() {
    let cache = FragmentCache::new(1024);
    let _ = joins(&cache, frag("aws_key", "aaa", 1, Some("d.env")));
    let after_two = joins(&cache, frag("aws_key", "bbb", 2, Some("d.env")));
    // Two distinct fragments -> exactly 2 ordered joins.
    assert_eq!(after_two, vec!["aaabbb".to_string(), "bbbaaa".to_string()]);

    // Re-record the FIRST fragment verbatim. Dedup keeps the cluster at size 2,
    // so the third call returns the same 2 joins (not 6 from a size-3 cluster).
    let after_dup = joins(&cache, frag("aws_key", "aaa", 1, Some("d.env")));
    assert_eq!(after_dup, vec!["aaabbb".to_string(), "bbbaaa".to_string()]);
    assert_eq!(after_dup.len(), 2);
}

// ---------------------------------------------------------------------------
// Cross-file / different-scope fragments never pool
// ---------------------------------------------------------------------------

#[test]
fn different_paths_do_not_pool() {
    let cache = FragmentCache::new(1024);
    let _ = joins(&cache, frag("aws_key", "AKIA1111", 1, Some("fileA.env")));
    // Same prefix + same line but DIFFERENT path -> different cluster key.
    let got = joins(&cache, frag("aws_key", "AKIA2222", 1, Some("fileB.env")));
    assert_eq!(got.len(), 0);
}

#[test]
fn different_prefix_does_not_pool() {
    let cache = FragmentCache::new(1024);
    let _ = joins(&cache, frag("aws_key", "AKIA1111", 1, Some("same.env")));
    // Same path but DIFFERENT prefix -> different cluster key, no join.
    let got = joins(&cache, frag("gcp_key", "AIza2222", 2, Some("same.env")));
    assert_eq!(got.len(), 0);
}

// ---------------------------------------------------------------------------
// Line-window boundary: |line diff| < 100 joins, == 100 does not
// ---------------------------------------------------------------------------

#[test]
fn line_window_diff_99_reassembles() {
    let cache = FragmentCache::new(1024);
    let _ = joins(&cache, frag("aws_key", "PART_A", 1, Some("w.env")));
    // lines 1 and 100 -> diff 99 < 100 -> near -> two ordered joins.
    let got = joins(&cache, frag("aws_key", "PART_B", 100, Some("w.env")));
    assert_eq!(
        got,
        vec!["PART_APART_B".to_string(), "PART_BPART_A".to_string()]
    );
}

#[test]
fn line_window_diff_100_does_not_reassemble() {
    let cache = FragmentCache::new(1024);
    let _ = joins(&cache, frag("aws_key", "PART_A", 1, Some("w.env")));
    // lines 1 and 101 -> diff 100 is NOT < 100 -> not near -> no join, even
    // though both share the same cluster (2 fragments present).
    let got = joins(&cache, frag("aws_key", "PART_B", 101, Some("w.env")));
    assert_eq!(got.len(), 0);
}

// ---------------------------------------------------------------------------
// Determinism: joins are sorted by glued bytes, independent of arrival
// ---------------------------------------------------------------------------

#[test]
fn three_way_joins_are_byte_sorted() {
    let cache = FragmentCache::new(1024);
    let _ = joins(&cache, frag("aws_key", "a", 1, Some("t.env")));
    let _ = joins(&cache, frag("aws_key", "b", 2, Some("t.env")));
    let got = joins(&cache, frag("aws_key", "c", 3, Some("t.env")));
    // cluster {a,b,c}, all pairwise near -> 6 ordered joins, byte-sorted.
    assert_eq!(
        got,
        vec![
            "ab".to_string(),
            "ac".to_string(),
            "ba".to_string(),
            "bc".to_string(),
            "ca".to_string(),
            "cb".to_string(),
        ]
    );
    // Explicitly assert the output equals its own sorted copy (determinism).
    let mut sorted = got.clone();
    sorted.sort();
    assert_eq!(got, sorted);
}

// ---------------------------------------------------------------------------
// Cache size bound: a scope never holds more than MAX_FRAGMENTS_PER_SCOPE (8)
// ---------------------------------------------------------------------------

#[test]
fn cluster_size_is_bounded_at_eight() {
    let cache = FragmentCache::new(1024);
    // Record 8 near, same-path fragments; count of joins = k*(k-1).
    let mut last = Vec::new();
    for line in 1..=MAX_FRAGMENTS_PER_SCOPE {
        last = joins(
            &cache,
            frag("aws_key", &format!("v{line:02}"), line, Some("cap.env")),
        );
    }
    // 8 fragments, all pairwise near -> 8*7 = 56 ordered joins.
    assert_eq!(
        last.len(),
        MAX_FRAGMENTS_PER_SCOPE * (MAX_FRAGMENTS_PER_SCOPE - 1)
    );
    assert_eq!(last.len(), 56);

    // A 9th fragment pushes past the cap; evict_one drops the smallest
    // (line,value) key. Cluster stays at 8, so the count stays 56 (not 72).
    let after_nine = joins(&cache, frag("aws_key", "v09", 9, Some("cap.env")));
    assert_eq!(after_nine.len(), 56);
}

#[test]
fn eviction_drops_smallest_line_fragment() {
    let cache = FragmentCache::new(1024);
    // Fill to the cap with lines 1..=8, then overflow with line 9.
    for line in 1..=9 {
        let _ = joins(
            &cache,
            frag("aws_key", &format!("v{line:02}"), line, Some("evict.env")),
        );
    }
    let after = joins(
        &cache,
        // Re-record line 9 to read the current cluster's joins; dedup keeps
        // the cluster unchanged so this reflects the post-eviction state.
        frag("aws_key", "v09", 9, Some("evict.env")),
    );
    assert_eq!(after.len(), 56);
    // evict_one removes the min (line,value) = line 1 ("v01"). No surviving
    // join may contain the evicted value...
    assert!(
        after.iter().all(|c| !c.contains("v01")),
        "evicted line-1 value v01 leaked into joins: {after:?}"
    );
    // ...while the newest high-line fragment (v09) is retained and glued.
    assert!(
        after.iter().any(|c| c.contains("v09")),
        "retained newest value v09 missing from joins"
    );
}

// ---------------------------------------------------------------------------
// clear() empties every shard
// ---------------------------------------------------------------------------

#[test]
fn clear_empties_the_cache() {
    let cache = FragmentCache::new(1024);
    let _ = joins(&cache, frag("aws_key", "aaa", 1, Some("c.env")));
    let two = joins(&cache, frag("aws_key", "bbb", 2, Some("c.env")));
    assert_eq!(two.len(), 2);

    cache.clear();
    // After clear the cluster is empty; re-recording "aaa" leaves it size 1,
    // so no partner exists and no join is produced.
    let after_clear = joins(&cache, frag("aws_key", "aaa", 1, Some("c.env")));
    assert_eq!(after_clear.len(), 0);
}

// ---------------------------------------------------------------------------
// None-path fragments pool under the empty ("") scope
// ---------------------------------------------------------------------------

#[test]
fn none_path_fragments_pool_under_empty_scope() {
    let cache = FragmentCache::new(1024);
    let _ = joins(&cache, frag("aws_key", "NOP1", 1, None));
    // Both fragments have path None -> both scope to "" -> same cluster, near.
    let got = joins(&cache, frag("aws_key", "NOP2", 2, None));
    assert_eq!(got, vec!["NOP1NOP2".to_string(), "NOP2NOP1".to_string()]);
}

// ---------------------------------------------------------------------------
// Shard drift invariant: slice-pair shard == joined-key shard == expected
// ---------------------------------------------------------------------------

#[test]
fn shard_index_has_no_drift() {
    for (prefix, scope) in [
        ("aws_key", "file.env"),
        ("", ""),
        ("a", "b"),
        ("gcp_key", "deep/dir/secrets.yaml"),
    ] {
        let (slice_shard, joined_shard) = shard_index_drift_probe(prefix, scope);
        // The hot slice path and the joined-key path must agree, else a
        // fragment recorded under one shard is unfindable under the other.
        assert_eq!(
            slice_shard, joined_shard,
            "shard drift for ({prefix:?},{scope:?})"
        );
        // ...and both must equal the independently recomputed shard index.
        assert_eq!(slice_shard, expected_shard(prefix, scope));
        assert!(slice_shard < SHARD_COUNT);
    }
}

#[test]
fn shard_index_pins_known_value() {
    // prefix "a", scope "": h = ((0*31 + 97)*31 + 0) = 3007; 3007 % 64 = 63.
    let (slice_shard, joined_shard) = shard_index_drift_probe("a", "");
    assert_eq!(slice_shard, 63);
    assert_eq!(joined_shard, 63);
}

// ---------------------------------------------------------------------------
// Stamped reassembly: anchor is the PREFIX (f1) fragment's path/line
// ---------------------------------------------------------------------------

#[cfg(feature = "simd")]
#[test]
fn stamped_candidate_anchors_on_prefix_fragment() {
    let cache = FragmentCache::new(1024);
    let _ = cache.record_and_reassemble_stamped(frag("aws_key", "AA", 5, Some("s.env")));
    let out = cache.record_and_reassemble_stamped(frag("aws_key", "BB", 7, Some("s.env")));
    // Two candidates, sorted by (glued bytes, anchor line):
    //   "AABB" anchored at f1=A -> line 5
    //   "BBAA" anchored at f1=B -> line 7
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].value.as_str(), "AABB");
    assert_eq!(out[0].line, 5);
    assert_eq!(out[0].path.as_deref(), Some("s.env"));
    assert_eq!(out[1].value.as_str(), "BBAA");
    assert_eq!(out[1].line, 7);
    assert_eq!(out[1].path.as_deref(), Some("s.env"));
}
