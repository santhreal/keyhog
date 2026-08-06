//! Migrated from src/fragment_cache.rs, cross-file/window
//! reassembly gates and the shard-hash drift invariant (KH-GAP-004).

use keyhog_scanner::testing::fragment_cache::{
    shard_index_drift_probe, FragmentCache, SecretFragment,
};
use std::sync::Arc;
use zeroize::Zeroizing;

fn frag(prefix: &str, var: &str, value: &str, line: usize, path: &str) -> SecretFragment {
    SecretFragment {
        prefix: prefix.to_string(),
        var_name: var.to_string(),
        value: Zeroizing::new(value.to_string()),
        line,
        path: Some(Arc::from(path)),
    }
}

/// Positive truth case: two fragments in the SAME file within 100 lines must
/// reassemble to a glued candidate. This is the legitimate file-boundary-split
/// path used when a credential spans a chunk seam.
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

/// Adversarial negative twin: two fragments in DIFFERENT files under the same
/// directory scope MUST NOT reassemble. This is the regression gate for the
/// cross-file cannibalization bug. Before the fix, this case produced a glued
/// AKIA||BBBB candidate.
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

/// Same-file fragments separated by more than the 100-line window are not
/// reassembled. This case proves the window gate is still load-bearing after
/// the cross-file restriction.
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

/// The slice-pair shard hash (hot record path, no joined-key allocation) must
/// land a fragment on the SAME shard as the joined-key hash. If these drift, a
/// fragment could be recorded into one shard and never found again in another,
/// silently breaking reassembly. Drives the equivalence over empty/short/long,
/// separator-containing, and unicode inputs.
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
        let (slice_pair, joined_key) = shard_index_drift_probe(prefix, scope);
        assert_eq!(
            slice_pair, joined_key,
            "shard hash drift for prefix={prefix:?} scope={scope:?}"
        );
    }
}
/// WHY: one tiny workload must not preallocate every shard for the maximum
/// daemon/watch history, and clearing a completed workload must release growth.
#[test]
fn capacity_tracks_live_workload_and_resets_after_clear() {
    let cache = FragmentCache::new(512);
    assert_eq!(cache.storage_for_test(), (0, 64, 512));

    let prefix = "workload";
    let target_shard = shard_index_drift_probe(prefix, "/repo/seed.env").0;
    let mut paths = Vec::new();
    for index in 0..10_000 {
        let path = format!("/repo/candidate-{index}.env");
        if shard_index_drift_probe(prefix, &path).0 == target_shard {
            paths.push(path);
            if paths.len() == 4 {
                break;
            }
        }
    }
    assert_eq!(paths.len(), 4, "test must find four colliding shard keys");

    for (line, path) in paths.iter().enumerate() {
        let candidates =
            cache.record_and_reassemble(frag(prefix, "WORKLOAD_PART", "abcd", line, path));
        assert!(candidates.is_empty());
    }
    assert_eq!(
        cache.storage_for_test(),
        (4, 67, 512),
        "only the touched shard should grow from one to four rows"
    );

    cache.clear();
    assert_eq!(
        cache.storage_for_test(),
        (0, 64, 512),
        "completed workload state and shard capacity must be released"
    );
}
