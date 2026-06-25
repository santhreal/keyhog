#![cfg(feature = "simd")]

// Regression: autoroute calibration aborted on high-core hosts when more
// distinct threads scanned one Hyperscan shard than the preallocated scratch
// pool seeded. The scan path must grow the pool and keep returning the exact
// complete match set, never a partial over-mark/degrade.

#[test]
fn oversubscribed_hyperscan_threads_all_get_the_complete_match_set() {
    let patterns = [
        (0usize, 0usize, "KHSCRATCH_[A-Z0-9]{8}", false),
        (1usize, 0usize, "ZZTOK_[a-z0-9]{6}", false),
    ];
    let probe = b"x KHSCRATCH_AB12CD34 y ZZTOK_xy99zz z";

    let ids = keyhog_scanner::testing::hyperscan_oversubscribed_match_ids_are_stable(
        &patterns, probe, 96, 6,
    )
    .expect("oversubscribed Hyperscan scans must stay complete and deterministic");

    assert_eq!(ids, vec![0, 1]);
}
