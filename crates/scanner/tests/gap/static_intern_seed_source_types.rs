//! Gap test: the static interner's frozen source-type seed universe is exact.
//!
//! The module doc used to enumerate a stale 9-entry illustrative subset of the
//! seed `source_type` literals while the real `SEED_SOURCE_TYPES` constant holds
//! 17. The doc now references the constant as the single source of truth; this
//! test pins the constant's exact contents AND that every entry is pre-interned
//! (a `lookup` hit on an interner built from only the seed universe), so the two
//! cannot silently drift again.

use keyhog_scanner::testing::static_interner_seed_probe_for_test;

#[test]
fn seed_source_types_are_exact_and_all_pre_interned() {
    let (seeds, interned, unknown) = static_interner_seed_probe_for_test();

    assert_eq!(
        seeds,
        vec![
            "filesystem",
            "git",
            "git/head",
            "git/history",
            "git/tag",
            "git/unreachable",
            "git/diff",
            "git/staged",
            "git-diff",
            "git-history",
            "stdin",
            "s3",
            "docker",
            "web",
            "github",
            "slack",
            "binary",
        ],
        "SEED_SOURCE_TYPES is the exact frozen source-type universe"
    );
    assert_eq!(seeds.len(), 17, "17 seed source-types");
    assert!(
        interned.iter().all(|&b| b),
        "every seed source-type is pre-interned for allocation-free lookup"
    );
    assert!(!unknown, "a non-seed string must not be pre-interned");
}
