//! Variable-fragment prefix normalization is case-insensitive without losing reassembly.

use keyhog_scanner::testing::fragment_cache::FragmentCache;
use keyhog_scanner::testing::multiline::collect_structural_fragments_for_test;

#[test]
fn case_mixed_part_suffixes_reassemble_same_fragment_prefix() {
    let cache = FragmentCache::new(64);
    let lines = [
        "let aws_key_PART1 = \"AKIA\";",
        "let aws-key-part2 = \"QYLPMN5HFIQR7XYA\";",
    ];
    let (joined, _) = collect_structural_fragments_for_test(&lines, &[0, 29], 0, &cache);
    assert!(
        joined.iter().any(|candidate| candidate == "AKIAQYLPMN5HFIQR7XYA"),
        "case-mixed PART suffixes and separators must normalize to the same fragment prefix; got: {:?}",
        joined
    );
}
