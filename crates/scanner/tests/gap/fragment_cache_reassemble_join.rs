//! Gap test: cross-chunk fragment reassembly output is exact and deterministic.
//!
//! The reassembly loop glues each near same-path fragment pair via a
//! `Zeroizing<String>`. That string is now built with
//! `String::with_capacity(f1.len + f2.len)` instead of growing from empty —
//! a Law-7 single-allocation fix that also avoids an intermediate realloc
//! leaving an un-zeroed plaintext copy of the first fragment on the heap. The
//! glued content and sorted emission order must be byte-for-byte unchanged,
//! pinned here on exact values.

use keyhog_scanner::testing::fragment_reassemble_for_test;

#[test]
fn near_same_path_fragments_join_in_sorted_order() {
    // Two fragments, same prefix + same path, one line apart -> both ordered
    // joins are produced and emitted sorted by the glued bytes.
    let joins = fragment_reassemble_for_test(&[
        ("aws", "AKIA1111", 1, Some("a.env")),
        ("aws", "AKIA2222", 2, Some("a.env")),
    ]);
    assert_eq!(
        joins,
        vec![
            "AKIA1111AKIA2222".to_string(),
            "AKIA2222AKIA1111".to_string(),
        ],
        "near same-path fragments must glue both orderings, sorted by glued bytes"
    );
}

#[test]
fn fragments_beyond_the_100_line_window_do_not_join() {
    // Same prefix + path (so they share a cluster) but 200 lines apart: the
    // reassembly window is strictly < 100 lines, so nothing glues.
    let joins = fragment_reassemble_for_test(&[
        ("aws", "AKIA1111", 1, Some("a.env")),
        ("aws", "AKIA2222", 201, Some("a.env")),
    ]);
    assert_eq!(
        joins,
        Vec::<String>::new(),
        "fragments 200 lines apart exceed the < 100-line reassembly window"
    );
}
