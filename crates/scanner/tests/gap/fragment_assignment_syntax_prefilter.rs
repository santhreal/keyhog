//! Regression: the cross-chunk fragment prefilter needs BOTH an assignment
//! operator (`=`/`:`) AND a quote (`"`/`'`/`` ` ``), and now decides it in two
//! SIMD passes (`memchr2`/`memchr3`) instead of five `memchr` calls.
//!
//! `has_fragment_assignment_syntax` gates the whole `scan_cross_chunk_fragments`
//! pass per chunk, so its truth table is load-bearing: a false negative skips
//! fragment reassembly for that chunk (a recall loss), a false positive only
//! wastes the cheap line walk. The memchr2/memchr3 rewrite must be exactly the
//! OR-of-memchr boolean — this pins it.

use keyhog_scanner::testing::has_fragment_assignment_syntax_for_test as present;

#[test]
fn fragment_prefilter_requires_assignment_and_quote() {
    // assignment (= or :) AND quote (" ' `) -> true
    assert!(present(b"key = \"value\""), "= and \" present");
    assert!(present(b"token: 'abc'"), ": and ' present");
    assert!(present(b"k=`v`"), "= and backtick present");
    assert!(present(b"path: \"x\""), ": and \" present");

    // assignment but NO quote -> false
    assert!(!present(b"key = value"), "= but no quote");
    assert!(!present(b"a:b:c"), ": but no quote");

    // quote but NO assignment -> false
    assert!(!present(b"\"just quoted\""), "\" but no assignment");
    assert!(!present(b"'lonely'"), "' but no assignment");

    // neither -> false
    assert!(!present(b"plain text no markers"), "neither present");
    assert!(!present(b""), "empty input");
}
