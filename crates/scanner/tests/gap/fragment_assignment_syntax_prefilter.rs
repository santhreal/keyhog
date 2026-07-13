//! Regression: the cross-chunk fragment prefilter needs BOTH an assignment
//! operator (`=`/`:`) AND a quote (`"`/`'`/`` ` ``), and now decides it in two
//! SIMD passes (`memchr2`/`memchr3`) instead of five `memchr` calls.
//!
//! `has_fragment_assignment_syntax` gates the whole `scan_cross_chunk_fragments`
//! pass per chunk, so its truth table is load-bearing: a false negative skips
//! fragment reassembly for that chunk (a recall loss), a false positive only
//! wastes the cheap line walk. The memchr2/memchr3 rewrite must be exactly the
//! OR-of-memchr boolean (this pins it).

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

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vector pins the truth table on 10 examples; this SWEEPS it as a
// DIFFERENTIAL: the memchr2/memchr3 SIMD implementation must EXACTLY equal the
// naive OR-of-`contains` boolean: `(has '=' or ':') AND (has '"' or '\'' or '`')`
// for every byte string. A divergence is a per-chunk recall bug (false negative
// skips fragment reassembly). Run over arbitrary bytes (edge/negative coverage)
// and a marker-rich alphabet (balanced true/false). No proptest before.

use proptest::prelude::*;

/// Marker bytes + a little noise, so both gates flip frequently.
const ALPHABET: &[u8] = &[b'a', b'x', b'=', b':', b'"', b'\'', b'`'];

fn naive_present(data: &[u8]) -> bool {
    let has_assign = data.iter().any(|&b| b == b'=' || b == b':');
    let has_quote = data.iter().any(|&b| matches!(b, b'"' | b'\'' | b'`'));
    has_assign && has_quote
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// Differential over arbitrary bytes (mostly the negative branches + no panic).
    #[test]
    fn present_matches_naive_oracle_arbitrary(data in prop::collection::vec(any::<u8>(), 0..64)) {
        prop_assert_eq!(present(&data), naive_present(&data));
    }

    /// The same differential over a marker-rich alphabet so both gates flip often.
    #[test]
    fn present_matches_naive_oracle_marker_rich(
        idxs in prop::collection::vec(0usize..ALPHABET.len(), 0..40),
    ) {
        let data: Vec<u8> = idxs.iter().map(|&i| ALPHABET[i]).collect();
        prop_assert_eq!(present(&data), naive_present(&data));
    }
}
