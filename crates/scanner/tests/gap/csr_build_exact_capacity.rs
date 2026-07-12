//! Regression: the `CsrU32` build reserves exact capacity (Law 7) and is
//! byte-identical to the old grow-from-empty build.
//!
//! The type doc claims CSR "collapses each table to exactly two allocations".
//! That was true of the STORED form but not the BUILD: `from_rows` grew both
//! `data` and `offsets` from empty, reallocating ~log(n) times as ~1000+ rows
//! were pushed. The four real builders all construct via `From<Vec<Vec<usize>>>`,
//! which knows the row count AND the total element count up front — so it now
//! reserves both vectors exactly and the build does exactly two allocations.
//!
//! This pins two things:
//!   (1) BEHAVIOUR — the build reconstructs the input rows byte-for-byte,
//!       including the empty rows CSR specifically optimizes (proves the
//!       restructure into `from_rows_sized` changed no output);
//!   (2) SOURCE SHAPE — the `From` path computes the exact `data` capacity from
//!       the row lengths and both vectors are `with_capacity`-reserved, and the
//!       concatenation loop lives in exactly one place (`from_rows_sized`), so a
//!       future edit can't quietly reintroduce the grow-from-empty reallocations
//!       or a duplicate second build loop.

use keyhog_scanner::testing::csr_from_rows_roundtrip_for_test as roundtrip;

fn read_src(rel: &str) -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(root.join(rel)).expect("source file readable")
}

#[test]
fn csr_build_is_byte_identical_and_exactly_reserved() {
    // (1) Byte-identical reconstruction, including leading/interior/trailing
    // empty rows and a multi-element row.
    let rows: Vec<Vec<usize>> = vec![vec![], vec![1, 2, 3], vec![], vec![7], vec![]];
    let got = roundtrip(rows);
    assert_eq!(
        got,
        vec![
            Vec::<u32>::new(),
            vec![1u32, 2, 3],
            Vec::<u32>::new(),
            vec![7u32],
            Vec::<u32>::new(),
        ],
        "CSR build must reconstruct every row (incl. empty rows) byte-for-byte"
    );
    // A single empty input yields a single empty row (the `n + 1` offsets
    // invariant: one row => two offsets, both zero).
    assert_eq!(roundtrip(vec![vec![]]), vec![Vec::<u32>::new()]);
    // Zero rows yields zero rows.
    assert_eq!(roundtrip(vec![]), Vec::<Vec<u32>>::new());

    // (2) Source shape: the exact-capacity reservation and single loop owner.
    let src = read_src("src/engine/csr.rs");
    assert!(
        src.contains("fn from_rows_sized"),
        "the CSR concatenation loop must live in one owner, from_rows_sized"
    );
    assert!(
        src.contains("rows.iter().map(Vec::len).sum()"),
        "From<Vec<Vec<usize>>> must compute the exact data capacity from row lengths"
    );
    assert!(
        src.contains("Vec::with_capacity(data_cap)")
            && src.contains("Vec::with_capacity(offsets_cap)"),
        "both data and offsets must be capacity-reserved (exactly two allocations on the build)"
    );
    // The old grow-from-empty seeds must be gone from the build.
    assert!(
        !src.contains("let mut data = Vec::new();"),
        "data must not grow from an unreserved Vec::new() (reintroduces reallocations)"
    );
    assert!(
        !src.contains("let mut offsets = vec![0u32];"),
        "offsets must not grow from an unreserved vec![0u32] (reintroduces reallocations)"
    );
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vector pins byte-identical reconstruction on one hand-built shape;
// these SWEEP the round-trip over arbitrary ragged rows. The CORRECTNESS CONTRACT
// of the CSR build is that `from_rows` then row-read reconstructs the EXACT input
// (each element cast usize→u32), including leading/interior/trailing empty rows
// and the `n+1` offsets invariant — an off-by-one in the capacity/offset math
// would corrupt row boundaries. Traced against engine/csr.rs. No proptest before.

use proptest::prelude::*;

/// Ragged rows: 0..24 rows, each 0..8 elements in `0..100_000` (well within u32),
/// so empty rows and multi-element rows both occur frequently.
fn ragged_rows() -> impl Strategy<Value = Vec<Vec<usize>>> {
    prop::collection::vec(prop::collection::vec(0usize..100_000, 0..8), 0..24)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3_000))]

    /// ROUND-TRIP: the CSR build reconstructs every row byte-for-byte (values cast
    /// to u32), for any ragged input including empty rows anywhere.
    #[test]
    fn csr_build_roundtrips_arbitrary_rows(rows in ragged_rows()) {
        let expected: Vec<Vec<u32>> = rows
            .iter()
            .map(|r| r.iter().map(|&x| x as u32).collect())
            .collect();
        prop_assert_eq!(roundtrip(rows), expected);
    }

    /// The round-trip preserves the row COUNT and every row's LENGTH exactly (the
    /// `n+1` offsets structure), independent of the value equality above.
    #[test]
    fn csr_build_preserves_row_count_and_lengths(rows in ragged_rows()) {
        let lengths: Vec<usize> = rows.iter().map(Vec::len).collect();
        let out = roundtrip(rows);
        prop_assert_eq!(out.len(), lengths.len());
        let out_lengths: Vec<usize> = out.iter().map(Vec::len).collect();
        prop_assert_eq!(out_lengths, lengths);
    }
}
