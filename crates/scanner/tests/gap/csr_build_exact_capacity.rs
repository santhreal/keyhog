//! Regression: the `CsrU32` flat-pair build reserves exact capacity and is
//! byte-identical to the prior nested-row representation.
//!
//! Production builders now emit `(row, value)` pairs directly. `from_pairs`
//! knows the complete value count and row count before constructing either
//! retained vector, so it reserves `pairs.len()` data slots and
//! `row_count + 1` offsets without temporary per-row vectors.
//!
//! This pins both the exact row reconstruction contract and the two allocation
//! capacities at the single production constructor.

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

    // (2) Source shape: the production pair constructor reserves both retained
    // vectors from exact input cardinalities.
    let src = read_src("src/engine/csr.rs");
    assert!(
        src.contains("let mut data = Vec::with_capacity(pairs.len());"),
        "CSR data storage must reserve the exact pair count"
    );
    assert!(
        src.contains("let mut offsets = Vec::with_capacity(row_count + 1);"),
        "CSR offsets must reserve exactly row_count + 1 entries"
    );
    assert!(
        !src.contains("let mut data = Vec::new();"),
        "CSR data must not grow from an unreserved vector"
    );
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vector pins byte-identical reconstruction on one hand-built shape;
// these SWEEP the round-trip over arbitrary ragged rows. The CORRECTNESS CONTRACT
// of the CSR build is that `from_rows` then row-read reconstructs the EXACT input
// (each element cast usize→u32), including leading/interior/trailing empty rows
// and the `n+1` offsets invariant, an off-by-one in the capacity/offset math
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
