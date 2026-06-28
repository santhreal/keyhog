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
        src.contains("Vec::with_capacity(data_cap)") && src.contains("Vec::with_capacity(offsets_cap)"),
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
