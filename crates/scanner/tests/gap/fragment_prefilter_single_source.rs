//! Regression: ONE assignment+quote prefilter for fragment reassembly.
//!
//! `scan_postprocess/fragments.rs` gates its pass on "the chunk has an
//! assignment operator AND a quote" through one `memchr2`/`memchr3` predicate.

use keyhog_scanner::testing::has_fragment_assignment_syntax_for_test as present;

fn read_src(rel: &str) -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(root.join(rel)).expect("source file readable")
}

#[test]
fn fragment_path_uses_the_canonical_prefilter_predicate() {
    let fragments = read_src("src/engine/scan_postprocess/fragments.rs");
    // The canonical predicate lives in fragments.rs and uses the fused
    // multi-needle SIMD passes.
    assert!(
        fragments.contains("fn has_fragment_assignment_syntax"),
        "fragments.rs owns the shared predicate"
    );
    assert!(
        fragments.contains("memchr::memchr2(b'=', b':', data)")
            && fragments.contains("memchr::memchr3(b'\"', b'\\'', b'`', data)"),
        "the shared predicate must use memchr2/memchr3 (two SIMD passes, not five memchr)"
    );

    // Behavioural tie: the predicate is true iff BOTH an assignment op and a
    // quote are present.
    assert!(present(b"key = \"v\""));
    assert!(present(b"a: 'b'"));
    assert!(!present(b"key = plain"), "operator without a quote");
    assert!(!present(b"\"quoted only\""), "quote without an operator");
    assert!(!present(b"neither here"));
}
