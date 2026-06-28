//! Regression: ONE assignment+quote prefilter for both fragment-reassembly
//! paths.
//!
//! `scan_postprocess/fragments.rs` (in-chunk reassembly) and
//! `scan_no_hit_reassembly.rs` (cross-file no-hit reassembly) each gate their
//! pass on "the chunk has an assignment operator AND a quote". They used to
//! open-code that as five separate `memchr(byte).is_some()` calls — two copies
//! of the same predicate that could silently drift apart. The no-hit path now
//! calls the shared `CompiledScanner::has_fragment_assignment_syntax`, which
//! itself uses `memchr2`/`memchr3` (two SIMD passes). This pins that the dedup
//! stays deduped (no re-open-coded memchr) AND re-checks the shared predicate's
//! behaviour so a future edit can't quietly diverge the two gates.

use keyhog_scanner::testing::has_fragment_assignment_syntax_for_test as present;

fn read_src(rel: &str) -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(root.join(rel)).expect("source file readable")
}

#[test]
fn both_fragment_paths_share_one_prefilter_predicate() {
    let no_hit = read_src("src/engine/scan_no_hit_reassembly.rs");
    // The no-hit reassembly path routes through the shared predicate ...
    assert!(
        no_hit.contains("has_fragment_assignment_syntax(chunk.data.as_bytes())"),
        "scan_no_hit_reassembly must gate on the shared has_fragment_assignment_syntax predicate"
    );
    // ... and must NOT re-open-code the per-byte memchr prefilter.
    assert!(
        !no_hit.contains("memchr::memchr(b'='"),
        "scan_no_hit_reassembly must not re-open-code the assignment memchr scan"
    );

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

    // Behavioural tie: the shared predicate is true iff BOTH an assignment op and
    // a quote are present (the contract both reassembly paths depend on).
    assert!(present(b"key = \"v\""));
    assert!(present(b"a: 'b'"));
    assert!(!present(b"key = plain"), "operator without a quote");
    assert!(!present(b"\"quoted only\""), "quote without an operator");
    assert!(!present(b"neither here"));
}
