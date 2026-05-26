//! KH-GAP-007: Santh lint preamble on lib.rs (hardening.rs has libc unsafe waiver).

#[test]
fn lib_rs_has_santh_lint_preamble() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("lib.rs");
    assert!(
        src.contains("clippy::unwrap_used"),
        "KH-GAP-007: missing deny(clippy::unwrap_used) in lint preamble"
    );
    assert!(
        src.contains("clippy::todo"),
        "KH-GAP-007: missing deny(clippy::todo) in lint preamble"
    );
}
