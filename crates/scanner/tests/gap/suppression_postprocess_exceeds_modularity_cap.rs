//! KH-GAP-124: `pipeline/postprocess/suppression.rs` is 709 LOC with no
//! `tests/unit/gates/*suppression*` file-size gate (unlike peer modules).

use std::path::PathBuf;

#[test]
fn suppression_postprocess_under_standard_modularity_cap() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/suppression/mod.rs");
    let lines = std::fs::read_to_string(&path)
        .expect("read suppression.rs")
        .lines()
        .count();
    const CAP: usize = 500;
    assert!(
        lines <= CAP,
        "KH-GAP-124: suppression.rs is {lines} lines — exceeds {CAP} LOC cap; \
         split example/placeholder/repetitive-mask helpers"
    );
}
