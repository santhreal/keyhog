//! KH-GAP-129: `context/inference.rs` embeds the literal `#[cfg(test)]` string
//! in test-function detection, tripping the no-inline-tests gate falsely while
//! providing no migrated unit coverage for the lookback logic.

#[test]
fn context_inference_has_no_cfg_test_literal_in_src() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/context/inference.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "KH-GAP-129: inference.rs contains literal `#[cfg(test)]` string. \
         breaks context_inference_no_inline_tests gate; use a const or escaped fragment"
    );
}
