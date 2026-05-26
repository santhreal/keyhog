//! Gate `verify::multi_step`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn verify_multi_step_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/verify/multi_step.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "verify::multi_step: move inline tests to crates/verifier/tests/"
    );
}
