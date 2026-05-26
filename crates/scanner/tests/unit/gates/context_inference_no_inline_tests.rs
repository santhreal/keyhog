//! Gate `context::inference`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn context_inference_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/context/inference.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "context::inference: move inline tests to crates/scanner/tests/"
    );
}
