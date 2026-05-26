//! Gate `verify::request`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn verify_request_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/verify/request.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "verify::request: move inline tests to crates/verifier/tests/"
    );
}
