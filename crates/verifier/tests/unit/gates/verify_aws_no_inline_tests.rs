//! Gate `verify::aws`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn verify_aws_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/verify/aws.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "verify::aws: move inline tests to crates/verifier/tests/"
    );
}
