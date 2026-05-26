//! Gate `s3::auth`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn s3_auth_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/s3/auth.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "s3::auth: move inline tests to crates/sources/tests/"
    );
}
