//! Gate `oob::client`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn oob_client_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/oob/client.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "oob::client: move inline tests to crates/verifier/tests/"
    );
}
