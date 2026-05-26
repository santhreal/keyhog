//! Gate `oob::session`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn oob_session_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/oob/session.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "oob::session: move inline tests to crates/verifier/tests/"
    );
}
