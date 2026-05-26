//! Gate `http`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn http_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/http.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "http: move inline tests to crates/sources/tests/"
    );
}
