//! Gate `web`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn web_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/web.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "web: move inline tests to crates/sources/tests/"
    );
}
