//! Gate `banner`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn banner_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/banner.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "banner: move inline tests to crates/core/tests/"
    );
}
