//! Gate `simdsieve_prefilter`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn simdsieve_prefilter_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/simdsieve_prefilter.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "simdsieve_prefilter: move inline tests to crates/scanner/tests/"
    );
}
