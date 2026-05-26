//! Gate `checksum::stripe`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn checksum_stripe_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/checksum/stripe.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "checksum::stripe: move inline tests to crates/scanner/tests/"
    );
}
