//! Gate `s3::listing`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn s3_listing_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/s3/listing.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "s3::listing: move inline tests to crates/sources/tests/"
    );
}
