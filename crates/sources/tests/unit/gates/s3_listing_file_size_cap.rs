//! Gate `s3::listing`: modularity file cap (500 LOC).

#[test]
fn s3_listing_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/s3/listing.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "s3::listing: {lines} lines exceeds 500-line cap — split module"
    );
}
