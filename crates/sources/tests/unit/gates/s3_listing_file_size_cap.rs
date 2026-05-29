//! Gate `s3::listing`: modularity file cap (500 LOC).

#[test]
fn s3_listing_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/s3/listing.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    // Advisory cap (Santh STANDARD.md): warn, do not fail CI.
    if lines > 500 {
        eprintln!("s3::listing: {lines} lines exceeds 500-line cap - split module");
    }
}
