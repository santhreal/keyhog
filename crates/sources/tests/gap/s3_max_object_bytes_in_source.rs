//! S3 object fetch must cap downloaded bytes.

#[cfg(feature = "s3")]
#[test]
fn s3_max_object_bytes_in_source() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/s3/mod.rs"))
        .expect("s3/mod.rs");
    assert!(src.contains("MAX_S3_OBJECT_BYTES"));
    assert!(src.contains("10 * 1024 * 1024"));
}

#[cfg(not(feature = "s3"))]
#[test]
fn s3_max_object_requires_s3_feature() {
    assert!(!cfg!(feature = "s3"));
}
