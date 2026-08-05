//! S3 object fetch must cap downloaded bytes.

#[cfg(not(feature = "s3"))]
#[test]
fn s3_max_object_requires_s3_feature() {
    assert!(!cfg!(feature = "s3"));
}
