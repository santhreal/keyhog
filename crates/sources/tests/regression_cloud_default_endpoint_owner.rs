//! Cloud default endpoint constants have one owner.

fn source(rel: &str) -> String {
    std::fs::read_to_string(format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel))
        .unwrap_or_else(|error| panic!("read {rel}: {error}"))
}

#[test]
fn cloud_default_endpoints_have_one_owner() {
    let cloud = source("src/cloud/mod.rs");
    assert!(
        cloud.contains("pub(crate) const DEFAULT_GCS_ENDPOINT")
            && cloud.contains("\"https://storage.googleapis.com\""),
        "cloud/mod.rs must own the default GCS endpoint"
    );
    assert!(
        cloud.contains("pub(crate) const DEFAULT_S3_HOST_SUFFIX")
            && cloud.contains("\"s3.amazonaws.com\""),
        "cloud/mod.rs must own the default S3 host suffix"
    );

    let gcs = source("src/gcs.rs");
    assert!(
        gcs.contains("crate::cloud::DEFAULT_GCS_ENDPOINT"),
        "GCS source must consume the shared default endpoint owner"
    );
    assert!(
        !gcs.contains("const DEFAULT_GCS_ENDPOINT"),
        "GCS source must not redeclare its default endpoint"
    );

    let s3 = source("src/s3/mod.rs");
    assert!(
        s3.contains("crate::cloud::DEFAULT_S3_HOST_SUFFIX"),
        "S3 source must consume the shared default host suffix owner"
    );
    assert!(
        !s3.contains("const DEFAULT_S3_HOST_SUFFIX"),
        "S3 source must not redeclare its default host suffix"
    );
}
