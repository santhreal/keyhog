//! OCI/Docker image-index vs manifest classification.
//!
//! Relocated from `src/docker/oci.rs` to honor the Santh "no inline tests in
//! `src/docker/**`" contract (`docker_no_inline_tests` gate). The classifier is
//! private, so it is exercised through the `oci_descriptor_points_to_index`
//! test accessor on the source testing facade.

use keyhog_sources::testing::{SourceTestApi, TestApi};

#[test]
fn classifies_index_vs_manifest_by_declared_media_type() {
    // Nested image index / manifest-list -> follow it.
    assert!(TestApi
        .oci_descriptor_points_to_index(Some("application/vnd.oci.image.index.v1+json"), b"{}"));
    assert!(TestApi.oci_descriptor_points_to_index(
        Some("application/vnd.docker.distribution.manifest.list.v2+json"),
        b"{}"
    ));
    // Image manifest -> parse `config`.
    assert!(!TestApi
        .oci_descriptor_points_to_index(Some("application/vnd.oci.image.manifest.v1+json"), b"{}"));
    assert!(!TestApi.oci_descriptor_points_to_index(
        Some("application/vnd.docker.distribution.manifest.v2+json"),
        b"{}"
    ));
}

#[test]
fn classifies_index_vs_manifest_structurally_when_media_type_absent() {
    // BuildKit-style layout where the entry omits mediaType: an image index
    // carries `manifests`, an image manifest carries `config`.
    let index_bytes = br#"{"manifests":[{"digest":"sha256:1"}]}"#;
    let manifest_bytes = br#"{"config":{"digest":"sha256:2"},"layers":[]}"#;
    assert!(TestApi.oci_descriptor_points_to_index(None, index_bytes));
    assert!(!TestApi.oci_descriptor_points_to_index(None, manifest_bytes));
}
