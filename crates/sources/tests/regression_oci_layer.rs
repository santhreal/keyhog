//! OCI image LAYER / MANIFEST parse axis.
//!
//! Distinct from `regression_docker_image_ref` (image-reference axis) and from
//! `docker_oci_classification` (the pure media-type/structural classifier): this
//! file drives the OCI index -> manifest -> {config, layer} blob resolution path
//! in `src/docker/oci.rs` through the public source testing facade, asserting
//! concrete parsed values, digest validation, blob-cap enforcement, and the
//! exact loud error text for malformed manifests.
//!
//! NOTE (verified in metadata.rs): `manifest_layer_archives` SORTS the resolved
//! layer paths (`layers.sort()`), so OCI manifest order is NOT preserved through
//! the facade; the multi-layer test asserts against a locally-sorted expectation.

#[cfg(feature = "docker")]
use keyhog_sources::testing::{SourceTestApi, TestApi};

#[cfg(feature = "docker")]
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest: [u8; 32] = hasher.finalize().into();
    keyhog_core::hex_encode(&digest)
}

/// Write a blob at `blobs/sha256/<sha256(bytes)>` and return its
/// `("sha256:<hex>", path)` descriptor pair, exactly as an OCI layout stores it.
#[cfg(feature = "docker")]
fn write_blob(root: &std::path::Path, bytes: &[u8]) -> (String, std::path::PathBuf) {
    let hex = sha256_hex(bytes);
    let path = root.join("blobs").join("sha256").join(&hex);
    std::fs::write(&path, bytes).expect("write OCI blob");
    (format!("sha256:{hex}"), path)
}

#[cfg(feature = "docker")]
fn oci_root() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    std::fs::create_dir_all(root.join("blobs").join("sha256")).expect("mkdir blobs");
    std::fs::write(root.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#)
        .expect("write oci-layout");
    (dir, root)
}

// ---------------------------------------------------------------------------
// Pure classifier axis (media-type vs structural), adversarial + boundary.
// ---------------------------------------------------------------------------

#[cfg(feature = "docker")]
#[test]
fn declared_media_type_wins_over_contradicting_body() {
    // Body carries `manifests` (structurally an index) but the descriptor
    // declares an image MANIFEST media type: the declaration is authoritative,
    // so the classifier must NOT follow it as an index.
    assert!(!TestApi.oci_descriptor_points_to_index(
        Some("application/vnd.oci.image.manifest.v1+json"),
        br#"{"manifests":[{"digest":"sha256:1"}]}"#
    ));
    // Body carries `config` (structurally a manifest) but the descriptor
    // declares an image INDEX media type: follow it as an index.
    assert!(TestApi.oci_descriptor_points_to_index(
        Some("application/vnd.oci.image.index.v1+json"),
        br#"{"config":{"digest":"sha256:2"}}"#
    ));
}

#[cfg(feature = "docker")]
#[test]
fn unknown_media_type_falls_through_to_structural_shape() {
    // A media type matching neither the index nor the manifest branch defers to
    // the structural shape of the body.
    assert!(TestApi.oci_descriptor_points_to_index(
        Some("application/octet-stream"),
        br#"{"manifests":[{"digest":"sha256:1"}]}"#
    ));
    assert!(!TestApi.oci_descriptor_points_to_index(
        Some("application/octet-stream"),
        br#"{"config":{"digest":"sha256:2"},"layers":[]}"#
    ));
}

#[cfg(feature = "docker")]
#[test]
fn unparseable_body_is_classified_as_manifest_not_index() {
    // LAW10: an unparseable blob is treated as not-an-index, so the caller
    // surfaces a loud manifest parse error rather than silently skipping it.
    assert!(!TestApi.oci_descriptor_points_to_index(None, b"{not valid json"));
    assert!(!TestApi.oci_descriptor_points_to_index(None, b""));
}

#[cfg(feature = "docker")]
#[test]
fn ambiguous_and_empty_shapes_are_not_indexes() {
    // Both `config` and `manifests` present -> config presence disqualifies the
    // index classification (parsed as a manifest).
    assert!(!TestApi.oci_descriptor_points_to_index(
        None,
        br#"{"config":{"digest":"sha256:2"},"manifests":[{"digest":"sha256:1"}]}"#
    ));
    // Neither field present -> not an index either.
    assert!(!TestApi.oci_descriptor_points_to_index(None, br#"{"schemaVersion":2}"#));
}

// ---------------------------------------------------------------------------
// Layer / config blob resolution axis.
// ---------------------------------------------------------------------------

#[cfg(feature = "docker")]
#[test]
fn oci_manifest_multiple_layers_resolve_to_sorted_blob_paths() {
    let (_dir, root) = oci_root();

    let (config_digest, _) = write_blob(&root, b"{}");
    let (layer0_digest, layer0_path) = write_blob(&root, b"layer-zero-archive-bytes");
    let (layer1_digest, layer1_path) = write_blob(&root, b"layer-one-archive-bytes-different");

    let manifest = format!(
        r#"{{"schemaVersion":2,
            "config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}"}},
            "layers":[
              {{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{layer0_digest}"}},
              {{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{layer1_digest}"}}
            ]}}"#
    );
    let (manifest_digest, _) = write_blob(&root, manifest.as_bytes());
    std::fs::write(
        root.join("index.json"),
        format!(
            r#"{{"schemaVersion":2,"manifests":[
                {{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{manifest_digest}"}}
              ]}}"#
        ),
    )
    .expect("write index");

    let mut expected = vec![layer0_path, layer1_path];
    expected.sort();
    let layers = TestApi.docker_manifest_layer_archives(&root).unwrap();
    assert_eq!(
        layers, expected,
        "both verified OCI layer blobs must resolve (sorted by blob path)"
    );
}

#[cfg(feature = "docker")]
#[test]
fn oci_manifest_config_ref_yields_single_chunk_with_digest_in_path() {
    let (_dir, root) = oci_root();

    let config = br#"{"config":{"Labels":{"k":"v"}}}"#;
    let (config_digest, _) = write_blob(&root, config);
    let manifest = format!(
        r#"{{"schemaVersion":2,
            "config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}"}},
            "layers":[]}}"#
    );
    let (manifest_digest, _) = write_blob(&root, manifest.as_bytes());
    std::fs::write(
        root.join("index.json"),
        format!(
            r#"{{"schemaVersion":2,"manifests":[
                {{"mediaType":"application/vnd.oci.image.manifest.v1+json",
                  "digest":"{manifest_digest}",
                  "annotations":{{"org.opencontainers.image.ref.name":"keyhog:layeraxis"}}}}
              ]}}"#
        ),
    )
    .expect("write index");

    let chunks = TestApi
        .docker_manifest_config_chunks(&root, "img:test")
        .unwrap();
    assert_eq!(chunks.len(), 1, "one image manifest -> one config chunk");
    let expected_path = format!("img:test:oci[0]:keyhog:layeraxis:config:{config_digest}");
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some(expected_path.as_str()),
        "config chunk path must carry index/ref/config-digest identity"
    );
    assert_eq!(chunks[0].metadata.source_type, "docker");
}

#[cfg(feature = "docker")]
#[test]
fn oci_nested_index_is_followed_to_the_real_manifest() {
    let (_dir, root) = oci_root();

    let (config_digest, _) = write_blob(&root, b"{}");
    let (layer_digest, layer_path) = write_blob(&root, b"nested-layer-archive-bytes");
    let manifest = format!(
        r#"{{"schemaVersion":2,
            "config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}"}},
            "layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{layer_digest}"}}]}}"#
    );
    let (manifest_digest, _) = write_blob(&root, manifest.as_bytes());

    // One nested image-index level (BuildKit multi-platform layout).
    let nested_index = format!(
        r#"{{"schemaVersion":2,"manifests":[
            {{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{manifest_digest}"}}
          ]}}"#
    );
    let (nested_digest, _) = write_blob(&root, nested_index.as_bytes());
    std::fs::write(
        root.join("index.json"),
        format!(
            r#"{{"schemaVersion":2,"manifests":[
                {{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"{nested_digest}"}}
              ]}}"#
        ),
    )
    .expect("write top index");

    let layers = TestApi.docker_manifest_layer_archives(&root).unwrap();
    assert_eq!(
        layers,
        vec![layer_path],
        "a nested image index must be followed one level to the real layer blob"
    );
}

// ---------------------------------------------------------------------------
// Loud-failure axis: malformed manifest, digest validation, blob caps.
// ---------------------------------------------------------------------------

#[cfg(feature = "docker")]
#[test]
fn oci_manifest_blob_malformed_json_fails_loud_with_entry_index() {
    let (_dir, root) = oci_root();

    let bad_manifest = b"{not valid manifest json";
    let (manifest_digest, _) = write_blob(&root, bad_manifest);
    std::fs::write(
        root.join("index.json"),
        format!(
            r#"{{"schemaVersion":2,"manifests":[
                {{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{manifest_digest}"}}
              ]}}"#
        ),
    )
    .expect("write index");

    let err = TestApi.docker_manifest_layer_archives(&root).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("invalid OCI image manifest") && msg.contains("from index entry 0"),
        "malformed OCI manifest blob must fail loud with the entry index, got {msg:?}"
    );
}

#[cfg(feature = "docker")]
#[test]
fn oci_layer_descriptor_missing_blob_fails_loud() {
    let (_dir, root) = oci_root();

    // Layer digest is well-formed but the blob file is never written.
    let absent_layer = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    let (config_digest, _) = write_blob(&root, b"{}");
    let manifest = format!(
        r#"{{"schemaVersion":2,
            "config":{{"digest":"{config_digest}"}},
            "layers":[{{"digest":"{absent_layer}"}}]}}"#
    );
    let (manifest_digest, _) = write_blob(&root, manifest.as_bytes());
    std::fs::write(
        root.join("index.json"),
        format!(
            r#"{{"schemaVersion":2,"manifests":[
                {{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{manifest_digest}"}}
              ]}}"#
        ),
    )
    .expect("write index");

    let err = TestApi.docker_manifest_layer_archives(&root).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("OCI layer descriptor references missing blob") && msg.contains(absent_layer),
        "missing OCI layer blob must fail loud with the digest, got {msg:?}"
    );
}

#[cfg(feature = "docker")]
#[test]
fn oci_config_blob_digest_mismatch_fails_loud() {
    let (_dir, root) = oci_root();

    // Config blob file is NAMED by an all-zero digest but holds `{}`, whose real
    // hash differs -> content-address verification must reject it.
    let declared_config = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let config_content = b"{}";
    std::fs::write(
        root.join("blobs")
            .join("sha256")
            .join("0000000000000000000000000000000000000000000000000000000000000000"),
        config_content,
    )
    .expect("write mismatched config blob");
    let real_config_hex = sha256_hex(config_content);

    let manifest = format!(
        r#"{{"schemaVersion":2,
            "config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{declared_config}"}},
            "layers":[]}}"#
    );
    let (manifest_digest, _) = write_blob(&root, manifest.as_bytes());
    std::fs::write(
        root.join("index.json"),
        format!(
            r#"{{"schemaVersion":2,"manifests":[
                {{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{manifest_digest}"}}
              ]}}"#
        ),
    )
    .expect("write index");

    let err = TestApi
        .docker_manifest_config_chunks(&root, "img:test")
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("digest mismatch")
            && msg.contains("expected sha256:0000000000000000")
            && msg.contains(format!("got sha256:{real_config_hex}").as_str()),
        "config blob digest mismatch must name expected and actual hashes, got {msg:?}"
    );
}

#[cfg(feature = "docker")]
#[test]
fn oci_manifest_descriptor_unsupported_digest_algorithm_fails_loud() {
    let (_dir, root) = oci_root();
    std::fs::write(
        root.join("index.json"),
        r#"{"schemaVersion":2,"manifests":[
            {"mediaType":"application/vnd.oci.image.manifest.v1+json",
             "digest":"md5:0000000000000000000000000000000000000000000000000000000000000000"}
          ]}"#,
    )
    .expect("write index");

    let err = TestApi.docker_manifest_layer_archives(&root).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("OCI manifest descriptor uses unsupported digest") && msg.contains("md5:"),
        "non-sha256 digest algorithm must be refused, got {msg:?}"
    );
}

#[cfg(feature = "docker")]
#[test]
fn oci_manifest_descriptor_wrong_length_digest_fails_loud() {
    let (_dir, root) = oci_root();
    // 63 hex chars: one short of the required 64.
    std::fs::write(
        root.join("index.json"),
        r#"{"schemaVersion":2,"manifests":[
            {"mediaType":"application/vnd.oci.image.manifest.v1+json",
             "digest":"sha256:000000000000000000000000000000000000000000000000000000000000000"}
          ]}"#,
    )
    .expect("write index");

    let err = TestApi.docker_manifest_layer_archives(&root).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("OCI manifest descriptor references unsafe digest"),
        "a 63-char sha256 hex must be rejected as an unsafe digest, got {msg:?}"
    );
}

#[cfg(feature = "docker")]
#[test]
fn oci_layer_descriptor_size_above_cap_fails_loud() {
    let (_dir, root) = oci_root();

    let (config_digest, _) = write_blob(&root, b"{}");
    // Well-formed layer digest with a declared size far above any byte cap; the
    // size guard fires before the blob file is even consulted.
    let layer_digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let manifest = format!(
        r#"{{"schemaVersion":2,
            "config":{{"digest":"{config_digest}"}},
            "layers":[{{"digest":"{layer_digest}","size":18446744073709551615}}]}}"#
    );
    let (manifest_digest, _) = write_blob(&root, manifest.as_bytes());
    std::fs::write(
        root.join("index.json"),
        format!(
            r#"{{"schemaVersion":2,"manifests":[
                {{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{manifest_digest}"}}
              ]}}"#
        ),
    )
    .expect("write index");

    let err = TestApi.docker_manifest_layer_archives(&root).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("18446744073709551615 bytes") && msg.contains("byte cap"),
        "an oversized declared layer size must be refused with the cap context, got {msg:?}"
    );
}

#[cfg(feature = "docker")]
#[test]
fn oci_index_missing_when_layout_present_fails_loud() {
    // oci-layout present but index.json absent: the reader must not silently
    // treat the layout as empty.
    let (_dir, root) = oci_root();
    let err = TestApi.docker_manifest_layer_archives(&root).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("OCI image layout is missing index.json"),
        "oci-layout without index.json must fail loud, got {msg:?}"
    );
}

// ---------------------------------------------------------------------------
// Feature-off stubs keep the file compiling and the surface honest without the
// `docker` feature.
// ---------------------------------------------------------------------------

#[cfg(not(feature = "docker"))]
#[test]
fn oci_layer_axis_requires_docker_feature() {
    assert!(!cfg!(feature = "docker"));
}
