//! Regression coverage for Docker/OCI **layer classification**: which blob is an
//! image index vs an image manifest vs a scannable layer, which archive entries
//! are recognized as layer archives vs skipped as non-layer files, and that a
//! secret inside a discovered layer surfaces carrying the layer's digest in its
//! chunk-metadata path.
//!
//! Distinct from `adversarial/docker_oci_manifest_layers.rs` (end-to-end unpack
//! of a single OCI blob layer) and `docker_oci_classification.rs` (two happy-path
//! media-type cases): this file drives the *adversarial* classification edges 
//! media-type-vs-body precedence, hybrid/empty/unparseable bodies, decoy
//! filenames, unreferenced non-layer blobs, and asserts the exact digest label
//! that ends up on the rewritten chunk.
//!
//! The private classifier + discovery are reached only through the crate's
//! `#[doc(hidden)]` testing facade (the `src/docker/**` no-inline-tests contract).

#[cfg(feature = "docker")]
use keyhog_sources::testing::{SourceTestApi, TestApi};

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

#[cfg(feature = "docker")]
fn raw_tar_bytes(path: &str, payload: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path(path).expect("set layer entry path");
    header.set_size(payload.len() as u64);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append(&header, payload)
        .expect("append layer entry");
    builder.finish().expect("finish tar");
    builder.into_inner().expect("into tar bytes")
}

#[cfg(feature = "docker")]
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest: [u8; 32] = hasher.finalize().into();
    keyhog_core::hex_encode(digest)
}

// ---------------------------------------------------------------------------
// descriptor classification: media-type precedence over structural body
// ---------------------------------------------------------------------------

/// The declared `mediaType` is authoritative: an `image.index` media type wins
/// even when the blob body is shaped like an image manifest (carries `config`),
/// and an `image.manifest` media type wins even when the body is index-shaped.
#[cfg(feature = "docker")]
#[test]
fn declared_media_type_overrides_conflicting_body_shape() {
    // media type says index, but the body looks like a manifest -> still index.
    let manifest_shaped_body = br#"{"config":{"digest":"sha256:aa"},"layers":[]}"#;
    assert!(
        TestApi.oci_descriptor_points_to_index(
            Some("application/vnd.oci.image.index.v1+json"),
            manifest_shaped_body
        ),
        "image.index media type must classify as an index even over a config-bearing body"
    );

    // media type says manifest, but the body looks like an index -> still manifest.
    let index_shaped_body = br#"{"manifests":[{"digest":"sha256:bb"}]}"#;
    assert!(
        !TestApi.oci_descriptor_points_to_index(
            Some("application/vnd.oci.image.manifest.v1+json"),
            index_shaped_body
        ),
        "image.manifest media type must classify as a manifest even over a manifests[] body"
    );
}

/// An unrecognized media type carries no verdict, so classification falls through
/// to structural inspection of the body.
#[cfg(feature = "docker")]
#[test]
fn unknown_media_type_falls_through_to_structural_body_shape() {
    let index_shaped_body = br#"{"manifests":[{"digest":"sha256:cc"}]}"#;
    let manifest_shaped_body = br#"{"config":{"digest":"sha256:dd"}}"#;
    assert!(
        TestApi.oci_descriptor_points_to_index(Some("application/octet-stream"), index_shaped_body),
        "unknown media type + manifests[] body must classify structurally as an index"
    );
    assert!(
        !TestApi
            .oci_descriptor_points_to_index(Some("application/octet-stream"), manifest_shaped_body),
        "unknown media type + config body must classify structurally as a manifest"
    );
}

/// `contains()`/`ends_with()` matching, not exact equality: a vendor-prefixed
/// media type still classifies via its recognized substring/suffix.
#[cfg(feature = "docker")]
#[test]
fn vendor_prefixed_media_types_classify_via_substring_and_suffix() {
    // ends_with the schema-2 distribution manifest suffix -> manifest.
    assert!(
        !TestApi.oci_descriptor_points_to_index(
            Some("application/vnd.acme.distribution.manifest.v2+json"),
            b"{}"
        ),
        "a vendor-prefixed distribution.manifest.v2+json suffix must classify as a manifest"
    );
    // contains `image.manifest` anywhere -> manifest.
    assert!(
        !TestApi.oci_descriptor_points_to_index(
            Some("application/vnd.acme.image.manifest.v9+json"),
            b"{}"
        ),
        "a media type containing image.manifest must classify as a manifest"
    );
    // contains `manifest.list` anywhere -> index.
    assert!(
        TestApi.oci_descriptor_points_to_index(
            Some("application/vnd.acme.distribution.manifest.list.v2+json"),
            b"{}"
        ),
        "a media type containing manifest.list must classify as an index"
    );
}

/// A blob body that is not valid JSON is classified as *not* an index (so the
/// caller parses it as an image manifest and surfaces a loud parse error) rather
/// than being silently skipped.
#[cfg(feature = "docker")]
#[test]
fn unparseable_body_without_media_type_is_not_an_index() {
    assert!(
        !TestApi.oci_descriptor_points_to_index(None, b"{ this is : not json ]["),
        "an unparseable descriptor body must classify as not-an-index (parsed as manifest, loud error)"
    );
    assert!(
        !TestApi.oci_descriptor_points_to_index(None, b"\x1f\x8b\x08\x00rawgzipbytes"),
        "binary/gzip descriptor body must classify as not-an-index"
    );
}

/// A hybrid body carrying BOTH `config` and `manifests` is classified as a
/// manifest (config presence dominates), never as an index.
#[cfg(feature = "docker")]
#[test]
fn hybrid_body_with_config_and_manifests_is_not_an_index() {
    let hybrid = br#"{"config":{"digest":"sha256:ee"},"manifests":[{"digest":"sha256:ff"}]}"#;
    assert!(
        !TestApi.oci_descriptor_points_to_index(None, hybrid),
        "a body with both config and manifests must classify as a manifest (config dominates)"
    );
}

/// Structural boundaries: an empty object is not an index; a body whose ONLY
/// distinguishing field is `manifests`: even an empty array. IS an index.
#[cfg(feature = "docker")]
#[test]
fn structural_boundary_empty_object_vs_manifests_key() {
    assert!(
        !TestApi.oci_descriptor_points_to_index(None, b"{}"),
        "an empty JSON object carries neither config nor manifests, so it is not an index"
    );
    assert!(
        TestApi.oci_descriptor_points_to_index(None, br#"{"manifests":[]}"#),
        "a body whose only key is manifests (even empty) and has no config must be an index"
    );
    assert!(
        !TestApi.oci_descriptor_points_to_index(None, br#"{"schemaVersion":2}"#),
        "a body with an unrelated key and no manifests/config must be a manifest, not an index"
    );
}

/// A layer blob's own media type is not one of the manifest/index markers, so a
/// layer descriptor over its (non-JSON) tar body is classified as not-an-index.
#[cfg(feature = "docker")]
#[test]
fn layer_media_types_are_not_classified_as_indexes() {
    let tar_body = raw_tar_bytes("layer-secret.env", b"K=AKIAIOSFODNN7EXAMPLE\n");
    assert!(
        !TestApi.oci_descriptor_points_to_index(
            Some("application/vnd.oci.image.layer.v1.tar+gzip"),
            &tar_body
        ),
        "an OCI tar+gzip layer media type must not classify as an image index"
    );
    assert!(
        !TestApi.oci_descriptor_points_to_index(
            Some("application/vnd.docker.image.rootfs.diff.tar.gzip"),
            &tar_body
        ),
        "a Docker rootfs-diff layer media type must not classify as an image index"
    );
}

// ---------------------------------------------------------------------------
// layer-archive discovery: which files are classified as layers
// ---------------------------------------------------------------------------

/// Fallback (metadata-less) discovery classifies a file as a layer archive only
/// by its exact basename; sibling non-layer files are skipped.
#[cfg(feature = "docker")]
#[test]
fn fallback_discovery_classifies_only_layer_named_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    std::fs::create_dir_all(&root).expect("mkdir root");
    std::fs::write(root.join("layer.tar"), raw_tar_bytes("a.env", b"S=1\n")).expect("write layer");
    std::fs::write(root.join("notes.txt"), b"not a layer").expect("write notes");
    std::fs::write(root.join("app.tar"), raw_tar_bytes("b.env", b"S=2\n"))
        .expect("write decoy tar");

    let layers = TestApi
        .docker_manifest_layer_archives(&root)
        .expect("fallback layer discovery must succeed");
    assert_eq!(
        layers,
        vec![root.join("layer.tar")],
        "only the layer.tar basename must be classified as a layer; notes.txt and app.tar are skipped"
    );
}

/// Every recognized layer-archive extension is discovered; decoys whose basename
/// is not in the recognized set are skipped. Result is sorted+deduped.
#[cfg(feature = "docker")]
#[test]
fn fallback_discovery_recognizes_all_layer_extensions_and_skips_decoys() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    std::fs::create_dir_all(&root).expect("mkdir root");

    let recognized = [
        "layer.tar",
        "layer.tar.gz",
        "layer.tgz",
        "layer.tar.zst",
        "layer.tar.zstd",
    ];
    for name in recognized {
        std::fs::write(root.join(name), raw_tar_bytes("x.env", b"S=x\n"))
            .unwrap_or_else(|error| panic!("write recognized {name}: {error}"));
    }
    // Decoys whose basename is NOT in the recognized set.
    for decoy in ["layer.tar.bz2", "sublayer.tar", "notlayer.tgz", "layer.zip"] {
        std::fs::write(root.join(decoy), b"decoy")
            .unwrap_or_else(|error| panic!("write decoy {decoy}: {error}"));
    }

    let mut expected: Vec<std::path::PathBuf> =
        recognized.iter().map(|name| root.join(name)).collect();
    expected.sort();

    let layers = TestApi
        .docker_manifest_layer_archives(&root)
        .expect("fallback layer discovery must succeed");
    assert_eq!(
        layers, expected,
        "all five recognized layer-archive basenames must be discovered, sorted, and decoys skipped"
    );
}

/// Manifest-driven discovery returns exactly the `Layers` the manifest lists; an
/// unreferenced config blob and an unreferenced stray blob sitting in the same
/// `blobs/sha256/` directory are not classified as layers.
#[cfg(feature = "docker")]
#[test]
fn manifest_discovery_skips_unreferenced_non_layer_blobs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    let blobs = root.join("blobs").join("sha256");
    std::fs::create_dir_all(&blobs).expect("mkdir blobs");

    let layer_bytes = raw_tar_bytes("etc/token.env", b"AWS_SECRET_ACCESS_KEY=abc\n");
    let layer_hex = sha256_hex(&layer_bytes);
    std::fs::write(blobs.join(&layer_hex), &layer_bytes).expect("write layer blob");

    // Unreferenced blobs that must NOT be classified as layers.
    std::fs::write(blobs.join("config"), br#"{"config":{}}"#).expect("write config blob");
    let stray_hex = sha256_hex(b"stray blob content");
    std::fs::write(blobs.join(&stray_hex), b"stray blob content").expect("write stray blob");

    let manifest = format!(
        r#"[{{"Config":"blobs/sha256/config","RepoTags":["keyhog:test"],"Layers":["blobs/sha256/{layer_hex}"]}}]"#
    );
    std::fs::write(root.join("manifest.json"), manifest).expect("write manifest");

    let layers = TestApi
        .docker_manifest_layer_archives(&root)
        .expect("manifest layer discovery must succeed");
    assert_eq!(
        layers,
        vec![blobs.join(&layer_hex)],
        "only the manifest-referenced layer digest is a layer; config + stray blobs are skipped"
    );
}

/// A manifest that references a layer digest with no backing blob file fails
/// loud, naming the missing layer (it is never silently dropped).
#[cfg(feature = "docker")]
#[test]
fn manifest_referencing_absent_layer_blob_fails_loud() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    std::fs::create_dir_all(root.join("blobs").join("sha256")).expect("mkdir blobs");

    let missing_hex = sha256_hex(b"never written to disk");
    let manifest = format!(
        r#"[{{"Config":"blobs/sha256/config","RepoTags":["keyhog:test"],"Layers":["blobs/sha256/{missing_hex}"]}}]"#
    );
    std::fs::write(root.join("manifest.json"), manifest).expect("write manifest");

    let err = TestApi
        .docker_manifest_layer_archives(&root)
        .expect_err("manifest referencing an absent layer blob must fail loud");
    let msg = err.to_string();
    assert!(
        msg.contains("references missing layer") && msg.contains(&missing_hex),
        "missing layer error must name the absent layer digest, got {msg:?}"
    );
}

// ---------------------------------------------------------------------------
// end-to-end: a layer secret surfaces carrying the layer digest label
// ---------------------------------------------------------------------------

/// Discover a manifest layer, unpack it, and rewrite its filesystem chunks: the
/// secret must surface on a chunk whose metadata path is exactly
/// `{image}:blobs/sha256/{digest}:{entry}` with `source_type == "docker"`.
#[cfg(feature = "docker")]
#[test]
fn layer_secret_surfaces_with_exact_digest_metadata_path() {
    use keyhog_core::Source;
    use keyhog_sources::FilesystemSource;

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    let blobs = root.join("blobs").join("sha256");
    std::fs::create_dir_all(&blobs).expect("mkdir blobs");

    let layer_bytes = raw_tar_bytes("secret.env", b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
    let layer_hex = sha256_hex(&layer_bytes);
    std::fs::write(blobs.join(&layer_hex), &layer_bytes).expect("write layer blob");

    let manifest = format!(
        r#"[{{"Config":"blobs/sha256/config","RepoTags":["keyhog:test"],"Layers":["blobs/sha256/{layer_hex}"]}}]"#
    );
    std::fs::write(root.join("manifest.json"), manifest).expect("write manifest");

    // 1. classification/discovery: exactly the digest-named blob is the layer.
    let layers = TestApi
        .docker_manifest_layer_archives(&root)
        .expect("layer discovery must succeed");
    let expected_layer_path = blobs.join(&layer_hex);
    assert_eq!(layers, vec![expected_layer_path.clone()]);

    // 2. production layer label = digest path relative to the archive root.
    let layer_name = expected_layer_path
        .strip_prefix(&root)
        .expect("layer path under root")
        .to_string_lossy()
        .replace('\\', "/");
    assert_eq!(layer_name, format!("blobs/sha256/{layer_hex}"));

    // 3. unpack + rewrite the extracted filesystem chunks under the digest label.
    let unpacked = dir.path().join("unpacked");
    std::fs::create_dir(&unpacked).expect("mkdir unpacked");
    let residual = TestApi
        .unpack_docker_layer_archive(&expected_layer_path, &unpacked)
        .expect("layer must unpack");
    assert_eq!(
        residual.len(),
        0,
        "a well-formed layer must unpack with no per-entry cap errors, got {residual:?}"
    );

    let fs_rows: Vec<keyhog_core::Chunk> = FilesystemSource::new(unpacked.clone())
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("unpacked layer filesystem chunks must drain without source errors");
    let rows: Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>> =
        fs_rows.into_iter().map(Ok).collect();
    let rewritten = TestApi
        .docker_rewrite_layer_chunks(rows, "keyhog:test", &unpacked, &layer_name)
        .expect("layer chunk rewrite must succeed");

    let expected_path = format!("keyhog:test:blobs/sha256/{layer_hex}:secret.env");
    let secret_chunk = rewritten
        .iter()
        .find(|chunk| chunk.metadata.path.as_deref() == Some(expected_path.as_str()))
        .unwrap_or_else(|| {
            panic!(
                "no rewritten chunk carried the digest-labeled path {expected_path:?}; got {:?}",
                rewritten
                    .iter()
                    .map(|chunk| chunk.metadata.path.clone())
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(secret_chunk.metadata.source_type.as_ref(), "docker");
    assert!(
        secret_chunk.data.contains("AKIAIOSFODNN7EXAMPLE"),
        "the digest-labeled chunk must carry the layer's secret payload, got {:?}",
        &*secret_chunk.data
    );
}

/// Rewriting a nested layer file normalizes the relative path under the digest
/// label and strips the git provenance fields while preserving scan offsets.
#[cfg(feature = "docker")]
#[test]
fn rewrite_normalizes_nested_path_under_digest_label_and_clears_git_fields() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layer_root = dir.path().join("layer");
    let nested = layer_root.join("usr").join("local").join("app");
    std::fs::create_dir_all(&nested).expect("mkdir nested");
    let file = nested.join(".env");
    std::fs::write(&file, b"STRIPE=sk_live_x\n").expect("write nested env");

    let digest_label =
        "blobs/sha256/1111111111111111111111111111111111111111111111111111111111111111";
    let chunk = keyhog_core::Chunk {
        data: "STRIPE=sk_live_x\n".into(),
        metadata: keyhog_core::ChunkMetadata {
            source_type: "filesystem/windowed".into(),
            path: Some(file.display().to_string().into()),
            base_offset: 8192,
            base_line: 64,
            commit: Some("deadbeef".into()),
            author: Some("attacker".into()),
            date: Some("2026-07-02".into()),
            size_bytes: Some(17),
            mtime_ns: Some(123),
            decoded_span: Some((3, 9)),
        },
    };

    let rewritten = TestApi
        .docker_rewrite_layer_chunks(vec![Ok(chunk)], "img:1.0", &layer_root, digest_label)
        .expect("nested rewrite must succeed");
    assert_eq!(rewritten.len(), 1);
    let out = &rewritten[0];
    assert_eq!(
        out.metadata.path.as_deref(),
        Some("img:1.0:blobs/sha256/1111111111111111111111111111111111111111111111111111111111111111:usr/local/app/.env"),
        "nested layer path must normalize to forward slashes under the digest label"
    );
    assert_eq!(out.metadata.source_type.as_ref(), "docker");
    assert_eq!(out.metadata.commit, None, "layer rewrite must clear commit");
    assert_eq!(out.metadata.author, None, "layer rewrite must clear author");
    assert_eq!(out.metadata.date, None, "layer rewrite must clear date");
    assert_eq!(
        out.metadata.base_offset, 8192,
        "scan offset must be preserved"
    );
    assert_eq!(out.metadata.base_line, 64, "scan line must be preserved");
    assert_eq!(out.metadata.decoded_span, Some((3, 9)));
}

// ---------------------------------------------------------------------------
// feature-off twins (keep the target compiling + running when docker is off)
// ---------------------------------------------------------------------------

#[cfg(not(feature = "docker"))]
#[test]
fn docker_layer_classify_disabled_without_feature() {
    assert!(
        !cfg!(feature = "docker"),
        "docker layer classification coverage is gated behind the docker feature"
    );
}
