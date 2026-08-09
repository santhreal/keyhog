//! Regression coverage for modern `docker image save` archives that contain both
//! a complete Docker `manifest.json` and a distribution OCI `index.json` whose
//! multi-platform children are not exported into the local archive.

#[cfg(feature = "docker")]
use keyhog_sources::testing::TestApi;

#[cfg(feature = "docker")]
fn docker_save_root() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("root");
    let blobs = root.join("blobs/sha256");
    std::fs::create_dir_all(&blobs).expect("create blob directory");
    std::fs::write(
        root.join("manifest.json"),
        r#"[{"Config":"blobs/sha256/config","RepoTags":["app:local"],"Layers":["blobs/sha256/layer"]}]"#,
    )
    .expect("write Docker manifest");
    std::fs::write(
        root.join("index.json"),
        r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","size":4096}]}"#,
    )
    .expect("write distribution index");
    std::fs::write(
        blobs.join("config"),
        r#"{"architecture":"amd64","config":{"Env":["KEYHOG_DOCKER_SAVE=complete"]}}"#,
    )
    .expect("write config blob");
    std::fs::write(blobs.join("layer"), b"layer archive fixture").expect("write layer blob");
    (directory, root)
}

/// A complete Docker manifest must own config selection even when the adjacent distribution index references platform manifests that `docker save` did not export.
#[cfg(feature = "docker")]
#[test]
fn docker_manifest_config_wins_over_unexported_distribution_index_children() {
    let (_directory, root) = docker_save_root();

    let chunks = TestApi
        .docker_manifest_config_chunks(&root, "app:local")
        .expect("Docker manifest config remains complete");

    assert_eq!(chunks.len(), 1);
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some("app:local:manifest[0]:blobs/sha256/config")
    );
    assert!(chunks[0].data.contains("KEYHOG_DOCKER_SAVE=complete"));
}

/// A complete Docker manifest must own layer selection instead of turning an intentionally partial distribution index into a false coverage failure.
#[cfg(feature = "docker")]
#[test]
fn docker_manifest_layers_win_over_unexported_distribution_index_children() {
    let (_directory, root) = docker_save_root();

    let layers = TestApi
        .docker_manifest_layer_archives(&root)
        .expect("Docker manifest layers remain complete");

    assert_eq!(layers, vec![root.join("blobs/sha256/layer")]);
}
