//! Regression coverage for how a Docker **image config** surfaces the values a
//! Dockerfile's `ENV`/`ARG`/`RUN` instructions leave behind for scanning.
//!
//! A Dockerfile is never scanned directly; `docker image save` bakes its `ENV`
//! declarations into the image config JSON's `config.Env` array and the build
//! commands (including leaked build `ARG`s) into `history[].created_by`. The
//! docker source pretty-serializes that whole config JSON into a scannable chunk.
//! This file proves an `ENV SECRET=<value>` line surfaces verbatim with exact
//! chunk metadata, that a build-arg leak in image history surfaces, that the
//! metadata-file (`manifest.json`/`index.json`/`oci-layout`) chunks carry exact
//! labels, and that malformed / unsafe references fail loud rather than silently
//! dropping the config.
//!
//! Distinct from `regression_docker_layer_classify.rs` (layer-blob classification
//! + digest labels) and `docker_oci_classification.rs` (media-type verdicts):
//! this file drives the manifest-config / archive-metadata chunk builders that
//! turn image config JSON into scan chunks.
//!
//! The private builders are reached only through the crate's `#[doc(hidden)]`
//! testing facade (the `src/docker/**` no-inline-tests contract).

#[cfg(feature = "docker")]
use keyhog_sources::testing::{SourceTestApi, TestApi};

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

/// A tempdir plus its `root/` archive directory, mirroring the layout the docker
/// source unpacks a saved image into.
#[cfg(feature = "docker")]
fn image_root() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    std::fs::create_dir_all(&root).expect("mkdir root");
    (dir, root)
}

/// Write a Docker archive `manifest.json` referencing a single config member.
#[cfg(feature = "docker")]
fn write_manifest(root: &std::path::Path, config_member: &str, repo_tag: &str) {
    let manifest =
        format!(r#"[{{"Config":"{config_member}","RepoTags":["{repo_tag}"],"Layers":[]}}]"#);
    std::fs::write(root.join("manifest.json"), manifest).expect("write manifest.json");
}

// ---------------------------------------------------------------------------
// ENV: the Dockerfile `ENV SECRET=<value>` line surfaces with exact metadata
// ---------------------------------------------------------------------------

/// A Dockerfile `ENV API_SECRET=<value>` lands in the image config `config.Env`
/// array; the manifest-config chunk builder must surface it in exactly one chunk
/// carrying the `{image}:manifest[{idx}]:{config}` path, `source_type == "docker"`,
/// and `size_bytes` equal to the serialized data length.
#[cfg(feature = "docker")]
#[test]
fn env_secret_line_surfaces_with_exact_chunk_metadata() {
    let (_dir, root) = image_root();
    write_manifest(&root, "config.json", "myrepo/app:v1");
    // `config.Env` is precisely where `ENV API_SECRET=...` ends up after build.
    std::fs::write(
        root.join("config.json"),
        r#"{"architecture":"amd64","config":{"Env":["PATH=/usr/local/bin","API_SECRET=s3cr3t-value-xyz789","DATABASE_URL=postgres://u:p@db/app"]}}"#,
    )
    .expect("write config.json");

    let chunks = TestApi
        .docker_manifest_config_chunks(&root, "keyhog:test")
        .expect("manifest config chunks must build");

    assert_eq!(
        chunks.len(),
        1,
        "one manifest entry with one config member must produce exactly one chunk, got {}",
        chunks.len()
    );
    let chunk = &chunks[0];
    assert_eq!(
        chunk.metadata.path.as_deref(),
        Some("keyhog:test:manifest[0]:config.json"),
        "config chunk must carry the image:manifest[idx]:config label"
    );
    assert_eq!(chunk.metadata.source_type.as_ref(), "docker");
    assert!(
        chunk.data.contains("API_SECRET=s3cr3t-value-xyz789"),
        "the ENV secret must surface verbatim in the serialized config chunk, got {:?}",
        &*chunk.data
    );
    assert!(
        chunk.data.contains("DATABASE_URL=postgres://u:p@db/app"),
        "every config.Env entry must surface, got {:?}",
        &*chunk.data
    );
    assert_eq!(
        chunk.metadata.size_bytes,
        Some(chunk.data.len() as u64),
        "size_bytes must equal the serialized data length"
    );
}

/// The manifest-config chunk carries no git provenance and zeroed scan offsets:
/// an image config is a whole-file chunk, not a windowed slice of a commit.
#[cfg(feature = "docker")]
#[test]
fn config_chunk_clears_provenance_and_zeroes_offsets() {
    let (_dir, root) = image_root();
    write_manifest(&root, "config.json", "img:latest");
    std::fs::write(
        root.join("config.json"),
        r#"{"config":{"Env":["TOKEN=abc123"]}}"#,
    )
    .expect("write config.json");

    let chunks = TestApi
        .docker_manifest_config_chunks(&root, "img:latest")
        .expect("chunks");
    assert_eq!(chunks.len(), 1);
    let meta = &chunks[0].metadata;
    assert_eq!(meta.base_offset, 0, "config chunk base_offset must be zero");
    assert_eq!(meta.base_line, 0, "config chunk base_line must be zero");
    assert_eq!(meta.commit, None, "config chunk must have no commit");
    assert_eq!(meta.author, None, "config chunk must have no author");
    assert_eq!(meta.date, None, "config chunk must have no date");
    assert_eq!(meta.mtime_ns, None, "config chunk must have no mtime");
    assert_eq!(
        meta.decoded_span, None,
        "config chunk must have no decode span"
    );
}

/// A build-time `ARG` that gets echoed into a `RUN` step leaks into the image
/// config `history[].created_by` string; the config chunk must surface it (the
/// classic "build secret baked into an image layer command" leak).
#[cfg(feature = "docker")]
#[test]
fn leaked_build_arg_in_history_created_by_surfaces() {
    let (_dir, root) = image_root();
    write_manifest(&root, "config.json", "img:build");
    std::fs::write(
        root.join("config.json"),
        r#"{"config":{"Env":["PATH=/usr/bin"]},"history":[{"created_by":"/bin/sh -c #(nop) ARG BUILD_TOKEN"},{"created_by":"|1 BUILD_TOKEN=ghp_leakedbuildarg123 /bin/sh -c echo $BUILD_TOKEN > /root/.netrc"}]}"#,
    )
    .expect("write config.json");

    let chunks = TestApi
        .docker_manifest_config_chunks(&root, "img:build")
        .expect("chunks");
    assert_eq!(chunks.len(), 1);
    assert!(
        chunks[0].data.contains("BUILD_TOKEN=ghp_leakedbuildarg123"),
        "a build ARG leaked into history.created_by must surface, got {:?}",
        &*chunks[0].data
    );
}

/// Pretty-serialization: a compact single-line config JSON is expanded to
/// multi-line, indented text (so line-oriented scanning has real lines), and
/// `size_bytes` tracks the expanded length — never the compact input length.
#[cfg(feature = "docker")]
#[test]
fn compact_config_json_is_pretty_expanded_to_multiline() {
    let (_dir, root) = image_root();
    write_manifest(&root, "config.json", "img:compact");
    let compact = r#"{"config":{"Env":["K=verylongsecretvalue1234567890"]}}"#;
    std::fs::write(root.join("config.json"), compact).expect("write config.json");

    let chunks = TestApi
        .docker_manifest_config_chunks(&root, "img:compact")
        .expect("chunks");
    assert_eq!(chunks.len(), 1);
    let data_len = chunks[0].data.len();
    assert!(
        chunks[0].data.contains('\n'),
        "pretty serialization must expand the compact config to multiple lines, got {:?}",
        &*chunks[0].data
    );
    assert!(
        data_len > compact.len(),
        "pretty-printed data ({data_len} bytes) must be longer than the compact input ({} bytes)",
        compact.len()
    );
    assert!(
        chunks[0].data.contains("K=verylongsecretvalue1234567890"),
        "the secret value must survive pretty serialization, got {:?}",
        &*chunks[0].data
    );
}

// ---------------------------------------------------------------------------
// multiple manifest entries: incrementing index labels
// ---------------------------------------------------------------------------

/// Two manifest entries each pointing at their own config produce two chunks with
/// incrementing `manifest[0]` / `manifest[1]` index labels, each carrying only
/// its own config's secret.
#[cfg(feature = "docker")]
#[test]
fn multiple_manifest_entries_get_incrementing_index_labels() {
    let (_dir, root) = image_root();
    let manifest = r#"[{"Config":"config-a.json","RepoTags":["a:1"],"Layers":[]},{"Config":"config-b.json","RepoTags":["b:1"],"Layers":[]}]"#;
    std::fs::write(root.join("manifest.json"), manifest).expect("write manifest.json");
    std::fs::write(
        root.join("config-a.json"),
        r#"{"config":{"Env":["SECRET_A=alpha-token-aaa"]}}"#,
    )
    .expect("write config-a");
    std::fs::write(
        root.join("config-b.json"),
        r#"{"config":{"Env":["SECRET_B=bravo-token-bbb"]}}"#,
    )
    .expect("write config-b");

    let chunks = TestApi
        .docker_manifest_config_chunks(&root, "multi:img")
        .expect("chunks");
    assert_eq!(chunks.len(), 2, "two entries must produce two chunks");
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some("multi:img:manifest[0]:config-a.json")
    );
    assert_eq!(
        chunks[1].metadata.path.as_deref(),
        Some("multi:img:manifest[1]:config-b.json")
    );
    assert!(
        chunks[0].data.contains("SECRET_A=alpha-token-aaa") && !chunks[0].data.contains("SECRET_B"),
        "entry 0 must carry only config-a's secret, got {:?}",
        &*chunks[0].data
    );
    assert!(
        chunks[1].data.contains("SECRET_B=bravo-token-bbb") && !chunks[1].data.contains("SECRET_A"),
        "entry 1 must carry only config-b's secret, got {:?}",
        &*chunks[1].data
    );
}

// ---------------------------------------------------------------------------
// fallback discovery: metadata-less config JSON still surfaces
// ---------------------------------------------------------------------------

/// With no `manifest.json` and no OCI layout, a stray config `*.json` is still
/// discovered by fallback walk and surfaces under a `fallback-config[idx]` label.
#[cfg(feature = "docker")]
#[test]
fn metadata_less_config_json_surfaces_via_fallback_label() {
    let (_dir, root) = image_root();
    std::fs::write(
        root.join("app-config.json"),
        r#"{"config":{"Env":["FALLBACK_SECRET=orphan-token-999"]}}"#,
    )
    .expect("write app-config.json");

    let chunks = TestApi
        .docker_manifest_config_chunks(&root, "orphan:img")
        .expect("fallback config chunks must build");
    assert_eq!(
        chunks.len(),
        1,
        "the lone stray config json must surface exactly once via fallback"
    );
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some("orphan:img:fallback-config[0]:app-config.json"),
        "metadata-less config must carry the fallback-config label"
    );
    assert!(
        chunks[0].data.contains("FALLBACK_SECRET=orphan-token-999"),
        "fallback config secret must surface, got {:?}",
        &*chunks[0].data
    );
}

// ---------------------------------------------------------------------------
// negative twins: malformed / unsafe references fail LOUD (never silent-drop)
// ---------------------------------------------------------------------------

/// A manifest that references a config member with no backing file fails loud,
/// naming the missing config — the config is never silently dropped.
#[cfg(feature = "docker")]
#[test]
fn manifest_referencing_absent_config_fails_loud() {
    let (_dir, root) = image_root();
    write_manifest(&root, "config-missing.json", "img:1");
    // deliberately do NOT create config-missing.json

    let err = TestApi
        .docker_manifest_config_chunks(&root, "img:1")
        .expect_err("a manifest referencing an absent config must fail loud");
    let msg = err.to_string();
    assert!(
        msg.contains("references missing config") && msg.contains("config-missing.json"),
        "missing-config error must name the absent config, got {msg:?}"
    );
}

/// A config file that is not valid JSON fails loud with an "invalid docker image
/// config" error rather than surfacing an empty or partial chunk.
#[cfg(feature = "docker")]
#[test]
fn invalid_json_config_fails_loud() {
    let (_dir, root) = image_root();
    write_manifest(&root, "config.json", "img:2");
    std::fs::write(root.join("config.json"), b"{ this is : not json ][")
        .expect("write bad config.json");

    let err = TestApi
        .docker_manifest_config_chunks(&root, "img:2")
        .expect_err("an unparseable config must fail loud");
    let msg = err.to_string();
    assert!(
        msg.contains("invalid docker image config"),
        "invalid config error must name the failure, got {msg:?}"
    );
}

/// A manifest whose config member escapes the archive root via `..` is rejected
/// as an unsafe path before any file access — path traversal is refused loud.
#[cfg(feature = "docker")]
#[test]
fn config_member_path_traversal_rejected_loud() {
    let (_dir, root) = image_root();
    write_manifest(&root, "../escape.json", "img:3");

    let err = TestApi
        .docker_manifest_config_chunks(&root, "img:3")
        .expect_err("a traversal config path must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("unsafe config path") && msg.contains("../escape.json"),
        "traversal rejection must name the unsafe path, got {msg:?}"
    );
}

/// An absolute config member path is refused the same way (no reading of
/// `/etc/passwd` and friends off the manifest's say-so).
#[cfg(feature = "docker")]
#[test]
fn absolute_config_member_path_rejected_loud() {
    let (_dir, root) = image_root();
    write_manifest(&root, "/etc/passwd", "img:4");

    let err = TestApi
        .docker_manifest_config_chunks(&root, "img:4")
        .expect_err("an absolute config path must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("unsafe config path") && msg.contains("/etc/passwd"),
        "absolute-path rejection must name the unsafe path, got {msg:?}"
    );
}

// ---------------------------------------------------------------------------
// archive metadata chunks: manifest.json / index.json / oci-layout labels
// ---------------------------------------------------------------------------

/// The archive metadata builder serializes `manifest.json` into a chunk labeled
/// `{image}:metadata:manifest.json` with `source_type == "docker"` and
/// `size_bytes` equal to the data length.
#[cfg(feature = "docker")]
#[test]
fn manifest_json_metadata_chunk_carries_exact_label() {
    let (_dir, root) = image_root();
    write_manifest(&root, "config.json", "myrepo/app:v1.2.3");

    let chunks = TestApi
        .docker_archive_metadata_chunks(&root, "keyhog:test")
        .expect("archive metadata chunks must build");
    assert_eq!(
        chunks.len(),
        1,
        "only manifest.json is present, so exactly one metadata chunk is expected"
    );
    let chunk = &chunks[0];
    assert_eq!(
        chunk.metadata.path.as_deref(),
        Some("keyhog:test:metadata:manifest.json")
    );
    assert_eq!(chunk.metadata.source_type.as_ref(), "docker");
    assert_eq!(chunk.metadata.size_bytes, Some(chunk.data.len() as u64));
    assert!(
        chunk.data.contains("myrepo/app:v1.2.3"),
        "the metadata chunk must carry the manifest's RepoTag, got {:?}",
        &*chunk.data
    );
}

/// All three recognized root metadata files present -> three chunks emitted in
/// the fixed `manifest.json`, `index.json`, `oci-layout` order.
#[cfg(feature = "docker")]
#[test]
fn all_three_root_metadata_files_emit_ordered_chunks() {
    let (_dir, root) = image_root();
    write_manifest(&root, "config.json", "img:meta");
    std::fs::write(root.join("index.json"), r#"{"manifests":[]}"#).expect("write index.json");
    std::fs::write(root.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#)
        .expect("write oci-layout");

    let chunks = TestApi
        .docker_archive_metadata_chunks(&root, "img:meta")
        .expect("chunks");
    let labels: Vec<Option<&str>> = chunks
        .iter()
        .map(|chunk| chunk.metadata.path.as_deref())
        .collect();
    assert_eq!(
        labels,
        vec![
            Some("img:meta:metadata:manifest.json"),
            Some("img:meta:metadata:index.json"),
            Some("img:meta:metadata:oci-layout"),
        ],
        "metadata chunks must follow the fixed root-file order"
    );
}

/// An archive root with no recognized metadata files yields zero metadata chunks
/// (a clean empty result, not an error).
#[cfg(feature = "docker")]
#[test]
fn empty_root_yields_zero_metadata_chunks() {
    let (_dir, root) = image_root();

    let chunks = TestApi
        .docker_archive_metadata_chunks(&root, "img:empty")
        .expect("empty root must still build (an empty vec)");
    assert_eq!(
        chunks.len(),
        0,
        "no metadata files present must yield zero chunks, got {}",
        chunks.len()
    );
}

/// A metadata path that exists but is a directory (not a regular file) fails
/// loud rather than being silently skipped — a symlink/dir decoy cannot hide the
/// metadata from the scan.
#[cfg(feature = "docker")]
#[test]
fn metadata_path_that_is_a_directory_fails_loud() {
    let (_dir, root) = image_root();
    std::fs::create_dir(root.join("manifest.json")).expect("create manifest.json as a directory");

    let err = TestApi
        .docker_archive_metadata_chunks(&root, "img:dir")
        .expect_err("a directory in place of manifest.json must fail loud");
    let msg = err.to_string();
    assert!(
        msg.contains("is not a regular file"),
        "non-regular metadata file must fail loud, got {msg:?}"
    );
}

// ---------------------------------------------------------------------------
// feature-off twin (keep the target compiling + running when docker is off)
// ---------------------------------------------------------------------------

#[cfg(not(feature = "docker"))]
#[test]
fn dockerfile_parse_disabled_without_feature() {
    assert!(
        !cfg!(feature = "docker"),
        "docker image-config parse coverage is gated behind the docker feature"
    );
}
