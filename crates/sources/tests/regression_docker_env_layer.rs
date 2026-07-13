//! Regression coverage for Docker **image ENV / config secret extraction** at the
//! chunk-builder boundary: how the manifest-config and archive-metadata builders
//! turn image config JSON (where a Dockerfile's `ENV`/`ARG` values end up baked)
//! into scannable chunks, and how they fail LOUD on malformed / hostile input.
//!
//! `docker image save` bakes `ENV` declarations into the image config JSON's
//! `config.Env` array; the docker source pretty-serializes that whole JSON into a
//! scan chunk. This file drives angles the sibling `regression_dockerfile_parse.rs`
//! does NOT: fallback config-JSON discovery ordering / extension gating / nested
//! labels, empty-manifest-array + missing-`Config`-field errors, nested config
//! member labels, empty-vec on a bare root, a checksum-valid GitHub PAT surfacing
//! verbatim from an ENV var, and the archive-metadata builder's `index.json` /
//! `oci-layout` single-file labels + its distinct "invalid docker metadata file"
//! error + its pretty-expansion.
//!
//! Distinct from `regression_docker_image_ref.rs` (image-name validation) and
//! `regression_docker_layer_classify.rs` / `docker_oci_classification.rs` (layer
//! blob + media-type verdicts): this file is ENV/config chunk extraction.
//!
//! Private builders are reached only through the crate's `#[doc(hidden)]` testing
//! facade (the `src/docker/**` no-inline-tests contract).

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
fn write_manifest(root: &std::path::Path, config_member: &str) {
    let manifest = format!(r#"[{{"Config":"{config_member}","RepoTags":["r:1"],"Layers":[]}}]"#);
    std::fs::write(root.join("manifest.json"), manifest).expect("write manifest.json");
}

// ---------------------------------------------------------------------------
// ENV surfacing: realistic secret shapes survive the config-chunk round trip
// ---------------------------------------------------------------------------

/// A checksum-valid GitHub classic PAT sitting in a `config.Env` var (the exact
/// shape a leaked `ENV GH_TOKEN=...` produces) must surface VERBATIM in the
/// serialized config chunk (the chunk builder does not mangle or truncate it).
#[cfg(feature = "docker")]
#[test]
fn canonical_github_pat_in_env_surfaces_verbatim() {
    let (_dir, root) = image_root();
    write_manifest(&root, "config.json");
    // Canonical checksum-valid ghp classic PAT (a fabricated body would be
    // dropped by the scanner, but here we only assert chunk SURFACING).
    std::fs::write(
        root.join("config.json"),
        r#"{"config":{"Env":["PATH=/usr/bin","GH_TOKEN=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"]}}"#,
    )
    .expect("write config.json");

    let chunks = TestApi
        .docker_manifest_config_chunks(&root, "img:pat")
        .expect("config chunks must build");
    assert_eq!(chunks.len(), 1, "one config member -> one chunk");
    assert!(
        chunks[0]
            .data
            .contains("GH_TOKEN=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"),
        "the ENV PAT must surface verbatim, got {:?}",
        &*chunks[0].data
    );
}

/// An ENV value packed with URL punctuation (`:` `@` `/` `?` `=`: none of which
/// require JSON escaping) survives serialization byte-for-byte.
#[cfg(feature = "docker")]
#[test]
fn env_value_with_url_punctuation_survives_verbatim() {
    let (_dir, root) = image_root();
    write_manifest(&root, "config.json");
    std::fs::write(
        root.join("config.json"),
        r#"{"config":{"Env":["DSN=postgres://admin:hunter2@db.internal:5432/prod?sslmode=require"]}}"#,
    )
    .expect("write config.json");

    let chunks = TestApi
        .docker_manifest_config_chunks(&root, "img:dsn")
        .expect("config chunks");
    assert_eq!(chunks.len(), 1);
    assert!(
        chunks[0]
            .data
            .contains("DSN=postgres://admin:hunter2@db.internal:5432/prod?sslmode=require"),
        "the punctuated DSN must survive serialization, got {:?}",
        &*chunks[0].data
    );
}

// ---------------------------------------------------------------------------
// fallback config-JSON discovery: ordering, extension gating, nested labels
// ---------------------------------------------------------------------------

/// Two metadata-less stray config JSONs are discovered by the fallback walk and
/// emitted in SORTED order with incrementing `fallback-config[0]` / `[1]` labels,
/// each carrying only its own secret.
#[cfg(feature = "docker")]
#[test]
fn two_stray_configs_get_sorted_incrementing_fallback_labels() {
    let (_dir, root) = image_root();
    // Write out of order to prove config_paths.sort() imposes deterministic order.
    std::fs::write(
        root.join("b-config.json"),
        r#"{"config":{"Env":["SECRET_B=bravo-999"]}}"#,
    )
    .expect("write b");
    std::fs::write(
        root.join("a-config.json"),
        r#"{"config":{"Env":["SECRET_A=alpha-111"]}}"#,
    )
    .expect("write a");

    let chunks = TestApi
        .docker_manifest_config_chunks(&root, "stray:img")
        .expect("fallback chunks must build");
    assert_eq!(chunks.len(), 2, "two stray configs -> two fallback chunks");
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some("stray:img:fallback-config[0]:a-config.json"),
        "sorted order puts a-config.json at index 0"
    );
    assert_eq!(
        chunks[1].metadata.path.as_deref(),
        Some("stray:img:fallback-config[1]:b-config.json"),
        "sorted order puts b-config.json at index 1"
    );
    assert!(
        chunks[0].data.contains("SECRET_A=alpha-111") && !chunks[0].data.contains("SECRET_B"),
        "chunk 0 carries only a's secret, got {:?}",
        &*chunks[0].data
    );
    assert!(
        chunks[1].data.contains("SECRET_B=bravo-999") && !chunks[1].data.contains("SECRET_A"),
        "chunk 1 carries only b's secret, got {:?}",
        &*chunks[1].data
    );
}

/// A non-`.json` stray file (e.g. `secrets.txt`) is NOT treated as a fallback
/// config: only the real `.json` surfaces, and the txt-only secret never appears.
#[cfg(feature = "docker")]
#[test]
fn non_json_stray_file_not_surfaced_as_fallback_config() {
    let (_dir, root) = image_root();
    std::fs::write(
        root.join("secrets.txt"),
        "TXT_ONLY_SECRET=should-not-surface-as-config",
    )
    .expect("write txt");
    std::fs::write(
        root.join("real.json"),
        r#"{"config":{"Env":["REAL_SECRET=json-777"]}}"#,
    )
    .expect("write json");

    let chunks = TestApi
        .docker_manifest_config_chunks(&root, "mix:img")
        .expect("chunks");
    assert_eq!(
        chunks.len(),
        1,
        "only the .json config is a fallback candidate, got {}",
        chunks.len()
    );
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some("mix:img:fallback-config[0]:real.json")
    );
    assert!(
        !chunks[0].data.contains("TXT_ONLY_SECRET"),
        "the .txt file must not be scanned as a config chunk, got {:?}",
        &*chunks[0].data
    );
}

/// The fallback extension check is case-insensitive: an uppercase `Config.JSON`
/// extension still qualifies and surfaces under the fallback label.
#[cfg(feature = "docker")]
#[test]
fn uppercase_json_extension_surfaces_via_fallback() {
    let (_dir, root) = image_root();
    std::fs::write(
        root.join("Config.JSON"),
        r#"{"config":{"Env":["UPPER_SECRET=case-333"]}}"#,
    )
    .expect("write uppercase json");

    let chunks = TestApi
        .docker_manifest_config_chunks(&root, "up:img")
        .expect("chunks");
    assert_eq!(chunks.len(), 1, "uppercase .JSON must qualify as a config");
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some("up:img:fallback-config[0]:Config.JSON")
    );
    assert!(
        chunks[0].data.contains("UPPER_SECRET=case-333"),
        "the uppercase-ext config secret must surface, got {:?}",
        &*chunks[0].data
    );
}

/// A fallback config nested in subdirectories is labeled with FORWARD-SLASH
/// separated path components (`sub/inner/app.json`), not the OS separator or a
/// `..`-prefixed absolute path.
#[cfg(feature = "docker")]
#[test]
fn nested_fallback_config_label_uses_forward_slashes() {
    let (_dir, root) = image_root();
    let nested = root.join("sub").join("inner");
    std::fs::create_dir_all(&nested).expect("mkdir nested");
    std::fs::write(
        nested.join("app.json"),
        r#"{"config":{"Env":["NESTED_SECRET=deep-555"]}}"#,
    )
    .expect("write nested json");

    let chunks = TestApi
        .docker_manifest_config_chunks(&root, "nest:img")
        .expect("chunks");
    assert_eq!(chunks.len(), 1);
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some("nest:img:fallback-config[0]:sub/inner/app.json"),
        "nested fallback label must join components with forward slashes"
    );
    assert!(
        chunks[0].data.contains("NESTED_SECRET=deep-555"),
        "nested config secret must surface, got {:?}",
        &*chunks[0].data
    );
}

/// A bare archive root with no manifest, no OCI layout, and no config JSON yields
/// zero config chunks (a clean empty result, not an error).
#[cfg(feature = "docker")]
#[test]
fn bare_root_yields_zero_config_chunks() {
    let (_dir, root) = image_root();

    let chunks = TestApi
        .docker_manifest_config_chunks(&root, "bare:img")
        .expect("a bare root must build an empty vec, not error");
    assert_eq!(
        chunks.len(),
        0,
        "no manifest / oci / stray config -> zero chunks, got {}",
        chunks.len()
    );
}

// ---------------------------------------------------------------------------
// manifest config member: nested member label + loud failures
// ---------------------------------------------------------------------------

/// A manifest `Config` member sitting in a subdirectory (`blobs/config.json`) is
/// resolved (all path components are Normal) and labeled with the raw member
/// string in the `manifest[idx]:` chunk path.
#[cfg(feature = "docker")]
#[test]
fn nested_config_member_surfaces_with_slashed_label() {
    let (_dir, root) = image_root();
    write_manifest(&root, "blobs/config.json");
    let blobs = root.join("blobs");
    std::fs::create_dir_all(&blobs).expect("mkdir blobs");
    std::fs::write(
        blobs.join("config.json"),
        r#"{"config":{"Env":["BLOB_SECRET=nested-member-222"]}}"#,
    )
    .expect("write blob config");

    let chunks = TestApi
        .docker_manifest_config_chunks(&root, "blob:img")
        .expect("chunks");
    assert_eq!(chunks.len(), 1);
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some("blob:img:manifest[0]:blobs/config.json"),
        "the nested member label carries the raw manifest member string"
    );
    assert!(
        chunks[0].data.contains("BLOB_SECRET=nested-member-222"),
        "the nested-member config secret must surface, got {:?}",
        &*chunks[0].data
    );
}

/// An empty manifest array (`[]`) fails LOUD, the config extraction refuses to
/// silently treat a zero-entry manifest as "nothing to scan".
#[cfg(feature = "docker")]
#[test]
fn empty_manifest_array_fails_loud() {
    let (_dir, root) = image_root();
    std::fs::write(root.join("manifest.json"), b"[]").expect("write empty manifest");

    let err = TestApi
        .docker_manifest_config_chunks(&root, "empty:img")
        .expect_err("a zero-entry manifest must fail loud");
    let msg = err.to_string();
    assert!(
        msg.contains("contains no image entries"),
        "empty-manifest error must name the condition, got {msg:?}"
    );
}

/// A manifest entry missing the required `Config` field fails LOUD with the
/// "invalid docker manifest.json" parse error (never a silently dropped image).
#[cfg(feature = "docker")]
#[test]
fn manifest_missing_config_field_fails_loud() {
    let (_dir, root) = image_root();
    std::fs::write(root.join("manifest.json"), br#"[{"Layers":[]}]"#)
        .expect("write manifest w/o Config");

    let err = TestApi
        .docker_manifest_config_chunks(&root, "nocfg:img")
        .expect_err("a manifest entry with no Config must fail loud");
    let msg = err.to_string();
    assert!(
        msg.contains("invalid docker manifest.json"),
        "missing-Config parse error must be surfaced, got {msg:?}"
    );
}

// ---------------------------------------------------------------------------
// archive metadata builder: single-file labels + distinct errors + pretty expand
// ---------------------------------------------------------------------------

/// With only `index.json` present, the archive-metadata builder emits exactly one
/// chunk labeled `{image}:metadata:index.json`, with `source_type == "docker"`,
/// `size_bytes` == data length, and any embedded secret surfaced.
#[cfg(feature = "docker")]
#[test]
fn index_json_alone_metadata_chunk_carries_exact_label() {
    let (_dir, root) = image_root();
    std::fs::write(
        root.join("index.json"),
        r#"{"manifests":[],"annotations":{"leaked.token":"idx_secret_abc123"}}"#,
    )
    .expect("write index.json");

    let chunks = TestApi
        .docker_archive_metadata_chunks(&root, "idx:img")
        .expect("metadata chunks must build");
    assert_eq!(
        chunks.len(),
        1,
        "only index.json present -> one metadata chunk, got {}",
        chunks.len()
    );
    let chunk = &chunks[0];
    assert_eq!(
        chunk.metadata.path.as_deref(),
        Some("idx:img:metadata:index.json")
    );
    assert_eq!(chunk.metadata.source_type.as_ref(), "docker");
    assert_eq!(chunk.metadata.size_bytes, Some(chunk.data.len() as u64));
    assert!(
        chunk.data.contains("idx_secret_abc123"),
        "a secret embedded in index.json annotations must surface, got {:?}",
        &*chunk.data
    );
}

/// With only `oci-layout` present, the metadata builder emits exactly one chunk
/// labeled `{image}:metadata:oci-layout`.
#[cfg(feature = "docker")]
#[test]
fn oci_layout_alone_metadata_chunk_carries_exact_label() {
    let (_dir, root) = image_root();
    std::fs::write(root.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#)
        .expect("write oci-layout");

    let chunks = TestApi
        .docker_archive_metadata_chunks(&root, "ocl:img")
        .expect("metadata chunks");
    assert_eq!(chunks.len(), 1, "only oci-layout present -> one chunk");
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some("ocl:img:metadata:oci-layout")
    );
}

/// An invalid-JSON metadata file fails LOUD with the metadata-specific "invalid
/// docker metadata file" error (distinct from the config builder's error), and
/// names the offending file.
#[cfg(feature = "docker")]
#[test]
fn invalid_metadata_json_fails_loud_with_metadata_message() {
    let (_dir, root) = image_root();
    std::fs::write(root.join("manifest.json"), b"{ not : valid json ][")
        .expect("write bad manifest.json");

    let err = TestApi
        .docker_archive_metadata_chunks(&root, "badmeta:img")
        .expect_err("unparseable metadata must fail loud");
    let msg = err.to_string();
    assert!(
        msg.contains("invalid docker metadata file") && msg.contains("manifest.json"),
        "metadata parse error must name the failure + file, got {msg:?}"
    );
}

/// The metadata builder pretty-EXPANDS a compact single-line JSON to multi-line
/// indented text (so line-oriented scanning has real lines), and `size_bytes`
/// tracks the expanded length (never the compact input length).
#[cfg(feature = "docker")]
#[test]
fn compact_metadata_json_is_pretty_expanded_to_multiline() {
    let (_dir, root) = image_root();
    let compact = r#"{"manifests":[],"annotations":{"k":"metadata-secret-4444"}}"#;
    std::fs::write(root.join("index.json"), compact).expect("write compact index.json");

    let chunks = TestApi
        .docker_archive_metadata_chunks(&root, "pretty:img")
        .expect("chunks");
    assert_eq!(chunks.len(), 1);
    let data_len = chunks[0].data.len();
    assert!(
        chunks[0].data.contains('\n'),
        "pretty serialization must expand to multiple lines, got {:?}",
        &*chunks[0].data
    );
    assert!(
        data_len > compact.len(),
        "pretty-printed data ({data_len} bytes) must exceed compact input ({} bytes)",
        compact.len()
    );
    assert_eq!(
        chunks[0].metadata.size_bytes,
        Some(data_len as u64),
        "size_bytes must equal the expanded data length"
    );
    assert!(
        chunks[0].data.contains("metadata-secret-4444"),
        "the secret must survive pretty serialization, got {:?}",
        &*chunks[0].data
    );
}

// ---------------------------------------------------------------------------
// feature-off twin (keep the target compiling + running when docker is off)
// ---------------------------------------------------------------------------

#[cfg(not(feature = "docker"))]
#[test]
fn docker_env_layer_disabled_without_feature() {
    assert!(
        !cfg!(feature = "docker"),
        "docker ENV/config extraction coverage is gated behind the docker feature"
    );
}
