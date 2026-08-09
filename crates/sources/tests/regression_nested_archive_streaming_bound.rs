//! Nested archive acquisition must prefer streaming / bounded extraction over
//! retaining every decompressed tarball image in memory.
//!
//! Pass requirements (perf-5 / KH-2140..KH-2149):
//! - large nested inputs do not explode peak RSS by materializing every layer
//! - extensionless / nested compressed members stay findable
//! - bomb budgets stay fail-closed (unchanged caps)
//!
//! These pins are structural on the filesystem compressed/tar path: the
//! streaming helpers must run before `decompress_to_bytes`, and TeX provenance
//! gating must inspect tar HEADER names only (never payload bytes that can
//! false-trigger a second full member pass).

fn read_src(rel: &str) -> String {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

#[test]
fn compressed_tar_attempts_streaming_before_full_decompress() {
    let src = read_src("src/filesystem/extract/compressed.rs");
    let start = src
        .find("pub(super) fn extract_compressed_chunks")
        .expect("extract_compressed_chunks");
    let body = &src[start..];
    let stream = body
        .find("try_emit_streaming_compressed_tar")
        .expect("streaming compressed→tar helper must be called from extract_compressed_chunks");
    let full = body
        .find("decompress_to_bytes")
        .expect("buffered decompress fallback must remain for non-tar streams");
    assert!(
        stream < full,
        "streaming tar extraction must run before decompress_to_bytes so a .tar.gz \
         is not forced through a full decompressed image first"
    );
    assert!(
        src.contains("try_emit_streaming_nested_tar"),
        "nested compressed tar members must also prefer the streaming path"
    );
    assert!(
        src.contains("path_looks_like_compressed_tar"),
        "bundle.tar.gz must be recognized as a tarball even though Path::extension is only gz"
    );
    assert!(
        src.contains("BudgetLimitedReader"),
        "streaming compressed-tar must wrap the decoder in a decompressed-byte ceiling"
    );
}

#[test]
fn tar_tex_gate_uses_header_names_not_payload_bytes() {
    let tex = read_src("src/filesystem/extract/tex_package.rs");
    let compressed = read_src("src/filesystem/extract/compressed.rs");
    assert!(
        tex.contains("pub(super) fn tar_header_names_might_need_tex"),
        "header-name TeX gate must exist"
    );
    let analyze = compressed
        .find("fn analyze_tex_package")
        .expect("analyze_tex_package");
    let analyze_body = &compressed[analyze..];
    let header_gate = analyze_body
        .find("tar_header_names_might_need_tex")
        .expect("analyze_tex_package must gate on header names");
    let payload_gate = analyze_body.find("bytes_might_contain_source_extension");
    assert!(
        payload_gate.is_none() || payload_gate.unwrap() > header_gate + 200,
        "analyze_tex_package must not prefer the payload-byte .tex scan that false-triggers \
         on nested compressed members"
    );
}

#[test]
fn documented_nested_archive_rss_bound_is_present() {
    // Operator-visible contract: nested archive scans stream members and do not
    // keep every decompressed layer resident. The bound lives in the archives
    // chapter so a future rewrite cannot silently reintroduce full-image retain
    // without updating the documented promise.
    let docs = std::fs::read_to_string(format!(
        "{}/../../docs/src/source-archives.md",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("docs/src/source-archives.md");
    assert!(
        docs.contains("streaming") && docs.contains("resident"),
        "source-archives.md must document streaming nested-archive extraction and the RSS bound"
    );
}
