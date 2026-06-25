//! Compressed formats with real decoders must not sit in the Tier-B default
//! extension denylist.

fn read(rel: &str) -> String {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

#[test]
fn xz_and_bzip2_route_to_compressed_extractor() {
    let rules = read("../../rules/default_excludes.toml");
    for ext in ["bz2", "xz"] {
        assert!(
            !rules.contains(&format!("\"{ext}\"")),
            "{ext} must not be in rules/default_excludes.toml extensions because it has a structured decompressor"
        );
    }

    let extract = read("src/filesystem/extract.rs");
    assert!(
        extract.contains("compressed::is_compressed_ext(ext)")
            && extract.contains("compressed::extract_compressed_chunks"),
        "process_entry must route compressed extensions through the shared compressed classifier"
    );

    let compressed = read("src/filesystem/extract/compressed.rs");
    for needle in [
        "ext.eq_ignore_ascii_case(\"bz2\")",
        "ext.eq_ignore_ascii_case(\"xz\")",
        "CompressedFormat::Bzip2",
        "CompressedFormat::Xz",
        "new_stream_decoder",
    ] {
        assert!(
            compressed.contains(needle),
            "compressed extractor must retain {needle}"
        );
    }
}
