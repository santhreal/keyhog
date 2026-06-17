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
    for ext in ["bz2", "xz"] {
        assert!(
            extract.contains(&format!("ext == \"{ext}\"")),
            "process_entry must route .{ext} to extract_compressed_chunks"
        );
    }

    let compressed = read("src/filesystem/extract/compressed.rs");
    for needle in [
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
