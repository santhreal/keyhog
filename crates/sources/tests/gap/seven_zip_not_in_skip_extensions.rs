//! 7z/RAR have real extractors and must not sit in the Tier-B default
//! extension denylist.

fn read(rel: &str) -> String {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

#[test]
fn seven_zip_routes_to_dedicated_extractor() {
    let rules = read("../../rules/default_excludes.toml");
    assert!(
        !rules.contains("\"7z\""),
        "7z must not be in rules/default_excludes.toml extensions because it has a structured extractor"
    );
    assert!(
        !rules.contains("\"rar\""),
        "rar must not be in rules/default_excludes.toml extensions because it has a structured extractor"
    );

    let extract = read("src/filesystem/extract.rs");
    for needle in [
        "mod seven_zip;",
        "ext == \"7z\"",
        "extract_seven_zip_chunks",
        "mod rar;",
        "ext == \"rar\"",
        "extract_rar_chunks",
    ] {
        assert!(
            extract.contains(needle),
            "process_entry must retain {needle}"
        );
    }

    let seven_zip = read("src/filesystem/extract/seven_zip.rs");
    for needle in [
        "ArchiveReader::new",
        "read_file_for_compressed_input",
        "SourceSkipEvent::Unreadable",
        "SourceSkipEvent::ArchiveTruncated",
        "EncoderMethod::LZMA",
        "filesystem/archive",
        "filesystem/archive-binary",
    ] {
        assert!(
            seven_zip.contains(needle),
            "7z extractor must retain {needle}"
        );
    }

    let rar = read("src/filesystem/extract/rar.rs");
    for needle in [
        "ArchiveReader::read",
        "read_file_for_compressed_input",
        "SourceSkipEvent::Unreadable",
        "SourceSkipEvent::ArchiveTruncated",
        "validate_scan_archive_entry_name",
        "chunk_from_archive_content",
    ] {
        assert!(rar.contains(needle), "RAR extractor must retain {needle}");
    }
}
