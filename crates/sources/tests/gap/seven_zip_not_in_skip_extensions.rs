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
        "ext.eq_ignore_ascii_case(\"7z\")",
        "extract_seven_zip_chunks",
        "mod rar;",
        "ext.eq_ignore_ascii_case(\"rar\")",
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
        "report_archive_truncation",
        "validate_scan_archive_entry_name",
        "EncoderMethod::LZMA",
        // Members route through the shared recursive dispatcher so a tar/zip/gz
        // nested inside the 7z is recursed, not leaf-scanned (Law 10). The
        // `filesystem/archive[-binary]` source types now live on that shared
        // leaf, asserted against extract.rs below.
        "emit_archive_member",
    ] {
        assert!(
            seven_zip.contains(needle),
            "7z extractor must retain {needle}"
        );
    }
    assert!(
        !seven_zip.contains("SourceSkipEvent::ArchiveTruncated"),
        "7z archive truncation must use the shared truncation reporter, not a format-local counter mutation"
    );

    // The canonical archive-member leaf (shared by every container extractor)
    // stamps the archive source types. Pinning them here keeps the contract
    // even though each extractor now routes through `emit_archive_member`.
    for needle in ["filesystem/archive", "filesystem/archive-binary"] {
        assert!(
            extract.contains(needle),
            "the shared archive-member dispatcher must stamp {needle}"
        );
    }

    let rar = read("src/filesystem/extract/rar.rs");
    for needle in [
        "ArchiveReader::read",
        "read_file_for_compressed_input",
        "SourceSkipEvent::Unreadable",
        "report_archive_truncation",
        "validate_scan_archive_entry_name",
        // RAR members route through the same shared recursive dispatcher (a
        // tar/zip/gz nested inside the RAR is recursed, not leaf-scanned).
        "emit_archive_member",
    ] {
        assert!(rar.contains(needle), "RAR extractor must retain {needle}");
    }
    assert!(
        !rar.contains("SourceSkipEvent::ArchiveTruncated"),
        "RAR archive truncation must use the shared truncation reporter, not a format-local counter mutation"
    );
}
