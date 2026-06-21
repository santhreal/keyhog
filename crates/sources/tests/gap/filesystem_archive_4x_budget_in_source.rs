//! Archive extraction must enforce 4× max_file_size uncompressed budget.

#[test]
fn filesystem_archive_4x_budget_in_source() {
    let extract_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/filesystem/extract.rs"
    ))
    .expect("filesystem/extract.rs");
    assert!(
        extract_src.contains("const UNCAPPED_ARCHIVE_BUDGET: u64 = 1024 * 1024 * 1024"),
        "missing single uncapped archive budget owner"
    );
    assert!(
        extract_src.contains("fn extraction_total_budget(max_size: u64) -> u64")
            && extract_src.contains("max_size.saturating_mul(4)"),
        "missing shared archive 4x zip-bomb budget helper"
    );
    assert!(
        extract_src.contains("report_archive_truncation")
            && extract_src.contains("aborting archive extraction")
            && extract_src.contains("archive-bomb guard"),
        "missing shared archive budget truncation reporter"
    );

    for relative in [
        "/src/filesystem/extract/archive.rs",
        "/src/filesystem/extract/seven_zip.rs",
        "/src/filesystem/extract/rar.rs",
        "/src/filesystem/extract/compressed.rs",
    ] {
        let src = std::fs::read_to_string(format!("{}{}", env!("CARGO_MANIFEST_DIR"), relative))
            .unwrap_or_else(|error| panic!("failed to read {relative}: {error}"));
        assert!(
            !src.contains("const UNCAPPED_ARCHIVE_BUDGET") && !src.contains("1024 * 1024 * 1024"),
            "{relative} must import the shared uncapped extraction budget, not define its own"
        );
        assert!(
            src.contains("extraction_total_budget"),
            "{relative} must route aggregate archive/decode budget through the shared helper"
        );
    }
}
