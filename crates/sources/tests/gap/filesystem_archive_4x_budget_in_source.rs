//! Archive extraction must enforce 4× max_file_size uncompressed budget.

#[test]
fn filesystem_archive_4x_budget_in_source() {
    let archive_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/filesystem/extract/archive.rs"
    ))
    .expect("filesystem/extract/archive.rs");
    assert!(
        archive_src.contains("max_size.saturating_mul(4)"),
        "missing archive 4x zip-bomb budget"
    );
    let extract_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/filesystem/extract.rs"
    ))
    .expect("filesystem/extract.rs");
    assert!(
        extract_src.contains("report_archive_truncation")
            && extract_src.contains("aborting archive extraction")
            && extract_src.contains("archive-bomb guard"),
        "missing shared archive budget truncation reporter"
    );
}
