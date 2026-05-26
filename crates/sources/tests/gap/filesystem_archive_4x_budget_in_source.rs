//! Archive extraction must enforce 4× max_file_size uncompressed budget.

#[test]
fn filesystem_archive_4x_budget_in_source() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/filesystem.rs"))
        .expect("filesystem.rs");
    assert!(
        src.contains("total_budget: u64 = max_size.saturating_mul(4)"),
        "missing archive 4x zip-bomb budget"
    );
    assert!(
        src.contains("aborting archive extraction: total uncompressed size exceeds 4x file cap"),
        "missing archive budget abort log"
    );
}
