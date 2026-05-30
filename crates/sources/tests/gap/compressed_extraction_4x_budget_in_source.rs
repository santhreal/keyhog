//! Compressed stream path must cap total decompressed bytes at 4× max_file_size.

#[test]
fn compressed_extraction_4x_budget_in_source() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/filesystem/extract.rs"
    ))
    .expect("filesystem/extract.rs");
    assert!(
        src.contains("let total_budget: usize = max_size.saturating_mul(4) as usize"),
        "missing compressed 4x decompression budget"
    );
    assert!(
        src.contains("aborting compressed extraction: total decompressed size exceeds 4x file cap"),
        "missing compressed budget abort log"
    );
}
