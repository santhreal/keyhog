//! Compressed/archive extraction must cap total decompressed bytes at
//! 4× max_file_size (decompression-bomb guard).
//!
//! The capability refactor (AUD-capability-1/2/3) unified the gzip / tgz / tar
//! paths through `decompress_to_bytes(.., budget)` and `emit_tar_entries`,
//! which made the guard *stronger* — the decompressing reader itself is capped
//! at `budget + 1` bytes so a bomb can never allocate past the ceiling, and an
//! over-budget stream is truncated-and-scanned rather than dropped. This pins
//! the durable shape of that guard (the 4× budget computation and the cap log)
//! rather than a now-stale exact line, so it survives the refactor while still
//! failing loudly if the 4× cap is ever removed.

#[test]
fn compressed_extraction_4x_budget_in_source() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/filesystem/extract.rs"
    ))
    .expect("filesystem/extract.rs");
    assert!(
        src.contains("max_size.saturating_mul(4)"),
        "missing 4x decompression/extraction budget (max_size.saturating_mul(4))"
    );
    assert!(
        src.contains("4x decompressed-size cap") || src.contains("exceeds 4x file cap"),
        "missing the 4x decompression-bomb cap log on the compressed/archive path"
    );
}
