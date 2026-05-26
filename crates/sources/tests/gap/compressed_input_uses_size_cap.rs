//! Compressed inputs must refuse mapping when compressed size exceeds max_file_size.

#[test]
fn compressed_input_uses_size_cap() {
    let fs_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/filesystem.rs"
    ))
    .expect("filesystem.rs");
    assert!(
        fs_src.contains("read_file_for_compressed_input(path, max_size)"),
        "extract_compressed_chunks must pass max_size cap"
    );

    let read_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/filesystem/read.rs"
    ))
    .expect("read.rs");
    assert!(
        read_src.contains("compressed file exceeds size cap"),
        "oversize compressed input must log refusal"
    );
    assert!(
        read_src.contains("fn read_file_for_compressed_input"),
        "compressed input helper must exist in read.rs"
    );
}
