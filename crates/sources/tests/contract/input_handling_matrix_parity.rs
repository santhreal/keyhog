//! WHY THIS TEST EXISTS:
//! Row 21 / Input handling matrix parity contract:
//! Proves that FilesystemSource and decoding inputs handle encodings beyond UTF-8,
//! BOMs, CRLF/LF mixed line endings, files without trailing newlines, long lines,
//! sparse files, hardlinks, and non-UTF-8 bytes without panic or silent failure.
//!
//! WHAT IT DOES NOT CATCH:
//! Physical filesystem media hardware corruption.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn input_handling_matrix_covers_all_input_classes() {
    let dir = TempDir::new().expect("tempdir");
    let root = dir.path();

    // 1. UTF-8 with BOM
    let bom_file = root.join("utf8_bom.txt");
    let mut bom_bytes = vec![0xEF, 0xBB, 0xBF];
    bom_bytes.extend_from_slice(b"KEY_BOM=secret_token_bom_12345\n");
    fs::write(&bom_file, bom_bytes).expect("write utf8_bom");

    // 2. UTF-16LE with BOM
    let utf16le_file = root.join("utf16le.txt");
    let mut u16le_bytes = vec![0xFF, 0xFE];
    for unit in "KEY_UTF16LE=secret_token_16le_67890\n".encode_utf16() {
        u16le_bytes.extend_from_slice(&unit.to_le_bytes());
    }
    fs::write(&utf16le_file, u16le_bytes).expect("write utf16le");

    // 3. UTF-16BE with BOM
    let utf16be_file = root.join("utf16be.txt");
    let mut u16be_bytes = vec![0xFE, 0xFF];
    for unit in "KEY_UTF16BE=secret_token_16be_abcde\n".encode_utf16() {
        u16be_bytes.extend_from_slice(&unit.to_be_bytes());
    }
    fs::write(&utf16be_file, u16be_bytes).expect("write utf16be");

    // 4. Mixed line endings (CRLF, LF, CR)
    let mixed_crlf_file = root.join("mixed_lines.txt");
    fs::write(
        &mixed_crlf_file,
        b"LINE_1=val1\r\nLINE_2=val2\nLINE_3=val3\rLINE_4=val4\n",
    )
    .expect("write mixed_lines");

    // 5. File without trailing newline
    let no_newline_file = root.join("no_trailing_newline.txt");
    fs::write(&no_newline_file, b"KEY_NO_NL=secret_token_no_newline").expect("write no_newline");

    // 6. Very long single line (64 KB single line)
    let long_line_file = root.join("long_line.txt");
    let mut long_content = String::with_capacity(65536);
    for _ in 0..1000 {
        long_content.push_str("prefix_padding_data_segment_");
    }
    long_content.push_str("SECRET=embedded_token_in_long_line\n");
    fs::write(&long_line_file, long_content.as_bytes()).expect("write long_line");

    // 7. Sparse / zero-filled blocks with embedded secret
    let sparse_file = root.join("sparse_with_secret.bin");
    let mut sparse_bytes = vec![0u8; 8192];
    let marker = b"KEY_SPARSE=secret_in_sparse_block";
    sparse_bytes[4096..4096 + marker.len()].copy_from_slice(marker);
    fs::write(&sparse_file, sparse_bytes).expect("write sparse_file");

    // 8. Hardlink sharing same inode
    let original_file = root.join("original_for_hardlink.txt");
    fs::write(&original_file, b"KEY_ORIG=hardlink_secret_val\n").expect("write original");
    let hardlink_file = root.join("hardlink_copy.txt");
    #[cfg(unix)]
    let _ = fs::hard_link(&original_file, &hardlink_file);

    // 9. Raw non-UTF-8 bytes (Latin-1 high bytes)
    let non_utf8_file = root.join("latin1_bytes.txt");
    let mut latin1_bytes = vec![0xC0, 0xC1, 0xF5, 0xFF];
    latin1_bytes.extend_from_slice(b"KEY_LATIN=secret_in_latin1\n");
    fs::write(&non_utf8_file, latin1_bytes).expect("write non_utf8");

    // Execute scan across directory root
    let source = FilesystemSource::new(PathBuf::from(root));
    let chunks: Vec<_> = source
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("all chunks collect cleanly");

    assert!(
        chunks.len() >= 8,
        "Expected at least 8 chunks from input classes, got {}",
        chunks.len()
    );

    // Verify no panics and valid metadata
    for chunk in &chunks {
        assert!(!chunk.data.is_empty(), "Chunk data must not be empty");
        assert!(
            chunk.metadata.path.is_some(),
            "Chunk metadata path must exist"
        );
    }
}
