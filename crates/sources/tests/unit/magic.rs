//! Unit tests for the byte-signature classifiers in `crates/sources/src/magic.rs`.
//!
//! The oracle is the published file-format signatures embedded in the module,
//! plus boundary cases (empty, too short, prefix-adjacent bytes) that must fail
//! closed rather than panic or misclassify.

use keyhog_sources::testing::*;

/// Every unambiguous binary prefix in the fleet catalog must be recognized.
#[test]
fn has_unambiguous_binary_prefix_matches_all_catalog_signatures() {
    let cases: &[(&[u8], &str)] = &[
        (b"%PDF-1.4", "pdf"),
        (b"PK\x03\x04", "zip local"),
        (b"\x89PNG\r\n\x1a\n", "png"),
        (b"\xD0\xCF\x11\xE0", "ole compound"),
        (b"\x7fELF", "elf"),
        (b"\xfe\xed\xfa\xce", "mach-o 32"),
        (b"\xfe\xed\xfa\xcf", "mach-o 64"),
        (b"\xcf\xfa\xed\xfe", "mach-o 64 reversed"),
        (b"\xca\xfe\xba\xbe", "java class / universal mach-o"),
        (b"\x1f\x8b", "gzip"),
        (b"\x28\xb5\x2f\xfd", "zstd"),
        (b"\xfd7zXZ\x00", "xz"),
        (b"7z\xbc\xaf\x27\x1c", "7z"),
        (b"Rar!\x1a\x07", "rar"),
        (b"GIF87a", "gif87a"),
        (b"GIF89a", "gif89a"),
        (b"\xff\xd8\xff", "jpeg"),
        (b"\x00\x00\x01\x00", "ico"),
        (b"OggS", "ogg"),
        (b"fLaC", "flac"),
        (b"\x00asm", "wasm"),
        (b"!<arch>\n", "ar"),
    ];
    for (bytes, label) in cases {
        assert!(
            has_unambiguous_binary_prefix_for_test(bytes),
            "{label} signature must be classified as binary"
        );
    }
}

/// Plain text and empty buffers must not match a binary prefix.
#[test]
fn has_unambiguous_binary_prefix_rejects_text_and_empty_and_short() {
    let negatives: &[(&[u8], &str)] = &[
        (b"hello world", "ascii text"),
        (b"", "empty"),
        (b"PK", "zip prefix fragment"),
        (b"PK\x01", "zip fragment"),
        (b"%PDF", "pdf without hyphen"),
        (b"\x89PNG", "png without line endings"),
        (b"\x7fEL", "elf fragment"),
    ];
    for (bytes, label) in negatives {
        assert!(
            !has_unambiguous_binary_prefix_for_test(bytes),
            "{label} must not be classified as binary"
        );
    }
}

#[test]
fn starts_with_python_pickle_protocol2_matches_only_protocol2_magic() {
    assert!(starts_with_python_pickle_protocol2_for_test(b"\x80\x02foo"));
    assert!(!starts_with_python_pickle_protocol2_for_test(
        b"\x80\x01foo"
    ));
    assert!(!starts_with_python_pickle_protocol2_for_test(b"\x80"));
    assert!(!starts_with_python_pickle_protocol2_for_test(b""));
}

#[test]
fn starts_with_pdf_matches_pdf_prefix_and_rejects_others() {
    assert!(starts_with_pdf_for_test(b"%PDF-1.4"));
    assert!(starts_with_pdf_for_test(b"%PDF-"));
    assert!(!starts_with_pdf_for_test(b"%PDF"));
    assert!(!starts_with_pdf_for_test(b"PDF-1.4"));
    assert!(!starts_with_pdf_for_test(b""));
}

#[test]
fn starts_with_zip_container_prefix_matches_local_and_end_of_central() {
    assert!(starts_with_zip_container_prefix_for_test(b"PK\x03\x04"));
    assert!(starts_with_zip_container_prefix_for_test(b"PK\x05\x06"));
    assert!(!starts_with_zip_container_prefix_for_test(b"PK\x01\x02"));
    assert!(!starts_with_zip_container_prefix_for_test(b"PK_is_text"));
    assert!(!starts_with_zip_container_prefix_for_test(b""));
}

#[test]
fn has_bmp_header_matches_bmp_structure_and_rejects_short_or_corrupt() {
    // BMP: 'BM' + 4-byte file size + 4 reserved zero bytes + 4-byte offset >= 14
    let valid = b"BM\x00\x00\x00\x00\x00\x00\x00\x00\x1e\x00\x00\x00";
    assert!(has_bmp_header_for_test(valid));

    let bad_offset = b"BM\x00\x00\x00\x00\x00\x00\x00\x00\x0d\x00\x00\x00";
    assert!(
        !has_bmp_header_for_test(bad_offset),
        "offset < 14 must reject"
    );

    assert!(!has_bmp_header_for_test(b"BM"), "too short must reject");
    assert!(
        !has_bmp_header_for_test(b"NB\x00\x00\x00\x00\x00\x00\x00\x00\x1e\x00\x00\x00"),
        "wrong signature"
    );
    assert!(!has_bmp_header_for_test(b"BMnotzero"), "reserved non-zero");
}

#[test]
fn has_pe_header_matches_mz_pe_layout_and_rejects_short_or_corrupt() {
    let mut pe = vec![0u8; 128];
    pe[0..2].copy_from_slice(b"MZ");
    pe[60..64].copy_from_slice(&60u32.to_le_bytes());
    pe[60..64].copy_from_slice(&64u32.to_le_bytes());
    pe[64..68].copy_from_slice(b"PE\x00\x00");
    assert!(has_pe_header_for_test(&pe));

    pe[64..68].copy_from_slice(b"PE\x00\x01");
    assert!(!has_pe_header_for_test(&pe), "wrong PE signature");

    pe[60..64].copy_from_slice(&255u32.to_le_bytes());
    assert!(!has_pe_header_for_test(&pe), "PE offset out of bounds");

    assert!(!has_pe_header_for_test(b"MZ"), "too short");
    assert!(!has_pe_header_for_test(b"PE\x00\x00"), "missing MZ");
}

#[test]
fn has_bzip2_header_matches_bz_digit_prefix() {
    assert!(has_bzip2_header_for_test(b"BZh9"));
    assert!(has_bzip2_header_for_test(b"BZh1"));
    assert!(
        !has_bzip2_header_for_test(b"BZh0"),
        "0 is not a valid block size digit"
    );
    assert!(!has_bzip2_header_for_test(b"BZh"), "missing digit");
    assert!(!has_bzip2_header_for_test(b"BZx1"), "wrong magic");
    assert!(!has_bzip2_header_for_test(b""));
}

#[cfg(feature = "docker")]
#[test]
fn starts_with_gzip_matches_gzip_magic() {
    assert!(starts_with_gzip_for_test(b"\x1f\x8b\x08"));
    assert!(starts_with_gzip_for_test(b"\x1f\x8b"));
    assert!(!starts_with_gzip_for_test(b"\x1f"));
    assert!(!starts_with_gzip_for_test(b""));
}

#[cfg(feature = "docker")]
#[test]
fn starts_with_zstd_frame_matches_zstd_magic() {
    assert!(starts_with_zstd_frame_for_test(b"\x28\xb5\x2f\xfd\x00"));
    assert!(!starts_with_zstd_frame_for_test(b"\x28\xb5\x2f"));
    assert!(!starts_with_zstd_frame_for_test(b""));
}

#[cfg(feature = "web")]
#[test]
fn starts_with_wasm_module_matches_wasm_magic() {
    assert!(starts_with_wasm_module_for_test(b"\x00asm"));
    assert!(!starts_with_wasm_module_for_test(b"\x00as"));
    assert!(!starts_with_wasm_module_for_test(b"asm\x00"));
    assert!(!starts_with_wasm_module_for_test(b""));
}
