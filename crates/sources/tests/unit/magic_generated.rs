#![cfg(test)]

use keyhog_sources::testing::{
    has_bmp_header_for_test, has_bzip2_header_for_test, has_pe_header_for_test,
    has_unambiguous_binary_prefix_for_test, starts_with_gzip_for_test, starts_with_pdf_for_test,
    starts_with_python_pickle_protocol2_for_test, starts_with_wasm_module_for_test,
    starts_with_zip_container_prefix_for_test, starts_with_zstd_frame_for_test,
};

macro_rules! magic_case {
    ($name:ident, $fn:ident, $bytes:expr, $expected:expr) => {
        #[test]
        fn $name() {
            assert_eq!($fn($bytes), $expected);
        }
    };
}

magic_case!(pdf_positive, starts_with_pdf_for_test, b"%PDF-1.4", true);
magic_case!(
    pdf_unambiguous,
    has_unambiguous_binary_prefix_for_test,
    b"%PDF-1.4",
    true
);
magic_case!(
    pdf_negative,
    starts_with_pdf_for_test,
    b"hello world",
    false
);
magic_case!(
    bmp_positive,
    has_bmp_header_for_test,
    &[0x42, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00],
    true
);
magic_case!(
    bmp_negative_too_short,
    has_bmp_header_for_test,
    &[0x42, 0x4D],
    false
);
magic_case!(
    bmp_negative_bad_zeros,
    has_bmp_header_for_test,
    &[0x42, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00],
    false
);
magic_case!(
    pe_positive,
    has_pe_header_for_test,
    &[
        0x4D, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x50, 0x45, 0x00, 0x00
    ],
    true
);
magic_case!(
    pe_negative_too_short,
    has_pe_header_for_test,
    &[0x4D, 0x5A],
    false
);
magic_case!(
    zip_local_positive,
    starts_with_zip_container_prefix_for_test,
    b"PK\x03\x04file",
    true
);
magic_case!(
    zip_eocd_positive,
    starts_with_zip_container_prefix_for_test,
    b"PK\x05\x06empty",
    true
);
magic_case!(
    zip_negative,
    starts_with_zip_container_prefix_for_test,
    b"PK_is_plain_text",
    false
);
magic_case!(
    gzip_positive,
    starts_with_gzip_for_test,
    &[0x1F, 0x8B, 0x08],
    true
);
magic_case!(
    gzip_negative,
    starts_with_gzip_for_test,
    &[0x00, 0x00],
    false
);
magic_case!(
    zstd_positive,
    starts_with_zstd_frame_for_test,
    &[0x28, 0xB5, 0x2F, 0xFD],
    true
);
magic_case!(
    zstd_negative,
    starts_with_zstd_frame_for_test,
    &[0x00, 0x00, 0x00, 0x00],
    false
);
magic_case!(
    wasm_positive,
    starts_with_wasm_module_for_test,
    &[0x00, 0x61, 0x73, 0x6D],
    true
);
magic_case!(
    wasm_negative,
    starts_with_wasm_module_for_test,
    &[0x00, 0x00, 0x00, 0x00],
    false
);
magic_case!(bzip2_positive, has_bzip2_header_for_test, b"BZh9", true);
magic_case!(
    bzip2_negative_bad_digit,
    has_bzip2_header_for_test,
    b"BZh0",
    false
);
magic_case!(
    pickle_positive,
    starts_with_python_pickle_protocol2_for_test,
    &[0x80, 0x02],
    true
);
magic_case!(
    pickle_negative,
    starts_with_python_pickle_protocol2_for_test,
    &[0x00, 0x00],
    false
);
magic_case!(
    unambiguous_png,
    has_unambiguous_binary_prefix_for_test,
    b"\x89PNG\r\n\x1a\n",
    true
);
magic_case!(
    unambiguous_elf,
    has_unambiguous_binary_prefix_for_test,
    b"\x7fELF",
    true
);
magic_case!(
    unambiguous_plain_text,
    has_unambiguous_binary_prefix_for_test,
    b"hello world",
    false
);
