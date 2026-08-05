//! Shared byte signatures for file/container format identification.
//!
//! Keep raw magic bytes here instead of repeating literals across sources.
//! Callers still own semantics: text decode rejects these as binary input,
//! Docker layer extraction routes them to the matching decompressor.

pub(crate) const GZIP_PREFIX: &[u8] = b"\x1f\x8b";
pub(crate) const PDF_PREFIX: &[u8] = b"%PDF-";
pub(crate) const PYTHON_PICKLE_PROTOCOL2_PREFIX: &[u8] = b"\x80\x02";
pub(crate) const ZIP_CENTRAL_DIRECTORY_FILE_HEADER_SIGNATURE: u32 = 0x0201_4b50;
pub(crate) const ZIP_END_OF_CENTRAL_DIRECTORY_PREFIX: &[u8] = b"PK\x05\x06";
pub(crate) const ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0605_4b50;
pub(crate) const ZIP_LOCAL_FILE_HEADER_SIGNATURE: u32 = 0x0403_4b50;
pub(crate) const ZIP_LOCAL_FILE_PREFIX: &[u8] = b"PK\x03\x04";
pub(crate) const ZSTD_FRAME_MAGIC: &[u8] = b"\x28\xb5\x2f\xfd";
pub(crate) const XZ_STREAM_MAGIC: &[u8] = b"\xfd7zXZ\x00";
pub(crate) const LZ4_FRAME_MAGIC: &[u8] = b"\x04\x22\x4d\x18";
pub(crate) const SNAPPY_FRAME_MAGIC: &[u8] = b"\xff\x06\x00\x00sNaPpY";
pub(crate) const WASM_MAGIC: &[u8; 4] = b"\x00asm";
/// Container families recognized by signature that the archive-MEMBER dispatcher
/// has no in-memory extractor for. Named so the member path can report an
/// uncovered region instead of leaf-scanning container bytes, whose compressed
/// payload holds no printable run and therefore reads as a clean member.
pub(crate) const SEVEN_ZIP_PREFIX: &[u8] = b"7z\xbc\xaf\x27\x1c";
pub(crate) const RAR_PREFIX: &[u8] = b"Rar!\x1a\x07";
pub(crate) const UNIX_AR_PREFIX: &[u8] = b"!<arch>\n";

pub(crate) const UNAMBIGUOUS_BINARY_PREFIXES: &[&[u8]] = &[
    PDF_PREFIX,
    ZIP_LOCAL_FILE_PREFIX, // ZIP / JAR / DOCX / XLSX / PPTX / APK / OOXML
    b"\x89PNG\r\n\x1a\n",
    b"\xD0\xCF\x11\xE0",   // OLE compound document (older Office)
    b"\x7fELF",            // Linux / BSD executables, .so, .o, .a
    b"\xfe\xed\xfa\xce",   // Mach-O 32-bit (macOS, iOS executables)
    b"\xfe\xed\xfa\xcf",   // Mach-O 64-bit
    b"\xcf\xfa\xed\xfe",   // Mach-O 64-bit reversed
    b"\xca\xfe\xba\xbe",   // Java .class (universal Mach-O collision)
    GZIP_PREFIX,           // gzip (.gz)
    ZSTD_FRAME_MAGIC,      // zstd (.zst)
    XZ_STREAM_MAGIC,       // xz (.xz)
    SEVEN_ZIP_PREFIX,      // 7z (.7z)
    RAR_PREFIX,            // RAR
    b"GIF87a",             // GIF
    b"GIF89a",             // GIF
    b"\xff\xd8\xff",       // JPEG (any variant)
    b"\x00\x00\x01\x00",   // ICO
    b"OggS",               // Ogg container
    b"fLaC",               // FLAC
    WASM_MAGIC,            // WebAssembly module
    UNIX_AR_PREFIX,        // Unix `ar` archives (.a, .deb)
];

#[inline]
pub(crate) fn has_unambiguous_binary_prefix(bytes: &[u8]) -> bool {
    UNAMBIGUOUS_BINARY_PREFIXES
        .iter()
        .any(|header| bytes.starts_with(header))
}

/// The container family of `bytes` when it is one the archive-MEMBER dispatcher
/// recognizes but cannot descend into.
///
/// `tar`, the zip family, and the single-stream compressed formats are all
/// handled in memory by `emit_archive_member`. These three are not: their
/// extractors need a seekable file on disk, so an embedded one is a container
/// whose contents were NOT scanned. Naming the family lets the member path
/// surface that as an uncovered region rather than fall through to the
/// printable-strings leaf, which finds no printable run in compressed container
/// bytes and so reports the member clean (Law 10 silent false clean).
///
/// Signature-only, at offset 0, over a prefix the caller already holds: this
/// never speculatively feeds bytes to an extractor.
#[inline]
pub(crate) fn uninterpreted_container_format(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(SEVEN_ZIP_PREFIX) {
        Some("7z")
    } else if bytes.starts_with(RAR_PREFIX) {
        Some("RAR")
    } else if bytes.starts_with(UNIX_AR_PREFIX) {
        Some("ar/deb")
    } else {
        None
    }
}

#[inline]
pub(crate) fn starts_with_python_pickle_protocol2(bytes: &[u8]) -> bool {
    bytes.starts_with(PYTHON_PICKLE_PROTOCOL2_PREFIX)
}

#[inline]
pub(crate) fn starts_with_pdf(bytes: &[u8]) -> bool {
    bytes.starts_with(PDF_PREFIX)
}

#[inline]
pub(crate) fn starts_with_zip_container_prefix(bytes: &[u8]) -> bool {
    bytes.starts_with(ZIP_LOCAL_FILE_PREFIX)
        || bytes.starts_with(ZIP_END_OF_CENTRAL_DIRECTORY_PREFIX)
}

#[inline]
pub(crate) fn has_bmp_header(bytes: &[u8]) -> bool {
    bytes.len() >= 14
        && bytes.starts_with(b"BM")
        && bytes[6..10] == [0, 0, 0, 0]
        && u32::from_le_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]) >= 14
}

#[inline]
pub(crate) fn has_pe_header(bytes: &[u8]) -> bool {
    if bytes.len() < 64 || !bytes.starts_with(b"MZ") {
        return false;
    }
    let pe_offset = u32::from_le_bytes([bytes[60], bytes[61], bytes[62], bytes[63]]) as usize;
    pe_offset >= 64
        && pe_offset
            .checked_add(4)
            .is_some_and(|end| end <= bytes.len() && &bytes[pe_offset..end] == b"PE\0\0")
}

#[inline]
pub(crate) fn has_bzip2_header(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes.starts_with(b"BZh") && matches!(bytes[3], b'1'..=b'9')
}

#[inline]
pub(crate) fn starts_with_gzip(bytes: &[u8]) -> bool {
    bytes.starts_with(GZIP_PREFIX)
}

#[inline]
pub(crate) fn starts_with_zstd_frame(bytes: &[u8]) -> bool {
    bytes.starts_with(ZSTD_FRAME_MAGIC)
}

#[inline]
pub(crate) fn starts_with_xz_stream(bytes: &[u8]) -> bool {
    bytes.starts_with(XZ_STREAM_MAGIC)
}

#[inline]
pub(crate) fn starts_with_lz4_frame(bytes: &[u8]) -> bool {
    bytes.starts_with(LZ4_FRAME_MAGIC)
}

#[inline]
pub(crate) fn starts_with_snappy_frame(bytes: &[u8]) -> bool {
    bytes.starts_with(SNAPPY_FRAME_MAGIC)
}

#[inline]
#[cfg(feature = "web")]
pub(crate) fn starts_with_wasm_module(bytes: &[u8]) -> bool {
    bytes.starts_with(WASM_MAGIC)
}

#[cfg(test)]
mod tests {
    #[test]
    fn zip_container_prefix_accepts_real_zip_starts_only() {
        assert!(super::starts_with_zip_container_prefix(b"PK\x03\x04file"));
        assert!(super::starts_with_zip_container_prefix(b"PK\x05\x06empty"));
        assert!(!super::starts_with_zip_container_prefix(
            b"PK_is_plain_text"
        ));
    }
}
