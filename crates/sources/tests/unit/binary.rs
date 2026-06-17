#[cfg(feature = "binary")]
use keyhog_core::Source;

#[cfg(feature = "binary")]
#[test]
fn binary_source_strings_only_mode_extracts_printable_secret_runs() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        tmp.path(),
        b"\x00\x00AKIA1234567890ABCDEF\x00\x00ghp_realTokenValue12345678901234\x00\x00",
    )
    .unwrap();

    let source = keyhog_sources::testing::binary_strings_only(tmp.path());
    let chunks: Vec<_> = source.chunks().collect();

    assert!(!chunks.is_empty());
    let chunk = chunks[0].as_ref().unwrap();
    assert!(chunk.data.contains("AKIA"));
    assert_eq!(chunk.metadata.source_type, "binary:strings");
}

#[cfg(feature = "binary")]
#[test]
fn binary_source_extracts_utf16le_wide_string_secret() {
    // A secret stored as a UTF-16LE wide string (Windows PE / .NET shape):
    // each ASCII byte interleaved with 0x00. ASCII-only extraction sees every
    // char interrupted by the 0x00 and never accumulates the run, so this
    // would be silently missed without UTF-16LE support.
    let secret = "AKIA1234567890ABCDEF";
    let mut wide = Vec::new();
    for b in secret.bytes() {
        wide.push(b);
        wide.push(0u8);
    }
    let mut data = vec![0x00, 0x00];
    data.extend_from_slice(&wide);
    data.extend_from_slice(&[0x00, 0x00]);

    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), &data).unwrap();

    let source = keyhog_sources::testing::binary_strings_only(tmp.path());
    let found = source
        .chunks()
        .filter_map(Result::ok)
        .any(|c| c.data.contains(secret));
    assert!(found, "UTF-16LE wide-string secret must be extracted");
}
