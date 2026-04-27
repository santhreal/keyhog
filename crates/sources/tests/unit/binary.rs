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

    let source = keyhog_sources::BinarySource::strings_only(tmp.path());
    let chunks: Vec<_> = source.chunks().collect();

    assert!(!chunks.is_empty());
    let chunk = chunks[0].as_ref().unwrap();
    assert!(chunk.data.contains("AKIA"));
    assert_eq!(chunk.metadata.source_type, "binary:strings");
}
