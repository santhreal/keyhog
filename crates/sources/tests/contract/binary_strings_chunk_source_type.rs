//! Binary strings mode must tag chunks as binary:strings.

#[cfg(feature = "binary")]
#[test]
fn binary_strings_chunk_source_type() {
    use keyhog_core::Source;
    use keyhog_sources::testing::{SourceTestApi, TestApi};

    let dir = tempfile::tempdir().expect("tempdir");
    let mut bytes = Vec::new();
    bytes.push(0);
    bytes.extend_from_slice(b"PASSWORD=longsecretvalue1234567890");
    bytes.push(0);
    std::fs::write(dir.path().join("x.bin"), bytes).expect("write");

    let chunk = TestApi
        .binary_strings_only(dir.path().join("x.bin"))
        .chunks()
        .next()
        .expect("chunk")
        .expect("ok");
    assert_eq!(chunk.metadata.source_type.as_ref(), "binary:strings");
}

#[cfg(not(feature = "binary"))]
#[test]
fn binary_strings_source_type_requires_binary() {
    assert!(!cfg!(feature = "binary"));
}
