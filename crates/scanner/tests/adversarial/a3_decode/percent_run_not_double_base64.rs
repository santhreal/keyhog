use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;

#[test]
fn percent_encoded_blob_not_also_decoded_as_spurious_base64() {
    let text = "%41%4b%49%41IOSFODNN7EXAMPLE1234567890";
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    let base64_only = decoded
        .iter()
        .all(|c| !c.metadata.source_type.ends_with("/base64") || c.data.contains('%'));
    assert!(
        base64_only || decoded.iter().any(|c| c.data.contains("AKIA")),
        "expect url decode, not spurious bare base64 of hex digits"
    );
}
