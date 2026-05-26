//! Decoded chunk source_type includes decoder name suffix.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;

#[test]
fn decoded_chunk_source_type_contains_decoder_name() {
    let text = r#"token = "c2stcHJvai1hYmMxMjM=""#;
    let chunk = Chunk { data: text.into(), metadata: Default::default() };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    assert!(
        decoded.iter().any(|c| c.metadata.source_type.contains("/base64")),
        "base64-decoded chunks must tag source_type with /base64"
    );
}
