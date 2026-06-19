//! validate=true drops decoded chunks containing NUL bytes.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;

#[test]
fn validate_true_drops_nul_decoded_chunks() {
    // Z85 of bytes with embedded NUL
    let text = r#"token = "0000000000""#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, true, None, None);
    assert!(
        decoded.iter().all(|c| !c.data.as_bytes().contains(&0)),
        "validate mode must not emit chunks containing NUL"
    );
}
