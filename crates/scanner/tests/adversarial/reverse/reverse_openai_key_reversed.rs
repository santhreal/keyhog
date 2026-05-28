//! R5-T-SCAN reverse decode must surface `openai-api-key`.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;

#[test]
fn reverse_openai_key_reversed() {
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890AB";
    let reversed: String = secret.chars().rev().collect();
    let chunk = Chunk {
        data: format!("token = \"{reversed}\"").into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 5, false, None, None);
    assert!(
        decoded.iter().any(|c| c.data.contains(secret)),
        "reverse decoder must surface openai-api-key body in decoded chunks"
    );
}
