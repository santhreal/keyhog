//! Reverse decoder emits chunk when reversed text contains known prefix.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::decode::decode_chunk;

#[test]
fn reversed_aws_access_key_id_decoded() {
    let reversed = "ELPMAXE7NNODFOSOIAK"; // AKIAIOSFODNN7EXAMPLE reversed (prefix portion)
    let forward = concat!("AK", "IAIOSFODNN7EXAMPLE");
    let rev_full: String = forward.chars().rev().collect();
    let text = format!("blob = \"{rev_full}\"");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            path: Some("config.bin".into()),
            ..Default::default()
        },
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    let has_forward = decoded.iter().any(|c| c.data.contains(forward));
    assert!(has_forward, "reverse decoder must recover forward AKIA key from reversed blob");
    let _ = reversed; // silence unused in case of refactor
}
