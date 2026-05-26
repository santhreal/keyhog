//! LR1-A8 replacement gate: `decode/reverse.rs` reverse layer emitted.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::decode::decode_chunk;

#[test]
fn decode_reverse_layer_recovers_forward_aws_key() {
    let forward = concat!("AK", "IAIOSFODNN7EXAMPLE");
    let rev_full: String = forward.chars().rev().collect();
    let chunk = Chunk {
        data: format!("blob = \"{rev_full}\"").into(),
        metadata: ChunkMetadata::default(),
    };
    let layers = decode_chunk(&chunk, 2, false, None, None);
    assert!(
        layers.iter().any(|c| c.data.contains(forward)),
        "reverse decoder must recover forward AKIA key from reversed blob"
    );
}
