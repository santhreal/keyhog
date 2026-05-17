use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::decode::decode_chunk;

#[test]
fn test_decode() {
    let chunk = Chunk {
        data: "auth: \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"\npayload: \"AKIAQYLPMN5HFIQR7BBB\""
            .into(),
        metadata: ChunkMetadata::default(),
    };
    let chunks = decode_chunk(&chunk, 3, false, None, None);
    for c in chunks {
        if c.data.as_str().contains("sb_") {
            println!("FOUND STRING: {}", c.data.as_str());
        }
    }
}
