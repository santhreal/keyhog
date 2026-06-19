//! Caesar decoder must not emit chunks for prose lacking known prefixes.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;

#[test]
fn pure_letter_prose_emits_no_caesar_chunks() {
    let chunk = Chunk {
        data: "HELLOWORLDFOOBARBAZQUX".into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    assert!(
        decoded
            .iter()
            .all(|c| !c.metadata.source_type.contains("/caesar")),
        "prose without credential prefix must not produce caesar chunks"
    );
}
