//! Long alphabetic runs without prefix reversal must not reverse-decode.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;

#[test]
fn alphabetic_prose_emits_no_reverse_chunks() {
    for text in ["ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789abcdefghijklmnopqr"] {
        let chunk = Chunk {
            data: text.into(),
            metadata: Default::default(),
        };
        let decoded = decode_chunk(&chunk, 2, false, None, None);
        assert!(
            decoded
                .iter()
                .all(|c| !c.metadata.source_type.contains("/reverse")),
            "reverse decoder must reject prose `{text}`"
        );
    }
}
