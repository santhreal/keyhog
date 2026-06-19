//! Reverse decoder ignores short or punctuated candidates.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;

#[test]
fn short_and_punctuated_strings_emit_no_reverse_chunks() {
    for text in ["hello", "a-b-c-d-e-f-g-h-i-j"] {
        let chunk = Chunk {
            data: text.into(),
            metadata: Default::default(),
        };
        let decoded = decode_chunk(&chunk, 2, false, None, None);
        assert!(
            decoded
                .iter()
                .all(|c| !c.metadata.source_type.contains("/reverse")),
            "reverse decoder must skip `{text}`"
        );
    }
}
