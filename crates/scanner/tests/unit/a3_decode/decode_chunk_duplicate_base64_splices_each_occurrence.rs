//! Duplicate encoded blobs splice at their own occurrence, not the first match.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;

#[test]
fn duplicate_base64_values_splice_each_source_occurrence() {
    let encoded = "c2stcHJvai1hYmMxMjM=";
    let text = format!("first = \"{encoded}\"\nsecond = \"{encoded}\"");
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };

    let decoded = decode_chunk(&chunk, 2, false, None, None);

    assert!(
        decoded
            .iter()
            .any(|c| c.data.contains("first = \"sk-proj-abc123\"")),
        "first encoded occurrence must be spliced at the first anchor: {decoded:?}"
    );
    assert!(
        decoded
            .iter()
            .any(|c| c.data.contains("second = \"sk-proj-abc123\"")),
        "second encoded occurrence must be spliced at the second anchor: {decoded:?}"
    );
}
