//! JSON unescape decoder splices unescaped value while preserving JSON key.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;

#[test]
fn json_unescape_splice_preserves_key_anchor() {
    let text = r#"{"api_key": "c2stcHJvai1hYmMxMjM\u003d"}"#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    let spliced = decoded
        .iter()
        .any(|c| c.data.contains("api_key") && c.data.contains("sk-proj-abc123"));
    assert!(
        spliced,
        "json decoder must splice unescaped credential near key anchor"
    );
}
