//! Base64 decode-through splices decoded secret back into parent context.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;

#[test]
fn base64_splice_preserves_companion_anchor() {
    let text = r#"aws_secret_access_key = "c2stcHJvai1hYmMxMjM=""#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    let spliced = decoded
        .iter()
        .any(|c| c.data.contains("aws_secret_access_key") && c.data.contains("sk-proj-abc123"));
    assert!(
        spliced,
        "decoded chunk must splice secret adjacent to assignment anchor"
    );
}
