//! Hex decode-through splices decoded bytes into parent assignment context.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;

#[test]
fn hex_splice_preserves_companion_anchor() {
    let secret = "sk-proj-abc12345";
    let hex: String = secret.bytes().map(|b| format!("{b:02x}")).collect();
    let text = format!(r#"api_key = "{hex}""#);
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    let spliced = decoded
        .iter()
        .any(|c| c.data.contains("api_key") && c.data.contains(secret));
    assert!(
        spliced,
        "hex splice must keep api_key anchor next to decoded secret"
    );
}
