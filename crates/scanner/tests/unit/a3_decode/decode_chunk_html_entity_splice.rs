//! HTML named entity decode splices unescaped value into parent.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;

#[test]
fn html_entity_decode_splices_into_parent() {
    let text = r#"password = "&lt;secret&gt;token1234567890""#;
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    let spliced = decoded
        .iter()
        .any(|c| c.data.contains("password") && c.data.contains("<secret>"));
    assert!(
        spliced,
        "html entity decode must splice unescaped text near assignment key"
    );
}
