//! URL percent decode splices Bearer-prefixed percent runs.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;

#[test]
fn url_percent_splice_preserves_bearer_context() {
    // "AKIA" percent-encoded
    let text = "Authorization: Bearer %41%4b%49%41IOSFODNN7EXAMPLE";
    let chunk = Chunk { data: text.into(), metadata: Default::default() };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    let spliced = decoded.iter().any(|c| c.data.contains("Authorization") && c.data.contains("AKIA"));
    assert!(spliced, "url decoder must splice percent-decoded prefix into bearer line");
}
