//! Standard base64 with padding decodes to expected UTF-8 secret prefix.

use keyhog_scanner::decode::base64_decode;

#[test]
fn standard_padded_base64_decodes_sk_prefix() {
    let decoded = base64_decode("c2stcHJvai1hYmMxMjM=").expect("valid base64");
    assert_eq!(String::from_utf8(decoded).unwrap(), "sk-proj-abc123");
}
