//! Underscore-grouped TESTKEY hex survives extract + decode.

use keyhog_core::Chunk;
use keyhog_scanner::decode::hex_decode;
use keyhog_scanner::testing::decode_chunk;

const VALID_CREDENTIAL: &str = "TESTKEY_aK7xP9mQ2wE5rT8yU1iO";

#[test]
fn underscored_testkey_hex_decodes_to_credential() {
    let hex: String = VALID_CREDENTIAL
        .bytes()
        .map(|b| format!("{b:02x}"))
        .collect();
    let underscored = hex
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join("_");
    let body = format!("const token_hex = \"{underscored}\";");
    let chunk = Chunk {
        data: body.into(),
        metadata: Default::default(),
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    assert!(
        decoded.iter().any(|c| c.data.contains(VALID_CREDENTIAL)),
        "hex decoder must recover TESTKEY credential from underscored literal"
    );
    let decoded = String::from_utf8(hex_decode(&underscored).unwrap()).unwrap();
    assert_eq!(decoded, VALID_CREDENTIAL);
}
