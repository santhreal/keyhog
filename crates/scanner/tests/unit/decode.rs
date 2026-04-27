use keyhog_scanner::decode::{base64_decode, find_base64_strings, hex_decode, z85_decode};

#[test]
fn decode_base64_secret() {
    let encoded = "c2stcHJvai1hYmMxMjM=";
    let decoded = base64_decode(encoded).unwrap();
    assert_eq!(String::from_utf8(decoded).unwrap(), "sk-proj-abc123");
}

#[test]
fn decode_hex_secret() {
    let encoded = "736b2d70726f6a2d616263";
    let decoded = hex_decode(encoded).unwrap();
    assert_eq!(String::from_utf8(decoded).unwrap(), "sk-proj-abc");
}

#[test]
fn find_base64_in_text() {
    let text = r#"TOKEN = "c2stcHJvai1hYmMxMjM=""#;
    let matches = find_base64_strings(text, 10);
    assert!(!matches.is_empty());
    assert_eq!(matches[0].value, "c2stcHJvai1hYmMxMjM=");
}

#[test]
fn decode_z85_secret() {
    // Four null bytes in Z85 is "00000"
    let encoded = "00000";
    let decoded = z85_decode(encoded).unwrap();
    assert_eq!(decoded, vec![0, 0, 0, 0]);
}
