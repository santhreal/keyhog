use keyhog_scanner::decode::{base64_decode, find_base64_strings, hex_decode, z85_decode};
use keyhog_scanner::testing::{find_hex_strings, take_hex_digits};

const VALID_CREDENTIAL: &str = "TESTKEY_aK7xP9mQ2wE5rT8yU1iO";

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

#[test]
fn take_hex_digits_basic() {
    let mut it = "deadbeef".chars().peekable();
    assert_eq!(take_hex_digits(&mut it, 8).unwrap(), 0xdeadbeef);
}

#[test]
fn take_hex_digits_partial_consumption() {
    let mut it = "ff00".chars().peekable();
    assert_eq!(take_hex_digits(&mut it, 2).unwrap(), 0xff);
    assert_eq!(take_hex_digits(&mut it, 2).unwrap(), 0x00);
}

#[test]
fn take_hex_digits_uppercase() {
    let mut it = "ABCD".chars().peekable();
    assert_eq!(take_hex_digits(&mut it, 4).unwrap(), 0xABCD);
}

#[test]
fn take_hex_digits_rejects_non_hex() {
    let mut it = "ZZZZ".chars().peekable();
    assert!(take_hex_digits(&mut it, 4).is_err());
}

#[test]
fn take_hex_digits_rejects_short_input() {
    let mut it = "ff".chars().peekable();
    assert!(take_hex_digits(&mut it, 4).is_err());
}

#[test]
fn underscored_hex_is_recognized() {
    // 64 hex chars (32 bytes) split into 2-char groups by `_`.
    // Wrapped in quotes so `extract_encoded_values` picks it up.
    let body = "\"41_42_43_44_45_46_47_48_49_4a_4b_4c_4d_4e_4f_50\
                _51_52_53_54_55_56_57_58_59_5a_61_62_63_64_65_66\"";
    let found = find_hex_strings(body, 32);
    assert_eq!(found.len(), 1);
    let cleaned: String = found[0].value.chars().filter(|c| *c != '_').collect();
    assert!(cleaned.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(cleaned.len(), 64);
    let decoded = hex_decode(&found[0].value).expect("decodes");
    assert_eq!(&decoded[..16], b"ABCDEFGHIJKLMNOP");
}

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
    let found = find_hex_strings(&body, 32);
    assert_eq!(found.len(), 1, "underscored TESTKEY hex must be found");
    let decoded = String::from_utf8(hex_decode(&found[0].value).unwrap()).unwrap();
    assert_eq!(decoded, VALID_CREDENTIAL);
}

#[test]
fn hex_decode_strips_underscore_separators() {
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
    let decoded = String::from_utf8(hex_decode(&underscored).unwrap()).unwrap();
    assert_eq!(decoded, VALID_CREDENTIAL);
}

#[test]
fn underscores_alone_dont_create_phantom_matches() {
    // Underscore-only string strips to empty, must not match.
    let found = find_hex_strings("\"_____________________________\"", 32);
    assert!(found.is_empty());
}
