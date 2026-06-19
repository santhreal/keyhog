use std::collections::{HashMap, HashSet};

use keyhog_core::testing::{CoreTestApi, TestApi};
use keyhog_core::{Credential, SensitiveString};

fn credential_expose_str(credential: &Credential) -> Option<&str> {
    CoreTestApi::credential_expose_str(&TestApi, credential)
}

fn encode_standard_base64(bytes: &[u8]) -> String {
    CoreTestApi::encode_standard_base64(&TestApi, bytes)
}

#[test]
fn credential_from_empty_bytes_is_empty() {
    let credential = Credential::from(Vec::<u8>::new());

    assert!(credential.expose_secret().is_empty());
    assert_eq!(credential.expose_secret().len(), 0);
}

#[test]
fn credential_from_text_exposes_correct_bytes() {
    let credential = Credential::from("test_value_abc123");

    assert_eq!(credential.expose_secret(), b"test_value_abc123");
    assert_eq!(
        credential_expose_str(&credential),
        Some("test_value_abc123")
    );
}

#[test]
fn credential_from_binary_bytes_exposes_no_utf8_str() {
    let credential = Credential::from(vec![0xff, 0xfe, 0xfd]);

    assert_eq!(credential_expose_str(&credential), None);
    assert_eq!(credential.expose_secret(), &[0xff, 0xfe, 0xfd]);
}

#[test]
fn credential_len_matches_byte_count() {
    let data = b"hello_world_1234";
    let credential = Credential::from(&data[..]);

    assert_eq!(credential.expose_secret().len(), data.len());
}

#[test]
fn credential_from_str_ref_works() {
    let credential: Credential = "from_str_test".into();

    assert_eq!(credential.expose_secret(), b"from_str_test");
}

#[test]
fn credential_from_string_works() {
    let credential: Credential = "from_string_test".to_string().into();

    assert_eq!(credential.expose_secret(), b"from_string_test");
}

#[test]
fn credential_from_vec_u8_works() {
    let credential: Credential = vec![0x41, 0x42, 0x43].into();

    assert_eq!(credential.expose_secret(), b"ABC");
}

#[test]
fn credential_equals_itself() {
    let credential = Credential::from("self_equals_test");

    assert_eq!(credential, credential.clone());
}

#[test]
fn credential_equal_same_bytes() {
    let first = Credential::from("shared_bytes_value");
    let second = Credential::from("shared_bytes_value");

    assert_eq!(first, second);
}

#[test]
fn credential_not_equal_different_bytes() {
    let first = Credential::from("value_alpha");
    let second = Credential::from("value_beta_");

    assert_ne!(first, second);
}

#[test]
fn credential_not_equal_prefix_mismatch() {
    let first = Credential::from("abc");
    let second = Credential::from("abcd");

    assert_ne!(first, second);
}

#[test]
fn credential_ordering_is_lexicographic() {
    let alpha = Credential::from("alpha");
    let beta = Credential::from("beta_");

    assert!(alpha < beta);
}

#[test]
fn credential_equal_is_not_less_than() {
    let first = Credential::from("same_value");
    let second = Credential::from("same_value");

    assert!(!(first < second));
    assert!(!(second < first));
}

#[test]
fn credential_usable_as_hashmap_key() {
    let mut map: HashMap<Credential, &str> = HashMap::new();
    let key = Credential::from("map_key_value");

    map.insert(key.clone(), "found");

    assert_eq!(map.get(&key), Some(&"found"));
}

#[test]
fn credential_different_values_hash_as_distinct_set_entries() {
    let mut set: HashSet<Credential> = HashSet::new();

    set.insert(Credential::from("unique_val_one"));
    set.insert(Credential::from("unique_val_two"));

    assert_eq!(set.len(), 2);
}

#[test]
fn credential_debug_does_not_expose_bytes() {
    let credential = Credential::from("secret_plaintext_value");
    let debug_output = format!("{credential:?}");

    assert!(
        !debug_output.contains("secret_plaintext_value"),
        "Debug must not expose plaintext; got: {debug_output}"
    );
    assert!(
        debug_output.contains("redacted"),
        "Debug must indicate redaction; got: {debug_output}"
    );
}

#[test]
fn credential_display_does_not_expose_bytes() {
    let credential = Credential::from("another_secret_value");
    let display_output = format!("{credential}");

    assert!(
        !display_output.contains("another_secret_value"),
        "Display must not expose plaintext; got: {display_output}"
    );
    assert!(
        display_output.contains("redacted"),
        "Display must indicate redaction; got: {display_output}"
    );
}

#[test]
fn credential_utf8_serializes_as_tagged_text() {
    let credential = Credential::from("roundtrip_text");
    let json = serde_json::to_string(&credential).expect("serialize credential");
    let back: Credential = serde_json::from_str(&json).expect("deserialize credential");

    assert!(
        json.contains("\"text\""),
        "UTF-8 credential must serialize under the text key: {json}"
    );
    assert_eq!(back, credential);
}

#[test]
fn credential_binary_serializes_as_tagged_b64() {
    let credential = Credential::from(vec![0xff, 0x00, 0xab]);
    let json = serde_json::to_string(&credential).expect("serialize credential");
    let back: Credential = serde_json::from_str(&json).expect("deserialize credential");

    assert!(
        json.contains("\"b64\""),
        "binary credential must serialize under the b64 key: {json}"
    );
    assert_eq!(back, credential);
}

#[test]
fn credential_legacy_plain_string_deserializes() {
    let json = r#""legacy_plain_credential""#;
    let credential: Credential = serde_json::from_str(json).expect("deserialize credential");

    assert_eq!(credential.expose_secret(), b"legacy_plain_credential");
}

#[test]
fn credential_legacy_b64_prefix_deserializes() {
    let bytes = b"binary_payload";
    let legacy = format!("b64:{}", encode_standard_base64(bytes));
    let json = serde_json::to_string(&legacy).expect("serialize legacy b64 string");
    let credential: Credential = serde_json::from_str(&json).expect("deserialize credential");

    assert_eq!(credential.expose_secret(), bytes.as_slice());
}

#[test]
fn credential_both_text_and_b64_is_error() {
    let json = r#"{"text":"foo", "b64":"YmFy"}"#;
    let result: Result<Credential, _> = serde_json::from_str(json);

    assert!(result.is_err(), "both text and b64 must be rejected");
}

#[test]
fn sensitive_string_exposes_content() {
    let sensitive = SensitiveString::from("hello_sensitive");

    assert_eq!(sensitive.as_ref(), "hello_sensitive");
    assert_eq!(sensitive.len(), 15);
    assert!(!sensitive.is_empty());
}

#[test]
fn sensitive_string_empty_is_empty() {
    let sensitive = SensitiveString::from(String::new());

    assert!(sensitive.is_empty());
    assert_eq!(sensitive.len(), 0);
}

#[test]
fn sensitive_string_debug_does_not_expose() {
    let sensitive = SensitiveString::from("secret_string_value");
    let debug_output = format!("{sensitive:?}");

    assert!(
        !debug_output.contains("secret_string_value"),
        "SensitiveString Debug must not expose plaintext; got: {debug_output}"
    );
    assert!(
        debug_output.contains("redacted"),
        "SensitiveString Debug must indicate redaction; got: {debug_output}"
    );
}

#[test]
fn sensitive_string_display_exposes() {
    let sensitive = SensitiveString::from("display_value");

    assert_eq!(format!("{sensitive}"), "display_value");
}

#[test]
fn sensitive_string_deref_gives_str() {
    let sensitive = SensitiveString::from("deref_test");
    let value: &str = &sensitive;

    assert_eq!(value, "deref_test");
}

#[test]
fn sensitive_string_as_ref_str() {
    let sensitive = SensitiveString::from("asref_test");
    let value: &str = sensitive.as_ref();

    assert_eq!(value, "asref_test");
}

#[test]
fn sensitive_string_join_inserts_separator() {
    let parts: Vec<SensitiveString> = ["alpha", "beta", "gamma"]
        .into_iter()
        .map(SensitiveString::from)
        .collect();

    let joined = SensitiveString::join(&parts, "-");

    assert_eq!(joined.as_ref(), "alpha-beta-gamma");
}

#[test]
fn sensitive_string_join_empty_list_produces_empty() {
    let joined = SensitiveString::join(&[], ", ");

    assert!(joined.is_empty());
}

#[test]
fn sensitive_string_join_single_no_separator() {
    let parts = vec![SensitiveString::from("only")];

    let joined = SensitiveString::join(&parts, ", ");

    assert_eq!(joined.as_ref(), "only");
}

#[test]
fn sensitive_string_serde_round_trip() {
    let sensitive = SensitiveString::from("serde_roundtrip_val");
    let json = serde_json::to_string(&sensitive).expect("serialize sensitive string");
    let back: SensitiveString = serde_json::from_str(&json).expect("deserialize sensitive string");

    assert_eq!(back.as_ref(), sensitive.as_ref());
}
