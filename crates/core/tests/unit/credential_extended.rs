/// Extended unit tests for `keyhog_core::credential` (Credential + SensitiveString).
///
/// Covers: empty bytes, binary (non-UTF-8) bytes, round-trip serde for both
/// tagged forms, legacy b64 and plain deserialization, constant-time equality,
/// ordering, hashing, Display/Debug redaction, and SensitiveString join.
use keyhog_core::credential::{Credential, SensitiveString};
use std::collections::HashMap;

// ── Credential: construction and accessors ────────────────────────────────────

#[test]
fn credential_from_empty_bytes_is_empty() {
    let c = Credential::from_bytes(&[]);
    assert!(c.is_empty());
    assert_eq!(c.len(), 0);
}

#[test]
fn credential_from_text_exposes_correct_bytes() {
    let c = Credential::from_text("test_value_abc123");
    assert_eq!(c.expose_secret(), b"test_value_abc123");
    assert_eq!(c.expose_str(), Some("test_value_abc123"));
}

#[test]
fn credential_from_bytes_binary_expose_str_is_none() {
    // Non-UTF-8 bytes — expose_str must return None, not panic
    let c = Credential::from_bytes(&[0xFF, 0xFE, 0xFD]);
    assert!(c.expose_str().is_none());
    assert_eq!(c.expose_secret(), &[0xFF, 0xFE, 0xFD]);
}

#[test]
fn credential_len_matches_byte_count() {
    let data = b"hello_world_1234";
    let c = Credential::from_bytes(data);
    assert_eq!(c.len(), data.len());
}

// ── Credential: From impls ────────────────────────────────────────────────────

#[test]
fn credential_from_str_ref_works() {
    let c: Credential = "from_str_test".into();
    assert_eq!(c.expose_secret(), b"from_str_test");
}

#[test]
fn credential_from_string_works() {
    let s = "from_string_test".to_string();
    let c: Credential = s.into();
    assert_eq!(c.expose_secret(), b"from_string_test");
}

#[test]
fn credential_from_vec_u8_works() {
    let v: Vec<u8> = vec![0x41, 0x42, 0x43];
    let c: Credential = v.into();
    assert_eq!(c.expose_secret(), b"ABC");
}

// ── Credential: equality is constant-time and reflexive ──────────────────────

#[test]
fn credential_equals_itself() {
    let c = Credential::from_text("self_equals_test");
    assert_eq!(c, c.clone());
}

#[test]
fn credential_equal_same_bytes() {
    let c1 = Credential::from_text("shared_bytes_value");
    let c2 = Credential::from_text("shared_bytes_value");
    assert_eq!(c1, c2);
}

#[test]
fn credential_not_equal_different_bytes() {
    let c1 = Credential::from_text("value_alpha");
    let c2 = Credential::from_text("value_beta_");
    assert_ne!(c1, c2);
}

#[test]
fn credential_not_equal_prefix_mismatch() {
    // Same prefix, different length
    let c1 = Credential::from_text("abc");
    let c2 = Credential::from_text("abcd");
    assert_ne!(c1, c2);
}

// ── Credential: ordering ──────────────────────────────────────────────────────

#[test]
fn credential_ordering_is_lexicographic() {
    let c_a = Credential::from_text("alpha");
    let c_b = Credential::from_text("beta_");
    assert!(c_a < c_b);
}

#[test]
fn credential_equal_is_not_less_than() {
    let c1 = Credential::from_text("same_value");
    let c2 = Credential::from_text("same_value");
    assert!(!(c1 < c2));
    assert!(!(c2 < c1));
}

// ── Credential: hashing ───────────────────────────────────────────────────────

#[test]
fn credential_usable_as_hashmap_key() {
    let mut map: HashMap<Credential, &str> = HashMap::new();
    let key = Credential::from_text("map_key_value");
    map.insert(key.clone(), "found");
    assert_eq!(map.get(&key), Some(&"found"));
}

#[test]
fn credential_different_values_different_hash_buckets() {
    use std::collections::HashSet;
    let mut set: HashSet<Credential> = HashSet::new();
    set.insert(Credential::from_text("unique_val_one"));
    set.insert(Credential::from_text("unique_val_two"));
    assert_eq!(set.len(), 2);
}

// ── Credential: Debug/Display redaction ───────────────────────────────────────

#[test]
fn credential_debug_does_not_expose_bytes() {
    let c = Credential::from_text("secret_plaintext_value");
    let dbg = format!("{c:?}");
    assert!(
        !dbg.contains("secret_plaintext_value"),
        "Debug must not expose plaintext; got: {dbg}"
    );
    assert!(dbg.contains("redacted"), "Debug must contain 'redacted'");
}

#[test]
fn credential_display_does_not_expose_bytes() {
    let c = Credential::from_text("another_secret_value");
    let disp = format!("{c}");
    assert!(
        !disp.contains("another_secret_value"),
        "Display must not expose plaintext; got: {disp}"
    );
    assert!(disp.contains("redacted"));
}

// ── Credential: serde round-trips ─────────────────────────────────────────────

#[test]
fn credential_utf8_serializes_as_tagged_text() {
    let c = Credential::from_text("roundtrip_text");
    let json = serde_json::to_string(&c).expect("serialize");
    assert!(json.contains("\"text\""), "UTF-8 must serialize under 'text' key");
    let back: Credential = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, c);
}

#[test]
fn credential_binary_serializes_as_tagged_b64() {
    let c = Credential::from_bytes(&[0xFF, 0x00, 0xAB]);
    let json = serde_json::to_string(&c).expect("serialize");
    assert!(json.contains("\"b64\""), "binary must serialize under 'b64' key");
    let back: Credential = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, c);
}

#[test]
fn credential_legacy_plain_string_deserializes() {
    let json = r#""legacy_plain_credential""#;
    let c: Credential = serde_json::from_str(json).expect("deserialize");
    assert_eq!(c.expose_secret(), b"legacy_plain_credential");
}

#[test]
fn credential_legacy_b64_prefix_deserializes() {
    // Old format: "b64:<base64 of bytes>"
    let bytes = b"binary_payload";
    let b64 = base64_encode_for_test(bytes);
    let legacy_str = format!("b64:{b64}");
    let json = serde_json::to_string(&legacy_str).expect("json string");
    let c: Credential = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(c.expose_secret(), bytes.as_slice());
}

/// Minimal base64 encoder for test — mirrors the private one in credential.rs.
fn base64_encode_for_test(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[test]
fn credential_both_text_and_b64_is_error() {
    let json = r#"{"text":"foo","b64":"YmFy"}"#;
    let result: Result<Credential, _> = serde_json::from_str(json);
    assert!(result.is_err(), "both text and b64 must be rejected");
}

// ── SensitiveString ────────────────────────────────────────────────────────────

#[test]
fn sensitive_string_exposes_content() {
    let s = SensitiveString::new("hello_sensitive".to_string());
    assert_eq!(s.as_str(), "hello_sensitive");
    assert_eq!(s.len(), 15);
    assert!(!s.is_empty());
}

#[test]
fn sensitive_string_empty_is_empty() {
    let s = SensitiveString::new(String::new());
    assert!(s.is_empty());
    assert_eq!(s.len(), 0);
}

#[test]
fn sensitive_string_debug_does_not_expose() {
    let s = SensitiveString::new("secret_string_value".to_string());
    let dbg = format!("{s:?}");
    assert!(
        !dbg.contains("secret_string_value"),
        "SensitiveString Debug must not expose plaintext"
    );
    assert!(dbg.contains("redacted"));
}

#[test]
fn sensitive_string_display_exposes() {
    // Display IS transparent (see the impl — it calls through to the inner str)
    let s = SensitiveString::new("display_value".to_string());
    assert_eq!(format!("{s}"), "display_value");
}

#[test]
fn sensitive_string_deref_gives_str() {
    let s = SensitiveString::new("deref_test".to_string());
    let r: &str = &*s;
    assert_eq!(r, "deref_test");
}

#[test]
fn sensitive_string_as_ref_str() {
    let s = SensitiveString::new("asref_test".to_string());
    let r: &str = s.as_ref();
    assert_eq!(r, "asref_test");
}

#[test]
fn sensitive_string_join_inserts_separator() {
    let parts: Vec<SensitiveString> = ["alpha", "beta", "gamma"]
        .iter()
        .map(|s| SensitiveString::from(*s))
        .collect();
    let joined = SensitiveString::join(&parts, "-");
    assert_eq!(joined.as_str(), "alpha-beta-gamma");
}

#[test]
fn sensitive_string_join_empty_list_produces_empty() {
    let joined = SensitiveString::join(&[], ",");
    assert!(joined.is_empty());
}

#[test]
fn sensitive_string_join_single_no_separator() {
    let parts = vec![SensitiveString::from("only")];
    let joined = SensitiveString::join(&parts, ",");
    assert_eq!(joined.as_str(), "only");
}

#[test]
fn sensitive_string_serde_round_trip() {
    let s = SensitiveString::new("serde_roundtrip_val".to_string());
    let json = serde_json::to_string(&s).expect("serialize");
    let back: SensitiveString = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.as_str(), s.as_str());
}
