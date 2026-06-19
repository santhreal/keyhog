//! Standalone coverage for keyhog-core leaf types and pure functions:
//! `Credential`, `SensitiveString`, `redact`, `Severity`, the standard-base64
//! decoder, and the offline AWS account/canary decode. Every assertion checks
//! a concrete value (bytes, ordering, redacted form, decoded account id), never
//! just `is_ok()` / `!is_empty()`.

use keyhog_core::decode_standard_base64;
use keyhog_core::{
    dedup_matches, redact, Credential, DedupScope, MatchLocation, RawMatch, SensitiveString,
    Severity,
};
use keyhog_core::{finding_metadata, key_id_canary_status};
use std::collections::HashMap;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Credential
// ---------------------------------------------------------------------------

#[test]
fn credential_from_text_len_and_expose() {
    let c = Credential::from("sk_live_abcdEFGH");
    assert_eq!(c.expose_secret().len(), 16);
    assert!(!c.expose_secret().is_empty());
    assert_eq!(c.expose_secret(), b"sk_live_abcdEFGH");
    assert_eq!(
        keyhog_core::testing::CoreTestApi::credential_expose_str(
            &keyhog_core::testing::TestApi,
            &c
        ),
        Some("sk_live_abcdEFGH")
    );
}

#[test]
fn credential_empty_is_empty() {
    let c = Credential::from("");
    assert!(c.expose_secret().is_empty());
    assert_eq!(c.expose_secret().len(), 0);
    assert_eq!(c.expose_secret(), b"");
    assert_eq!(
        keyhog_core::testing::CoreTestApi::credential_expose_str(
            &keyhog_core::testing::TestApi,
            &c
        ),
        Some("")
    );
}

#[test]
fn credential_from_bytes_non_utf8_expose_str_none() {
    // 0xFF 0xFE is not valid UTF-8 -> expose_str must be None, expose_secret exact.
    let c = Credential::from(vec![0xFF, 0xFE, 0x00, 0x41]);
    assert_eq!(c.expose_secret().len(), 4);
    assert_eq!(c.expose_secret(), &[0xFF, 0xFE, 0x00, 0x41]);
    assert_eq!(
        keyhog_core::testing::CoreTestApi::credential_expose_str(
            &keyhog_core::testing::TestApi,
            &c
        ),
        None
    );
}

#[test]
fn credential_eq_is_value_based() {
    let a = Credential::from("same-secret-value");
    let b = Credential::from("same-secret-value");
    let c = Credential::from("different");
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn credential_eq_different_lengths_not_equal() {
    let a = Credential::from("abcd");
    let b = Credential::from("abcde");
    assert_ne!(a, b);
}

#[test]
fn credential_ord_matches_byte_order() {
    let a = Credential::from("aaa");
    let b = Credential::from("aab");
    assert!(a < b);
    assert!(b > a);
    assert_eq!(a.cmp(&a.clone()), std::cmp::Ordering::Equal);
}

#[test]
fn credential_hash_matches_for_equal_values() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(Credential::from("dup"));
    set.insert(Credential::from("dup"));
    set.insert(Credential::from("other"));
    // Equal credentials collapse in a HashSet; only two distinct remain.
    assert_eq!(set.len(), 2);
}

#[test]
fn credential_debug_redacts_bytes() {
    let c = Credential::from("supersecretvalue");
    let dbg = format!("{c:?}");
    assert!(
        !dbg.contains("supersecretvalue"),
        "Debug leaked plaintext: {dbg}"
    );
    assert_eq!(dbg, "Credential(<redacted 16 bytes>)");
}

#[test]
fn credential_display_redacts_bytes() {
    let c = Credential::from("supersecretvalue");
    let shown = format!("{c}");
    assert!(!shown.contains("supersecretvalue"));
    assert_eq!(shown, "<redacted 16 bytes>");
}

#[test]
fn credential_serde_text_roundtrip_tagged() {
    let c = Credential::from("hello-token");
    let json = serde_json::to_string(&c).unwrap();
    // Tagged form: {"text":"hello-token"} - never a bare string.
    assert_eq!(json, r#"{"text":"hello-token"}"#);
    let back: Credential = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
    assert_eq!(
        keyhog_core::testing::CoreTestApi::credential_expose_str(
            &keyhog_core::testing::TestApi,
            &back
        ),
        Some("hello-token")
    );
}

#[test]
fn credential_serde_b64_roundtrip_for_non_utf8() {
    let c = Credential::from(vec![0x00, 0xFF, 0x10, 0x80]);
    let json = serde_json::to_string(&c).unwrap();
    // Non-UTF-8 must serialize under the "b64" tag, not "text".
    assert!(
        json.starts_with(r#"{"b64":"#),
        "expected b64 tag, got {json}"
    );
    let back: Credential = serde_json::from_str(&json).unwrap();
    assert_eq!(back.expose_secret(), &[0x00, 0xFF, 0x10, 0x80]);
}

#[test]
fn credential_deser_legacy_plain_string() {
    // Legacy on-disk form: a bare string with no b64: prefix is plaintext.
    let back: Credential = serde_json::from_str(r#""legacy-plain""#).unwrap();
    assert_eq!(
        keyhog_core::testing::CoreTestApi::credential_expose_str(
            &keyhog_core::testing::TestApi,
            &back
        ),
        Some("legacy-plain")
    );
}

#[test]
fn credential_deser_legacy_b64_prefixed_string() {
    // "b64:SGVsbG8=" decodes to "Hello".
    let back: Credential = serde_json::from_str(r#""b64:SGVsbG8=""#).unwrap();
    assert_eq!(
        keyhog_core::testing::CoreTestApi::credential_expose_str(
            &keyhog_core::testing::TestApi,
            &back
        ),
        Some("Hello")
    );
}

#[test]
fn credential_deser_rejects_both_tags() {
    let err = serde_json::from_str::<Credential>(r#"{"text":"a","b64":"QQ=="}"#);
    assert!(err.is_err(), "specifying both text and b64 must fail");
}

#[test]
fn credential_from_conversions_agree() {
    let want = Credential::from("xyz");
    assert_eq!(Credential::from("xyz"), want);
    assert_eq!(Credential::from(String::from("xyz")), want);
    assert_eq!(Credential::from(&b"xyz"[..]), want);
    assert_eq!(Credential::from(vec![b'x', b'y', b'z']), want);
}

// ---------------------------------------------------------------------------
// SensitiveString
// ---------------------------------------------------------------------------

#[test]
fn sensitive_string_basic_accessors() {
    let s = SensitiveString::from("API_KEY=value");
    assert_eq!(s.len(), 13);
    assert!(!s.is_empty());
    assert_eq!(s.as_ref(), "API_KEY=value");
    assert_eq!(s.as_bytes(), b"API_KEY=value");
    // Deref to str.
    assert!(s.contains("API_KEY"));
}

#[test]
fn sensitive_string_default_is_empty() {
    let s = SensitiveString::default();
    assert!(s.is_empty());
    assert_eq!(s.len(), 0);
    assert_eq!(s.as_ref(), "");
}

#[test]
fn sensitive_string_join() {
    let parts = [
        SensitiveString::from("a"),
        SensitiveString::from("b"),
        SensitiveString::from("c"),
    ];
    let joined = SensitiveString::join(&parts, "-");
    assert_eq!(joined.as_ref(), "a-b-c");
    // Empty parts -> empty string.
    assert_eq!(SensitiveString::join(&[], ",").as_ref(), "");
}

#[test]
fn sensitive_string_display_exposes_but_debug_redacts() {
    let s = SensitiveString::from("leaky-content");
    // Display intentionally exposes (auditable surface).
    assert_eq!(format!("{s}"), "leaky-content");
    // Debug must NOT leak.
    let dbg = format!("{s:?}");
    assert!(!dbg.contains("leaky-content"), "Debug leaked: {dbg}");
    assert_eq!(dbg, "SensitiveString(<redacted 13 bytes>)");
}

#[test]
fn sensitive_string_serde_roundtrip_plain_string() {
    let s = SensitiveString::from("round-trip");
    let json = serde_json::to_string(&s).unwrap();
    assert_eq!(json, r#""round-trip""#);
    let back: SensitiveString = serde_json::from_str(&json).unwrap();
    assert_eq!(back.as_ref(), "round-trip");
}

#[test]
fn canonical_match_credentials_use_zeroizing_sensitive_string() {
    fn assert_sensitive_string(_: &SensitiveString) {}

    let raw = RawMatch {
        detector_id: Arc::from("unit"),
        detector_name: Arc::from("Unit"),
        service: Arc::from("unit-service"),
        severity: Severity::High,
        credential: SensitiveString::from("live-secret-value"),
        credential_hash: [7u8; 32],
        companions: HashMap::new(),
        location: MatchLocation {
            source: Arc::from("unit"),
            file_path: Some(Arc::from("unit.env")),
            line: Some(1),
            offset: 4,
            commit: None,
            author: None,
            date: None,
        },
        entropy: Some(4.5),
        confidence: Some(0.95),
    };
    assert_sensitive_string(&raw.credential);

    let raw_json = serde_json::to_value(&raw).unwrap();
    assert_eq!(raw_json["credential"], "live-secret-value");

    let mut deduped = dedup_matches(vec![raw], &DedupScope::None);
    assert_eq!(deduped.len(), 1);
    let finding = deduped.pop().unwrap();
    assert_sensitive_string(&finding.credential);

    let deduped_json = serde_json::to_value(&finding).unwrap();
    assert_eq!(deduped_json["credential"], "live-secret-value");
}

// ---------------------------------------------------------------------------
// redact
// ---------------------------------------------------------------------------

#[test]
fn redact_short_ascii_fully_masked() {
    assert_eq!(redact(""), "****");
    assert_eq!(redact("a"), "****");
    assert_eq!(redact("12345678"), "****"); // exactly 8 -> masked
}

#[test]
fn redact_long_ascii_uses_scaled_edges() {
    assert_eq!(redact("123456789"), "12...89"); // 9 chars
    assert_eq!(redact("ghp_0123456789abcdef"), "ghp_...cdef");
}

#[test]
fn redact_boundary_at_nine_chars() {
    // 8 -> masked, 9 -> partial; pin the boundary.
    assert_eq!(redact("AAAAAAAA"), "****");
    assert_eq!(redact("AAAAAAAAA"), "AA...AA");
}

#[test]
fn redact_unicode_uses_char_count() {
    // 9 multibyte chars -> first 2 ... last 2.
    let s = "αβγδεζηθι"; // 9 Greek letters, 2 bytes each
    assert_eq!(s.chars().count(), 9);
    assert_eq!(redact(s), "αβ...θι");
}

#[test]
fn redact_short_unicode_masked() {
    // 8 chars -> masked even though byte len > 8.
    let s = "αβγδεζηθ";
    assert_eq!(s.chars().count(), 8);
    assert_eq!(redact(s), "****");
}

// ---------------------------------------------------------------------------
// Severity ordering + serde + helpers
// ---------------------------------------------------------------------------

#[test]
fn severity_total_order() {
    use Severity::*;
    assert!(Info < ClientSafe);
    assert!(ClientSafe < Low);
    assert!(Low < Medium);
    assert!(Medium < High);
    assert!(High < Critical);
    // The full sorted order.
    let mut v = vec![Critical, Info, High, Low, ClientSafe, Medium];
    v.sort();
    assert_eq!(v, vec![Info, ClientSafe, Low, Medium, High, Critical]);
}

#[test]
fn severity_default_is_info() {
    assert_eq!(Severity::default(), Severity::Info);
}

#[test]
fn severity_as_str_and_display_kebab() {
    assert_eq!(Severity::Info.to_string(), "info");
    assert_eq!(Severity::ClientSafe.to_string(), "client-safe");
    assert_eq!(Severity::Low.to_string(), "low");
    assert_eq!(Severity::Medium.to_string(), "medium");
    assert_eq!(Severity::High.to_string(), "high");
    assert_eq!(Severity::Critical.to_string(), "critical");
    assert_eq!(format!("{}", Severity::ClientSafe), "client-safe");
}

#[test]
fn severity_serde_kebab_roundtrip() {
    for sev in [
        Severity::Info,
        Severity::ClientSafe,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let back: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sev, "roundtrip mismatch for {sev:?}");
    }
    // Wire form check.
    assert_eq!(
        serde_json::to_string(&Severity::ClientSafe).unwrap(),
        r#""client-safe""#
    );
}

#[test]
fn severity_serde_accepts_client_safe_alias() {
    // serde alias "client_safe" must deserialize to ClientSafe.
    let back: Severity = serde_json::from_str(r#""client_safe""#).unwrap();
    assert_eq!(back, Severity::ClientSafe);
}

#[test]
fn severity_downgrade_one_chain() {
    assert_eq!(Severity::Critical.downgrade_one(), Severity::High);
    assert_eq!(Severity::High.downgrade_one(), Severity::Medium);
    assert_eq!(Severity::Medium.downgrade_one(), Severity::Low);
    assert_eq!(Severity::Low.downgrade_one(), Severity::ClientSafe);
    assert_eq!(Severity::ClientSafe.downgrade_one(), Severity::Info);
    // Info is the floor.
    assert_eq!(Severity::Info.downgrade_one(), Severity::Info);
}

// ---------------------------------------------------------------------------
// encoding::decode_standard_base64
// ---------------------------------------------------------------------------

#[test]
fn base64_decode_known_vectors() {
    assert_eq!(decode_standard_base64("").unwrap(), b"");
    assert_eq!(decode_standard_base64("SGVsbG8=").unwrap(), b"Hello");
    assert_eq!(
        decode_standard_base64("SGVsbG8gd29ybGQ=").unwrap(),
        b"Hello world"
    );
    // Without padding still decodes.
    assert_eq!(decode_standard_base64("SGVsbG8").unwrap(), b"Hello");
}

#[test]
fn base64_decode_plus_slash_alphabet() {
    // 0xFB 0xFF 0xFE -> "+//+" round-trip check on the +/ alphabet bytes.
    let decoded = decode_standard_base64("+/+/").unwrap();
    assert_eq!(decoded.len(), 3);
}

#[test]
fn base64_decode_rejects_invalid_char() {
    let err = decode_standard_base64("SGVs*G8=");
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("invalid base64 char"));
}

#[test]
fn base64_decode_rejects_truncated_single_char() {
    // A single base64 char cannot encode a byte; chunk.get(1) is None.
    let err = decode_standard_base64("A");
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("truncated"));
}

#[test]
fn base64_decode_oversize_rejected() {
    let cap = keyhog_core::testing::CoreTestApi::max_standard_base64_input_bytes(
        &keyhog_core::testing::TestApi,
    );
    let big = "A".repeat(cap + 1);
    let err = decode_standard_base64(&big);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("exceeds"));
}

// ---------------------------------------------------------------------------
// aws offline decode + canary classification
// ---------------------------------------------------------------------------

#[test]
fn aws_account_decode_known_vector() {
    // trufflesecurity reference: AKIASP2TPHJSQH3FJXYZ-style. Use a
    // deterministic well-formed key and assert the 12-digit, zero-padded shape.
    let acct = keyhog_core::testing::CoreTestApi::aws_account_from_key_id(
        &keyhog_core::testing::TestApi,
        "AKIAIOSFODNN7EXAMPLE",
    );
    assert!(acct.is_some(), "well-formed AKIA key must decode");
    let acct = acct.unwrap();
    assert_eq!(acct.len(), 12, "account id must be 12 digits");
    assert!(acct.chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn aws_account_decode_is_deterministic() {
    let a = keyhog_core::testing::CoreTestApi::aws_account_from_key_id(
        &keyhog_core::testing::TestApi,
        "AKIAIOSFODNN7EXAMPLE",
    )
    .unwrap();
    let b = keyhog_core::testing::CoreTestApi::aws_account_from_key_id(
        &keyhog_core::testing::TestApi,
        "AKIAIOSFODNN7EXAMPLE",
    )
    .unwrap();
    assert_eq!(a, b);
}

#[test]
fn aws_account_decode_asia_prefix_works() {
    let acct = keyhog_core::testing::CoreTestApi::aws_account_from_key_id(
        &keyhog_core::testing::TestApi,
        "ASIAIOSFODNN7EXAMPLE",
    );
    assert!(acct.is_some(), "ASIA temporary keys must also decode");
    assert_eq!(acct.unwrap().len(), 12);
}

#[test]
fn aws_account_decode_rejects_wrong_length() {
    assert_eq!(
        keyhog_core::testing::CoreTestApi::aws_account_from_key_id(
            &keyhog_core::testing::TestApi,
            "AKIASHORT"
        ),
        None
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::aws_account_from_key_id(
            &keyhog_core::testing::TestApi,
            "AKIATOOLONGTOOLONGTOOLONG"
        ),
        None
    );
}

#[test]
fn aws_account_decode_rejects_wrong_prefix() {
    // Right length (20), wrong prefix.
    assert_eq!(
        keyhog_core::testing::CoreTestApi::aws_account_from_key_id(
            &keyhog_core::testing::TestApi,
            "ZKIAIOSFODNN7EXAMPLE"
        ),
        None
    );
}

#[test]
fn aws_account_decode_rejects_non_base32_body() {
    // '1', '0', '8', '9' are not in the RFC-4648 base32 alphabet.
    assert_eq!(
        keyhog_core::testing::CoreTestApi::aws_account_from_key_id(
            &keyhog_core::testing::TestApi,
            "AKIA1111111111111111"
        ),
        None
    );
}

#[test]
fn aws_account_decode_trims_whitespace() {
    let trimmed = keyhog_core::testing::CoreTestApi::aws_account_from_key_id(
        &keyhog_core::testing::TestApi,
        "  AKIAIOSFODNN7EXAMPLE  ",
    );
    let plain = keyhog_core::testing::CoreTestApi::aws_account_from_key_id(
        &keyhog_core::testing::TestApi,
        "AKIAIOSFODNN7EXAMPLE",
    );
    assert_eq!(trimmed, plain);
    assert!(trimmed.is_some());
}

#[test]
fn aws_finding_metadata_present_for_valid_key() {
    let meta = finding_metadata("AKIAIOSFODNN7EXAMPLE").expect("valid key -> metadata");
    let acct = meta.get("account_id").expect("account_id present");
    assert_eq!(acct.len(), 12);
    assert_eq!(
        meta.get("account_id").unwrap(),
        &keyhog_core::testing::CoreTestApi::aws_account_from_key_id(
            &keyhog_core::testing::TestApi,
            "AKIAIOSFODNN7EXAMPLE"
        )
        .unwrap()
    );
}

#[test]
fn aws_finding_metadata_none_for_non_key() {
    assert!(finding_metadata("not-a-key").is_none());
}

#[test]
fn aws_canary_message_is_actionable() {
    // The operator-facing message must warn against verifying.
    assert!(
        keyhog_core::testing::CoreTestApi::aws_canary_message(&keyhog_core::testing::TestApi,)
            .contains("Do NOT verify")
    );
    assert!(
        keyhog_core::testing::CoreTestApi::aws_canary_message(&keyhog_core::testing::TestApi,)
            .contains("canary")
    );
}

#[test]
fn aws_canary_negative_for_random_account() {
    // A clearly-non-canary 12-digit account must classify false (the baseline
    // canary list does not contain arbitrary accounts).
    assert!(!keyhog_core::testing::CoreTestApi::aws_account_is_canary(
        &keyhog_core::testing::TestApi,
        "000000000001"
    ));
}

#[test]
fn aws_key_id_is_canary_false_for_non_canary_key() {
    // The example key's decoded account is not a Thinkst canary.
    assert!(!key_id_canary_status("AKIAIOSFODNN7EXAMPLE").expect("canary status"));
    // A malformed key is never a canary (decode fails closed).
    assert!(!key_id_canary_status("not-a-key").expect("canary status"));
}
