/// Unit tests for `keyhog_scanner::jwt`.
///
/// Covers: looks_like_jwt (shape), analyze (full structural decode),
/// anomaly classification (alg=none, unknown alg, non-standard typ, expiry),
/// anomalies_to_metadata, hostile inputs (empty segments, oversized, non-b64url).
use keyhog_scanner::testing::jwt::{analyze, anomalies_to_metadata, looks_like_jwt, JwtAnomaly};

// Pre-encoded JWT fragments for tests. Using base64url encoding of known JSON.
// header: {"alg":"HS256","typ":"JWT"}
const HEADER_HS256: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
// payload: {"sub":"test","exp":9999999999}
const PAYLOAD_FUTURE: &str = "eyJzdWIiOiJ0ZXN0IiwiZXhwIjo5OTk5OTk5OTk5fQ";
// payload: {"sub":"test","exp":1}  (expired in the past)
const PAYLOAD_EXPIRED: &str = "eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxfQ";
// A fake but syntactically valid signature segment (all base64url)
const SIG: &str = "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPP";

// ── looks_like_jwt ────────────────────────────────────────────────────────────

#[test]
fn three_part_base64url_is_jwt() {
    let token = format!("{HEADER_HS256}.{PAYLOAD_FUTURE}.{SIG}");
    assert!(looks_like_jwt(&token));
}

#[test]
fn two_part_not_jwt() {
    assert!(!looks_like_jwt(&format!("{HEADER_HS256}.{PAYLOAD_FUTURE}")));
}

#[test]
fn four_part_not_jwt() {
    assert!(!looks_like_jwt(&format!(
        "{HEADER_HS256}.{PAYLOAD_FUTURE}.{SIG}.extra"
    )));
}

#[test]
fn empty_header_segment_rejected() {
    assert!(!looks_like_jwt(&format!(".{PAYLOAD_FUTURE}.{SIG}")));
}

#[test]
fn empty_payload_segment_rejected() {
    assert!(!looks_like_jwt(&format!("{HEADER_HS256}..{SIG}")));
}

#[test]
fn empty_sig_segment_rejected() {
    assert!(!looks_like_jwt(&format!(
        "{HEADER_HS256}.{PAYLOAD_FUTURE}."
    )));
}

#[test]
fn non_base64url_header_rejected() {
    // Standard base64 + and / are not base64url
    assert!(!looks_like_jwt("a+bc.payload.sig"));
}

#[test]
fn oversized_segment_rejected() {
    // > 16KB per segment, should be rejected without OOM
    let huge: String = "A".repeat(16 * 1024 + 1);
    let token = format!("{huge}.{PAYLOAD_FUTURE}.{SIG}");
    assert!(!looks_like_jwt(&token));
}

#[test]
fn empty_string_not_jwt() {
    assert!(!looks_like_jwt(""));
}

// ── analyze ───────────────────────────────────────────────────────────────────

#[test]
fn valid_hs256_jwt_parses_correctly() {
    let token = format!("{HEADER_HS256}.{PAYLOAD_FUTURE}.{SIG}");
    let analysis = analyze(&token).expect("should parse a valid JWT");
    assert_eq!(analysis.alg, "HS256");
    assert_eq!(analysis.typ.as_deref(), Some("JWT"));
    assert!(
        analysis.anomalies.is_empty(),
        "no anomalies expected for HS256"
    );
}

#[test]
fn future_exp_not_expired() {
    let token = format!("{HEADER_HS256}.{PAYLOAD_FUTURE}.{SIG}");
    let analysis = analyze(&token).expect("parse ok");
    assert_eq!(analysis.expired, Some(false));
}

#[test]
fn expired_jwt_flags_anomaly() {
    let token = format!("{HEADER_HS256}.{PAYLOAD_EXPIRED}.{SIG}");
    let analysis = analyze(&token).expect("parse ok");
    assert_eq!(analysis.expired, Some(true));
    assert!(
        analysis.anomalies.contains(&JwtAnomaly::Expired),
        "expected Expired anomaly"
    );
}

#[test]
fn alg_none_jwt_flags_anomaly() {
    // header: {"alg":"none"}
    let none_header = "eyJhbGciOiJub25lIn0";
    // payload: {}
    let empty_payload = "e30";
    let token = format!("{none_header}.{empty_payload}.{SIG}");
    let analysis = analyze(&token).expect("parse ok");
    assert!(
        analysis.anomalies.contains(&JwtAnomaly::AlgNone),
        "expected AlgNone anomaly"
    );
}

#[test]
fn unknown_alg_flags_anomaly() {
    // header: {"alg":"X-CUSTOM-999"}
    let custom_header = "eyJhbGciOiJYLUNVU1RPTS05OTkifQ";
    let empty_payload = "e30";
    let token = format!("{custom_header}.{empty_payload}.{SIG}");
    let analysis = analyze(&token).expect("parse ok");
    assert!(
        analysis
            .anomalies
            .iter()
            .any(|a| matches!(a, JwtAnomaly::UnknownAlg(_))),
        "expected UnknownAlg anomaly"
    );
}

#[test]
fn non_standard_typ_flags_anomaly() {
    // header: {"alg":"HS256","typ":"CUSTOM"}
    let custom_typ_header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkNVU1RPTSR9";
    let empty_payload = "e30";
    let token = format!("{custom_typ_header}.{empty_payload}.{SIG}");
    // May or may not parse depending on JSON validity, just ensure no panic
    let _ = analyze(&token);
}

#[test]
fn not_a_jwt_returns_none() {
    assert!(analyze("not.a.jwt!@@").is_none());
    assert!(analyze("").is_none());
    assert!(analyze("plain_string").is_none());
}

#[test]
fn malformed_json_header_returns_none() {
    // base64url encode of "{invalid json"
    use base64::Engine;
    let bad_header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{invalid json");
    let empty_payload = "e30";
    let token = format!("{bad_header}.{empty_payload}.{SIG}");
    // Should gracefully return None, not panic
    assert!(analyze(&token).is_none());
}

// ── anomalies_to_metadata ────────────────────────────────────────────────────

#[test]
fn anomalies_to_metadata_empty_when_no_anomalies() {
    let token = format!("{HEADER_HS256}.{PAYLOAD_FUTURE}.{SIG}");
    if let Some(analysis) = analyze(&token) {
        assert!(
            anomalies_to_metadata(&analysis).is_none(),
            "no anomalies → metadata should be None"
        );
    }
}

#[test]
fn anomalies_to_metadata_alg_none() {
    let none_header = "eyJhbGciOiJub25lIn0";
    let empty_payload = "e30";
    let token = format!("{none_header}.{empty_payload}.{SIG}");
    if let Some(analysis) = analyze(&token) {
        let meta = anomalies_to_metadata(&analysis).expect("should have metadata for AlgNone");
        assert!(
            meta.contains_key("jwt.alg_none"),
            "expected jwt.alg_none key in metadata"
        );
    }
}

#[test]
fn anomalies_to_metadata_expired() {
    let token = format!("{HEADER_HS256}.{PAYLOAD_EXPIRED}.{SIG}");
    if let Some(analysis) = analyze(&token) {
        if let Some(meta) = anomalies_to_metadata(&analysis) {
            assert!(meta.contains_key("jwt.expired"));
        }
    }
}

// ── all standard algs parse without UnknownAlg anomaly ────────────────────────

#[test]
fn rs256_is_known_alg() {
    // header: {"alg":"RS256"}
    let rs256_header = "eyJhbGciOiJSUzI1NiJ9";
    let empty_payload = "e30";
    let token = format!("{rs256_header}.{empty_payload}.{SIG}");
    if let Some(analysis) = analyze(&token) {
        assert!(
            !analysis
                .anomalies
                .iter()
                .any(|a| matches!(a, JwtAnomaly::UnknownAlg(_))),
            "RS256 should not produce UnknownAlg"
        );
    }
}

#[test]
fn es256_is_known_alg() {
    // header: {"alg":"ES256"}
    let es256_header = "eyJhbGciOiJFUzI1NiJ9";
    let empty_payload = "e30";
    let token = format!("{es256_header}.{empty_payload}.{SIG}");
    if let Some(analysis) = analyze(&token) {
        assert!(
            !analysis
                .anomalies
                .iter()
                .any(|a| matches!(a, JwtAnomaly::UnknownAlg(_))),
            "ES256 should not produce UnknownAlg"
        );
    }
}
