//! Standalone unit coverage for `keyhog_scanner::jwt`.
//!
//! Builds real JWTs (base64url header.payload.sig) and asserts the exact
//! parsed `alg`/`iss`/`sub`/`exp`, the precise `JwtAnomaly` set (notably the
//! `alg=none` forgery signal), and the shape-gate behaviour (never `is_some`).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use keyhog_scanner::jwt::finding_metadata;
use keyhog_scanner::testing::jwt::{analyze, anomalies_to_metadata, looks_like_jwt, JwtAnomaly};

/// Assemble a `header.payload.sig` JWT from raw JSON, base64url-no-pad encoded.
fn make_jwt(header_json: &str, payload_json: &str) -> String {
    let h = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let p = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    // Signature segment only needs to be non-empty base64url; content unread.
    format!("{h}.{p}.c2lnbmF0dXJl")
}

// ---------------------------------------------------------------------------
// looks_like_jwt, shape gate
// ---------------------------------------------------------------------------

#[test]
fn looks_like_jwt_accepts_three_base64url_segments() {
    let jwt = make_jwt(r#"{"alg":"HS256","typ":"JWT"}"#, r#"{"sub":"u"}"#);
    assert!(looks_like_jwt(&jwt));
}

#[test]
fn looks_like_jwt_rejects_two_segments() {
    assert!(!looks_like_jwt("aaaa.bbbb"));
}

#[test]
fn looks_like_jwt_rejects_four_segments() {
    assert!(!looks_like_jwt("aaaa.bbbb.cccc.dddd"));
}

#[test]
fn looks_like_jwt_rejects_empty_segment() {
    assert!(!looks_like_jwt("aaaa..cccc"));
}

#[test]
fn looks_like_jwt_rejects_non_base64url_chars() {
    // A space is not a base64url byte.
    assert!(!looks_like_jwt("aa aa.bbbb.cccc"));
}

// ---------------------------------------------------------------------------
// analyze, real claim extraction
// ---------------------------------------------------------------------------

#[test]
fn analyze_extracts_alg_and_claims() {
    let jwt = make_jwt(
        r#"{"alg":"RS256","typ":"JWT","kid":"key-1"}"#,
        r#"{"iss":"https://auth.example.com","sub":"user-42","aud":"api"}"#,
    );
    let a = analyze(&jwt).expect("valid JWT must analyze");
    assert_eq!(a.alg, "RS256");
    assert_eq!(a.typ.as_deref(), Some("JWT"));
    assert_eq!(a.kid.as_deref(), Some("key-1"));
    assert_eq!(a.iss.as_deref(), Some("https://auth.example.com"));
    assert_eq!(a.sub.as_deref(), Some("user-42"));
    assert_eq!(a.aud.as_deref(), Some("api"));
    // RS256 is a known alg, JWT is a standard typ -> no anomalies.
    assert!(a.anomalies.is_empty());
}

#[test]
fn analyze_joins_array_audience() {
    let jwt = make_jwt(r#"{"alg":"HS256"}"#, r#"{"aud":["api","admin","web"]}"#);
    let a = analyze(&jwt).expect("valid JWT");
    assert_eq!(a.aud.as_deref(), Some("api,admin,web"));
}

#[test]
fn analyze_flags_alg_none_as_forgery_anomaly() {
    let jwt = make_jwt(r#"{"alg":"none"}"#, r#"{"sub":"attacker"}"#);
    let a = analyze(&jwt).expect("alg=none is still a parseable JWT");
    assert_eq!(a.alg, "none");
    assert!(
        a.anomalies.contains(&JwtAnomaly::AlgNone),
        "alg=none must raise the AlgNone anomaly"
    );
}

#[test]
fn analyze_flags_unknown_alg() {
    let jwt = make_jwt(r#"{"alg":"HS999"}"#, r#"{"sub":"x"}"#);
    let a = analyze(&jwt).expect("valid JWT");
    assert_eq!(a.alg, "HS999");
    assert!(a
        .anomalies
        .contains(&JwtAnomaly::UnknownAlg("HS999".to_string())));
}

#[test]
fn analyze_flags_non_standard_typ() {
    let jwt = make_jwt(r#"{"alg":"HS256","typ":"weird+type"}"#, r#"{"sub":"x"}"#);
    let a = analyze(&jwt).expect("valid JWT");
    assert!(a
        .anomalies
        .contains(&JwtAnomaly::NonStandardTyp("weird+type".to_string())));
}

#[test]
fn analyze_flags_expired_token() {
    // exp far in the past (year 2001) -> Expired anomaly + expired==Some(true).
    let jwt = make_jwt(r#"{"alg":"HS256"}"#, r#"{"sub":"x","exp":1000000000}"#);
    let a = analyze(&jwt).expect("valid JWT");
    assert_eq!(a.exp, Some(1_000_000_000));
    assert_eq!(a.expired, Some(true));
    assert!(a.anomalies.contains(&JwtAnomaly::Expired));
}

#[test]
fn analyze_future_exp_not_expired() {
    // exp in year 4001 -> not expired.
    let jwt = make_jwt(r#"{"alg":"HS256"}"#, r#"{"sub":"x","exp":64060588800}"#);
    let a = analyze(&jwt).expect("valid JWT");
    assert_eq!(a.expired, Some(false));
    assert!(!a.anomalies.contains(&JwtAnomaly::Expired));
}

#[test]
fn analyze_rejects_non_jwt_shape() {
    assert!(analyze("not.a.jwt.at.all").is_none());
    assert!(analyze("plain text").is_none());
}

#[test]
fn analyze_rejects_non_json_header() {
    // Valid base64url segments but the header is not JSON.
    let h = URL_SAFE_NO_PAD.encode(b"this is not json");
    let p = URL_SAFE_NO_PAD.encode(b"{}");
    let jwt = format!("{h}.{p}.c2ln");
    assert!(analyze(&jwt).is_none());
}

#[test]
fn analyze_missing_alg_substitutes_marker() {
    let jwt = make_jwt(r#"{"typ":"JWT"}"#, r#"{"sub":"x"}"#);
    let a = analyze(&jwt).expect("header without alg still parses");
    assert_eq!(a.alg, "<missing>");
}

// ---------------------------------------------------------------------------
// anomalies_to_metadata
// ---------------------------------------------------------------------------

#[test]
fn anomalies_metadata_none_when_clean() {
    let jwt = make_jwt(r#"{"alg":"RS256","typ":"JWT"}"#, r#"{"sub":"x"}"#);
    let a = analyze(&jwt).unwrap();
    assert!(anomalies_to_metadata(&a).is_none());
}

#[test]
fn anomalies_metadata_carries_alg_none_key() {
    let jwt = make_jwt(r#"{"alg":"none"}"#, r#"{"sub":"x"}"#);
    let a = analyze(&jwt).unwrap();
    let meta = anomalies_to_metadata(&a).expect("alg=none yields metadata");
    assert!(meta.contains_key("jwt.alg_none"));
    assert!(meta["jwt.alg_none"].contains("unsigned"));
}

// ---------------------------------------------------------------------------
// finding_metadata, the shared scan/verify/daemon bridge
// ---------------------------------------------------------------------------

#[test]
fn finding_metadata_surfaces_alg_and_claims() {
    let jwt = make_jwt(
        r#"{"alg":"ES256","typ":"JWT"}"#,
        r#"{"iss":"issuer","sub":"subj","exp":64060588800}"#,
    );
    let meta = finding_metadata(&jwt).expect("real JWT yields metadata");
    assert_eq!(meta.get("jwt.alg").map(String::as_str), Some("ES256"));
    assert_eq!(meta.get("jwt.iss").map(String::as_str), Some("issuer"));
    assert_eq!(meta.get("jwt.sub").map(String::as_str), Some("subj"));
    assert_eq!(meta.get("jwt.exp").map(String::as_str), Some("64060588800"));
}

#[test]
fn finding_metadata_none_for_non_jwt() {
    assert!(finding_metadata("ghp_abcdefghij0123456789").is_none());
}

#[test]
fn finding_metadata_includes_alg_none_anomaly_key() {
    let jwt = make_jwt(r#"{"alg":"none"}"#, r#"{"sub":"x"}"#);
    let meta = finding_metadata(&jwt).expect("alg=none JWT yields metadata");
    assert_eq!(meta.get("jwt.alg").map(String::as_str), Some("none"));
    assert!(
        meta.contains_key("jwt.alg_none"),
        "the load-bearing forgery signal must reach the operator"
    );
}
