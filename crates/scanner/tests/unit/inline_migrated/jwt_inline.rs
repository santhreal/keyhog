//! Migrated from src/jwt.rs

use keyhog_scanner::jwt::{analyze, looks_like_jwt, JwtAnomaly};

/// Standard HS256 JWT, payload `{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
/// signed with HMAC `your-256-bit-secret`.
const JWT_HS256: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

#[test]
fn looks_like_jwt_accepts_standard_shape() {
    assert!(looks_like_jwt(JWT_HS256));
}

#[test]
fn looks_like_jwt_rejects_two_segments() {
    assert!(!looks_like_jwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0"));
}

#[test]
fn looks_like_jwt_rejects_random_base64() {
    assert!(!looks_like_jwt("aaa+aa.bbb.ccc"));
}

#[test]
fn analyze_returns_alg_and_typ() {
    let a = analyze(JWT_HS256).expect("analyzes");
    assert_eq!(a.alg, "HS256");
    assert_eq!(a.typ.as_deref(), Some("JWT"));
    assert_eq!(a.sub.as_deref(), Some("1234567890"));
    assert!(a.anomalies.is_empty());
}

#[test]
fn analyze_flags_alg_none() {
    let none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.AAAA";
    let a = analyze(none_jwt).expect("analyzes");
    assert_eq!(a.alg, "none");
    assert!(a.anomalies.iter().any(|x| matches!(x, JwtAnomaly::AlgNone)));
}

#[test]
fn analyze_flags_unknown_alg() {
    use base64::Engine;
    let header =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"XX256","typ":"JWT"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{}");
    let token = format!("{header}.{payload}.AAAA");
    let a = analyze(&token).expect("analyzes");
    assert!(a
        .anomalies
        .iter()
        .any(|x| matches!(x, JwtAnomaly::UnknownAlg(_))));
}
