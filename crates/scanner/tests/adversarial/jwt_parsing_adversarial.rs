//! Adversarial tests for JWT structural validation.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use keyhog_scanner::jwt::{analyze, looks_like_jwt, JwtAnomaly};

fn make_jwt(header: &str, payload: &str, sig: &str) -> String {
    let h_b64 = URL_SAFE_NO_PAD.encode(header);
    let p_b64 = URL_SAFE_NO_PAD.encode(payload);
    format!("{}.{}.{}", h_b64, p_b64, sig)
}

#[test]
fn test_deeply_nested_json_dos() {
    // 500 levels of nested JSON objects to trigger parser recursion limits
    let mut deep_header = String::new();
    for _ in 0..500 {
        deep_header.push_str(r#"{"a":"#);
    }
    deep_header.push_str(r#""b""#);
    for _ in 0..500 {
        deep_header.push_str(r#"}"#);
    }

    let token = make_jwt(&deep_header, r#"{"sub":"123"}"#, "sig");
    let result = analyze(&token);
    // Should return None safely because serde_json hits recursion limit rather than overflowing stack
    assert!(result.is_none());
}

#[test]
fn test_malformed_base64url_inputs() {
    // segment containing '+' and '/' which are standard base64 but not base64url
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ==.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV/adQssw5c+";
    assert!(!looks_like_jwt(token));
    assert!(analyze(token).is_none());
}

#[test]
fn test_whitespace_padded_segments() {
    // Valid HS256 JWT surrounded by whitespace
    let raw_token = "   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n\r  ";
    assert!(looks_like_jwt(raw_token));
    let result = analyze(raw_token).expect("should parse white-space padded JWT");
    assert_eq!(result.alg, "HS256");
    assert_eq!(result.sub.as_deref(), Some("1234567890"));
}

#[test]
fn test_invalid_utf8_in_decoded_json() {
    // raw invalid UTF-8 bytes encoded as base64url
    let invalid_utf8_bytes = vec![0xc3, 0x28];
    let h_b64 = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256"}"#);
    let p_b64 = URL_SAFE_NO_PAD.encode(&invalid_utf8_bytes);
    let token = format!("{}.{}.sig", h_b64, p_b64);

    let result = analyze(&token);
    // Should fail to parse as JSON or invalid UTF-8
    assert!(result.is_none());
}

#[test]
fn test_extreme_expiration_timestamps() {
    // 1. exp overflows i64 (huge number)
    let payload_overflow = r#"{"sub":"123","exp":9999999999999999999999999999999999999999}"#;
    let token1 = make_jwt(r#"{"alg":"HS256"}"#, payload_overflow, "sig");
    let res1 = analyze(&token1).expect("should still parse JWT despite exp overflow");
    assert_eq!(res1.exp, None); // exp parsed to None, but the JWT is parsed successfully!

    // 2. exp underflows i64 (huge negative number)
    let payload_underflow = r#"{"sub":"123","exp":-9999999999999999999999999999999999999999}"#;
    let token2 = make_jwt(r#"{"alg":"HS256"}"#, payload_underflow, "sig");
    let res2 = analyze(&token2).expect("should still parse JWT despite exp underflow");
    assert_eq!(res2.exp, None);

    // 3. exp is a float
    let payload_float = r#"{"sub":"123","exp":1516239022.123}"#;
    let token3 = make_jwt(r#"{"alg":"HS256"}"#, payload_float, "sig");
    let res3 = analyze(&token3).expect("should still parse JWT despite exp being float");
    assert_eq!(res3.exp, None);

    // 4. exp is a string
    let payload_string = r#"{"sub":"123","exp":"1516239022"}"#;
    let token4 = make_jwt(r#"{"alg":"HS256"}"#, payload_string, "sig");
    let res4 = analyze(&token4).expect("should still parse JWT despite exp being string");
    assert_eq!(res4.exp, None);
}

#[test]
fn test_custom_unregistered_alg_and_typ() {
    let header = r#"{"alg":"CUSTOM-256","typ":"custom-token"}"#;
    let token = make_jwt(header, r#"{"sub":"123"}"#, "sig");
    let res = analyze(&token).expect("should parse JWT with custom alg and typ");

    assert_eq!(res.alg, "CUSTOM-256");
    assert_eq!(res.typ.as_deref(), Some("custom-token"));

    // Verify anomalies are detected
    let anomalies = res.anomalies;
    assert!(anomalies
        .iter()
        .any(|a| matches!(a, JwtAnomaly::UnknownAlg(s) if s == "CUSTOM-256")));
    assert!(anomalies
        .iter()
        .any(|a| matches!(a, JwtAnomaly::NonStandardTyp(s) if s == "custom-token")));
}
