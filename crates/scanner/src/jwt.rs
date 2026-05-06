//! JWT structural validation.
//!
//! A bare JWT regex (three base64url segments separated by dots) catches an
//! enormous number of false positives — Etag headers, hash digests, opaque
//! session IDs, tracking pixels, etc. This module decodes the header +
//! payload and validates the JWT shape (`alg`/`typ`/`exp`) so we can:
//!
//!   1. Boost confidence on credentials that ARE real JWTs (correctly
//!      structured header + valid algorithm).
//!   2. Suppress credentials that LOOK like JWTs but aren't (random base64,
//!      malformed header).
//!   3. Surface metadata: `alg`, `iss`, `sub`, `aud`, `exp` as evidence in
//!      the finding output, helping responders rotate the right credential.
//!   4. Flag `alg=none` JWTs as a SECURITY ANOMALY — these are unsigned,
//!      forgeable, and almost always indicate a misconfiguration or active
//!      attack.

#![deny(unsafe_code)]

use serde::Deserialize;
use std::collections::BTreeMap;

#[cfg(test)]
use base64::Engine as _;

/// Result of a JWT structural check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtAnalysis {
    /// Header `alg` field (e.g. `RS256`, `HS256`, `none`).
    pub alg: String,
    /// Header `typ` field when present (typically `JWT` or `at+jwt`).
    pub typ: Option<String>,
    /// Header `kid` field — useful for key-rotation forensics.
    pub kid: Option<String>,
    /// Payload `iss` claim — surfaces the issuer service.
    pub iss: Option<String>,
    /// Payload `sub` claim — subject (user/service identifier).
    pub sub: Option<String>,
    /// Payload `aud` claim — single audience or comma-joined list.
    pub aud: Option<String>,
    /// Payload `exp` claim, if numeric.
    pub exp: Option<i64>,
    /// Whether the JWT has expired relative to `Instant::now`.
    pub expired: Option<bool>,
    /// Anomalies detected during analysis. Non-empty implies a suspicious
    /// JWT that warrants higher reporting severity.
    pub anomalies: Vec<JwtAnomaly>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JwtAnomaly {
    /// `alg = "none"` — unsigned token. Should never appear in production
    /// credentials; almost always a misconfiguration or active forgery
    /// attack. RFC 7519 §6 calls this out as risky.
    AlgNone,
    /// Algorithm not on the standard registry list. Legitimate JWTs use a
    /// well-known algorithm (RS256, HS256, ES256, …); custom values are
    /// rare and frequently indicate fake / handcrafted tokens.
    UnknownAlg(String),
    /// `typ` present but not in the standard set (`JWT`, `at+jwt`, `id+jwt`,
    /// `dpop+jwt`).
    NonStandardTyp(String),
    /// Token already expired.
    Expired,
}

/// Render anomalies into a `metadata` map suitable for SARIF properties or
/// the text reporter. Returns `None` when there are no anomalies.
pub fn anomalies_to_metadata(analysis: &JwtAnalysis) -> Option<BTreeMap<String, String>> {
    if analysis.anomalies.is_empty() {
        return None;
    }
    let mut out = BTreeMap::new();
    for anomaly in &analysis.anomalies {
        match anomaly {
            JwtAnomaly::AlgNone => {
                out.insert(
                    "jwt.alg_none".to_string(),
                    "true (unsigned token — RFC 7519 §6 risk)".to_string(),
                );
            }
            JwtAnomaly::UnknownAlg(alg) => {
                out.insert("jwt.unknown_alg".to_string(), alg.clone());
            }
            JwtAnomaly::NonStandardTyp(typ) => {
                out.insert("jwt.non_standard_typ".to_string(), typ.clone());
            }
            JwtAnomaly::Expired => {
                out.insert("jwt.expired".to_string(), "true".to_string());
            }
        }
    }
    Some(out)
}

/// Returns `true` when `s` looks like a JWT (three base64url segments).
/// Cheap shape check — does NOT decode.
pub fn looks_like_jwt(s: &str) -> bool {
    const MAX_JWT_SEGMENT_LEN: usize = 16 * 1024; // 16KB limit per segment

    let mut parts = s.split('.');
    let (Some(h), Some(p), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };

    // Length gate to prevent quadratic DoS on pathological inputs (millions of dots)
    if h.len() > MAX_JWT_SEGMENT_LEN
        || p.len() > MAX_JWT_SEGMENT_LEN
        || sig.len() > MAX_JWT_SEGMENT_LEN
    {
        return false;
    }

    !h.is_empty()
        && !p.is_empty()
        && !sig.is_empty()
        && h.bytes().all(is_base64url_byte)
        && p.bytes().all(is_base64url_byte)
        && sig.bytes().all(is_base64url_byte)
}

/// Full structural analysis. Returns `None` if `s` is not a parseable JWT
/// (missing dots, non-base64url header/payload, malformed JSON inside).
///
/// Signature verification is intentionally NOT performed — that requires
/// the issuer's public key, which we don't have. Structural validation is
/// the high-recall layer; the verifier crate handles cryptographic checks
/// for services that expose them.
pub fn analyze(s: &str) -> Option<JwtAnalysis> {
    if !looks_like_jwt(s) {
        return None;
    }
    let mut parts = s.split('.');
    let header_b64 = parts.next()?;
    let payload_b64 = parts.next()?;
    // We don't read the signature segment beyond the shape check.
    let _signature_b64 = parts.next()?;

    let header_json = decode_b64url(header_b64)?;
    let payload_json = decode_b64url(payload_b64)?;

    let header: JwtHeader = serde_json::from_slice(&header_json).ok()?;
    let mut payload: JwtPayload = serde_json::from_slice(&payload_json).ok()?;
    let aud = payload.take_aud();
    let iss = payload.iss.take();
    let sub = payload.sub.take();

    let mut anomalies = Vec::new();

    let alg = header.alg.unwrap_or_else(|| "<missing>".to_string());
    if alg.eq_ignore_ascii_case("none") {
        anomalies.push(JwtAnomaly::AlgNone);
    } else if !is_known_alg(&alg) {
        anomalies.push(JwtAnomaly::UnknownAlg(alg.clone()));
    }

    if let Some(typ) = header.typ.as_deref() {
        if !is_standard_typ(typ) {
            anomalies.push(JwtAnomaly::NonStandardTyp(typ.to_string()));
        }
    }

    let expired = payload.exp.map(|exp| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let is_expired = now >= exp;
        if is_expired {
            anomalies.push(JwtAnomaly::Expired);
        }
        is_expired
    });

    Some(JwtAnalysis {
        alg,
        typ: header.typ,
        kid: header.kid,
        iss,
        sub,
        aud,
        exp: payload.exp,
        expired,
        anomalies,
    })
}

#[inline]
fn is_base64url_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'='
}

fn decode_b64url(s: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    // Strip any padding the input might have (base64url is unpadded by spec).
    let trimmed = s.trim_end_matches('=');
    URL_SAFE_NO_PAD.decode(trimmed).ok()
}

fn is_known_alg(alg: &str) -> bool {
    matches!(
        alg,
        "RS256"
            | "RS384"
            | "RS512"
            | "HS256"
            | "HS384"
            | "HS512"
            | "ES256"
            | "ES384"
            | "ES512"
            | "ES256K"
            | "PS256"
            | "PS384"
            | "PS512"
            | "EdDSA"
    )
}

fn is_standard_typ(typ: &str) -> bool {
    matches!(typ, "JWT" | "at+jwt" | "id+jwt" | "dpop+jwt" | "logout+jwt")
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: Option<String>,
    typ: Option<String>,
    kid: Option<String>,
}

#[derive(Deserialize)]
struct JwtPayload {
    iss: Option<String>,
    sub: Option<String>,
    #[serde(default)]
    aud: serde_json::Value,
    exp: Option<i64>,
}

impl JwtPayload {
    fn take_aud(&mut self) -> Option<String> {
        match std::mem::take(&mut self.aud) {
            serde_json::Value::String(s) if !s.is_empty() => Some(s),
            serde_json::Value::Array(items) if !items.is_empty() => {
                let joined: Vec<String> = items
                    .into_iter()
                    .filter_map(|v| match v {
                        serde_json::Value::String(s) => Some(s),
                        _ => None,
                    })
                    .collect();
                if joined.is_empty() {
                    None
                } else {
                    Some(joined.join(","))
                }
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Three segments but contains '+' which is base64-standard, not -url.
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
        // Header `{"alg":"none","typ":"JWT"}` base64url, payload `{}`. The
        // signature segment must be non-empty for `looks_like_jwt` to accept
        // the shape — `alg=none` JWTs in the wild typically still emit a
        // dummy signature segment for transport compatibility, even though
        // it carries no cryptographic meaning. We mirror that here.
        let none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.AAAA";
        let a = analyze(none_jwt).expect("analyzes");
        assert_eq!(a.alg, "none");
        assert!(a.anomalies.iter().any(|x| matches!(x, JwtAnomaly::AlgNone)));
    }

    #[test]
    fn analyze_flags_unknown_alg() {
        // Header `{"alg":"XX256","typ":"JWT"}`.
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"XX256","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{}");
        let token = format!("{header}.{payload}.AAAA");
        let a = analyze(&token).expect("analyzes");
        assert!(a
            .anomalies
            .iter()
            .any(|x| matches!(x, JwtAnomaly::UnknownAlg(_))));
    }
}
