//! JWT structural validation.
//!
//! A bare JWT regex (three base64url segments separated by dots) catches an
//! enormous number of false positives - Etag headers, hash digests, opaque
//! session IDs, tracking pixels, etc. This module decodes the header +
//! payload and validates the JWT shape (`alg`/`typ`/`exp`) so we can:
//!
//!   1. Boost confidence on credentials that ARE real JWTs (correctly
//!      structured header + valid algorithm).
//!   2. Suppress credentials that LOOK like JWTs but aren't (random base64,
//!      malformed header).
//!   3. Surface metadata: `alg`, `iss`, `sub`, `aud`, `exp` as evidence in
//!      the finding output, helping responders rotate the right credential.
//!   4. Flag `alg=none` JWTs as a SECURITY ANOMALY - these are unsigned,
//!      forgeable, and almost always indicate a misconfiguration or active
//!      attack.

#![deny(unsafe_code)]

use serde::Deserialize;
use std::collections::BTreeMap;

/// Result of a JWT structural check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtAnalysis {
    /// Header `alg` field (e.g. `RS256`, `HS256`, `none`).
    pub alg: String,
    /// Header `typ` field when present (typically `JWT` or `at+jwt`).
    pub typ: Option<String>,
    /// Header `kid` field - useful for key-rotation forensics.
    pub kid: Option<String>,
    /// Payload `iss` claim - surfaces the issuer service.
    pub iss: Option<String>,
    /// Payload `sub` claim - subject (user/service identifier).
    pub sub: Option<String>,
    /// Payload `aud` claim - single audience or comma-joined list.
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
    /// `alg = "none"` - unsigned token. Should never appear in production
    /// credentials; almost always a misconfiguration or active forgery
    /// attack. RFC 7519 §6 calls this out as risky.
    AlgNone,
    /// Algorithm not on the standard registry list. Legitimate JWTs use a
    /// well-known algorithm (RS256, HS256, ES256, …); custom values are
    /// rare and frequently indicate fake / handcrafted tokens.
    UnknownAlg(String),
    /// `typ` present but not in the standard set (`JWT`, `at+jwt`, `id+jwt`,
    /// `dpop+jwt`, `logout+jwt`).
    NonStandardTyp(String),
    /// Token already expired.
    Expired,
}

/// Render anomalies into a `metadata` map suitable for SARIF properties or
/// the text reporter. Returns `None` when there are no anomalies.
pub(crate) fn anomalies_to_metadata(analysis: &JwtAnalysis) -> Option<BTreeMap<String, String>> {
    if analysis.anomalies.is_empty() {
        return None;
    }
    let mut out = BTreeMap::new();
    for anomaly in &analysis.anomalies {
        match anomaly {
            JwtAnomaly::AlgNone => {
                out.insert(
                    "jwt.alg_none".to_string(),
                    "true (unsigned token: RFC 7519 §6 risk)".to_string(),
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

/// Wire the structural analysis of `credential` into a finding's `metadata`
/// map. Returns `None` when `credential` is not a parseable JWT (so non-JWT
/// findings carry no JWT keys); otherwise returns the claim evidence the
/// module doc promises - `jwt.alg`, and any of `jwt.iss` / `jwt.sub` /
/// `jwt.aud` / `jwt.exp` that are present - PLUS every anomaly key from
/// [`anomalies_to_metadata`] (notably `jwt.alg_none` for an unsigned forgery).
///
/// This is the single, shared bridge between the fully-built [`analyze`] and
/// the scan output: the in-process finalize, the verify skip branch, and the
/// daemon-route finalize all call it, so the JWT evidence reaches the operator
/// regardless of route (no `jwt.alg_none` divergence between in-process and
/// daemon). The keys use a `String`/`String` shape so a `VerifiedFinding`'s
/// `HashMap<String, String>` metadata can absorb them directly.
pub fn finding_metadata(credential: &str) -> Option<std::collections::HashMap<String, String>> {
    let analysis = analyze(credential)?;
    // At most eight keys: jwt.alg + up to four claim keys (iss/sub/aud/exp) +
    // up to three anomaly keys (one alg anomaly, non_standard_typ, expired).
    // Reserve up front so this per-finding map never rehashes. Byte-identical
    // output (capacity does not affect HashMap contents or equality).
    let mut meta = std::collections::HashMap::with_capacity(8);

    // The algorithm is the primary structural evidence and is always present
    // (`analyze` substitutes `<missing>` when the header omits it), so surface
    // it unconditionally for any real JWT.
    meta.insert("jwt.alg".to_string(), analysis.alg.clone());
    if let Some(iss) = &analysis.iss {
        meta.insert("jwt.iss".to_string(), iss.clone());
    }
    if let Some(sub) = &analysis.sub {
        meta.insert("jwt.sub".to_string(), sub.clone());
    }
    if let Some(aud) = &analysis.aud {
        meta.insert("jwt.aud".to_string(), aud.clone());
    }
    if let Some(exp) = analysis.exp {
        meta.insert("jwt.exp".to_string(), exp.to_string());
    }

    // Anomaly keys (jwt.alg_none / jwt.unknown_alg / jwt.non_standard_typ /
    // jwt.expired). The dedicated `alg=none` key is the load-bearing security
    // signal: an unsigned, trivially forgeable token.
    if let Some(anomalies) = anomalies_to_metadata(&analysis) {
        for (k, v) in anomalies {
            meta.insert(k, v);
        }
    }

    Some(meta)
}

/// Returns `true` when `s` looks like a JWT (three base64url segments).
/// Cheap shape check - does NOT decode.
#[cfg(test)]
pub(crate) fn looks_like_jwt(s: &str) -> bool {
    jwt_segments(s).is_some()
}

fn jwt_segments(s: &str) -> Option<(&str, &str, &str)> {
    let s = s.trim();
    const MAX_JWT_SEGMENT_LEN: usize = 16 * 1024; // 16KB limit per segment

    let mut parts = s.split('.');
    let (Some(h), Some(p), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };

    // Length gate to prevent quadratic DoS on pathological inputs (millions of dots)
    if h.len() > MAX_JWT_SEGMENT_LEN
        || p.len() > MAX_JWT_SEGMENT_LEN
        || sig.len() > MAX_JWT_SEGMENT_LEN
    {
        return None;
    }

    if !h.is_empty()
        && !p.is_empty()
        && !sig.is_empty()
        && h.bytes().all(is_base64url_byte)
        && p.bytes().all(is_base64url_byte)
        && sig.bytes().all(is_base64url_byte)
    {
        Some((h, p, sig))
    } else {
        None
    }
}

/// Full structural analysis. Returns `None` if `s` is not a parseable JWT
/// (missing dots, non-base64url header/payload, malformed JSON inside).
///
/// Signature verification is intentionally NOT performed - that requires
/// the issuer's public key, which we don't have. Structural validation is
/// the high-recall layer; the verifier crate handles cryptographic checks
/// for services that expose them.
pub(crate) fn analyze(s: &str) -> Option<JwtAnalysis> {
    let (header_b64, payload_b64, _signature_b64) = jwt_segments(s)?;
    // We don't read the signature segment beyond the shape check.

    let header_json = decode_b64url(header_b64)?;
    let payload_json = decode_b64url(payload_b64)?;

    if !check_nesting_depth(&header_json, 15) || !check_nesting_depth(&payload_json, 15) {
        return None;
    }

    let header: JwtHeader = serde_json::from_slice(&header_json).ok()?; // LAW10: malformed input => None (fail-closed at the boundary; not a valid value), recall-safe
    let mut payload: JwtPayload = serde_json::from_slice(&payload_json).ok()?; // LAW10: malformed input => None (fail-closed at the boundary; not a valid value), recall-safe
    let aud = payload.take_aud();
    let iss = payload.iss.take();
    let sub = payload.sub.take();

    let mut anomalies = Vec::new();

    let alg = header.alg.unwrap_or_else(|| "<missing>".to_string()); // LAW10: absent path/field => display placeholder; reporting-only, recall-safe
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

    let exp = payload.exp.take().and_then(json_i64);

    let expired = exp.map(|exp_val| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0); // LAW10: empty/absent => documented numeric/sentinel default, recall-safe
        let is_expired = now >= exp_val;
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
        exp,
        expired,
        anomalies,
    })
}

fn json_i64(value: serde_json::Value) -> Option<i64> {
    match value {
        serde_json::Value::Number(number) => number.as_i64(),
        _ => None,
    }
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
    URL_SAFE_NO_PAD.decode(trimmed).ok() // LAW10: malformed input => None (fail-closed at the boundary; not a valid value), recall-safe
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
    exp: Option<serde_json::Value>,
}

impl JwtPayload {
    fn take_aud(&mut self) -> Option<String> {
        match std::mem::take(&mut self.aud) {
            serde_json::Value::String(s) if !s.is_empty() => Some(s),
            serde_json::Value::Array(items) if !items.is_empty() => join_audience_strings(items),
            _ => None,
        }
    }
}

fn join_audience_strings(items: Vec<serde_json::Value>) -> Option<String> {
    let mut strings = items.into_iter().filter_map(|value| match value {
        serde_json::Value::String(value) => Some(value),
        _ => None,
    });
    let mut joined = strings.next()?;
    for audience in strings {
        joined.push(',');
        joined.push_str(&audience);
    }
    Some(joined)
}

fn check_nesting_depth(json: &[u8], max_depth: usize) -> bool {
    let mut depth = 0;
    let mut in_string = false;
    let mut escaped = false;
    for &b in json {
        if escaped {
            escaped = false;
            continue;
        }
        if b == b'\\' {
            if in_string {
                escaped = true;
            }
            continue;
        }
        if b == b'"' {
            in_string = !in_string;
            continue;
        }
        if !in_string {
            if b == b'{' || b == b'[' {
                depth += 1;
                if depth > max_depth {
                    return false;
                }
            } else if b == b'}' || b == b']' {
                depth = depth.saturating_sub(1);
            }
        }
    }
    true
}
