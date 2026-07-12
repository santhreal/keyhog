use std::collections::HashMap;
use std::sync::LazyLock;

use futures_util::StreamExt;
use keyhog_core::{MetadataSpec, VerificationResult};

use crate::verify::request::{execute_request, RequestError};

pub(crate) const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;

/// The connection dropped mid-body while reading the API response. Transient.
/// Leads with the legacy `body read failed` phrase so existing `.contains`
/// checks keep matching (Law 3), then states the actionable fix.
pub const BODY_READ_FAILED_ERROR: &str =
    "body read failed: the connection dropped while reading the verification response. \
     Fix: this is usually transient network or proxy instability — retry, or check egress \
     to the credential's host";

/// The endpoint returned more than the 1 MB the verifier reads, so the
/// live/dead signal can't be parsed from a truncated body.
pub const RESPONSE_TOO_LARGE_ERROR: &str =
    "response body exceeds 1MB limit: the endpoint returned more than the 1 MB the verifier \
     reads, so the success/failure signal cannot be parsed. \
     Fix: this usually means the verify URL points at a web page or download rather than the \
     JSON API — check the detector's verify URL";

/// The response body was not valid UTF-8, so the success/failure text can't be read.
pub const BODY_NOT_UTF8_ERROR: &str =
    "body is not utf-8: the verifier needs a UTF-8 response to read the API's success/failure \
     signal, but this body was binary. \
     Fix: confirm the verify URL targets the JSON API endpoint, not a binary, redirect, or CDN \
     response";

pub(crate) struct HttpResponseBody {
    pub status: u16,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResponseContractError {
    message: String,
}

impl ResponseContractError {
    fn invalid_json(json_path: &str, error: serde_json::Error) -> Self {
        Self {
            message: format!(
                "response body is not valid JSON for success json_path `{json_path}`: {error}"
            ),
        }
    }

    pub(crate) fn into_verification_error(self) -> VerificationResult {
        VerificationResult::Error(self.message)
    }
}

impl std::fmt::Display for ResponseContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub(crate) async fn execute_and_read_response(
    request: reqwest::RequestBuilder,
) -> std::result::Result<HttpResponseBody, RequestError> {
    let response = execute_request(request).await?;
    let status = response.status().as_u16();
    let body = read_response_body(response).await?;
    Ok(HttpResponseBody { status, body })
}

/// Preallocation hint for a streamed response body: honor the server's
/// advertised `Content-Length`, but CLAMP to `MAX_RESPONSE_BODY_BYTES` so a
/// lying or hostile header cannot make us reserve gigabytes up front (the
/// streaming loop still enforces the true cap byte-by-byte). `None` (no header)
/// => no preallocation. The `.min` is done in `u64` space so a huge length can
/// never wrap through the `usize` cast.
pub(crate) fn body_capacity_hint(content_length: Option<u64>) -> usize {
    content_length
        .map(|len| len.min(MAX_RESPONSE_BODY_BYTES as u64) as usize)
        .unwrap_or(0)
}

pub(crate) async fn read_response_body(
    response: reqwest::Response,
) -> std::result::Result<String, RequestError> {
    // Preallocate from Content-Length (clamped) to avoid repeated Vec-growth
    // reallocations while streaming a large body.
    let capacity_hint = body_capacity_hint(response.content_length());
    let mut stream = response.bytes_stream();
    let mut body = Vec::with_capacity(capacity_hint);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| RequestError {
            result: VerificationResult::Error(BODY_READ_FAILED_ERROR.into()),
            transient: true,
        })?;
        if body.len() + chunk.len() > MAX_RESPONSE_BODY_BYTES {
            return Err(RequestError {
                result: VerificationResult::Error(RESPONSE_TOO_LARGE_ERROR.into()),
                transient: false,
            });
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| RequestError {
        result: VerificationResult::Error(BODY_NOT_UTF8_ERROR.into()),
        transient: false,
    })
}

pub(crate) fn evaluate_success(
    spec: &keyhog_core::SuccessSpec,
    status: u16,
    body: &str,
) -> Result<bool, ResponseContractError> {
    if let Some(expected_status) = spec.status {
        if status != expected_status {
            return Ok(false);
        }
    }
    if let Some(not_status) = spec.status_not {
        if status == not_status {
            return Ok(false);
        }
    }
    if let Some(ref contains) = spec.body_contains {
        if !body.contains(contains) {
            return Ok(false);
        }
    }
    if let Some(ref not_contains) = spec.body_not_contains {
        if body.contains(not_contains) {
            return Ok(false);
        }
    }
    if let Some(ref json_path) = spec.json_path {
        let json = serde_json::from_str::<serde_json::Value>(body)
            .map_err(|error| ResponseContractError::invalid_json(json_path, error))?;
        if let Some(val) = json.pointer(json_path) {
            return Ok(spec.equals.as_ref().map_or(!val.is_null(), |expected| {
                json_value_to_contract_string(val) == *expected
            }));
        }
        return Ok(false);
    }
    Ok(true)
}

/// Generic "the response body announces a failure" heuristic, used as a
/// defense-in-depth backstop on top of a detector's explicit success spec.
///
/// The hard problem with the original implementation was that it scanned the
/// lowercased whole body for the bare substrings `invalid` / `error` /
/// `expired` / `revoked`. That fires on overwhelmingly common *benign* tokens
/// in a live JSON payload — `"errors":[]`, `"error":null`, `"error_rate":0`,
/// `"invalid_count":0`, `"expired":false`, or any field/account/repo name that
/// merely embeds one of those words — and silently flips confirmed-live
/// credentials to Dead (a recall regression).
///
/// To avoid clobbering an explicitly-matched success signal, the check is now
/// conservative: an error token only counts when it is paired with a value
/// that actually denotes a present error. For JSON bodies that means an error
/// key whose value is a non-empty string, a non-empty array/object, or boolean
/// `true` / numeric non-zero — `null`, `false`, `0`, `[]`, and `{}` are treated
/// as "no error" exactly as a service author would intend. Non-JSON bodies fall
/// back to a whole-word (not arbitrary-substring) scan so values like
/// `error_rate` or `myinvalidatedname` no longer trigger it.
pub(crate) fn body_indicates_error(body: &str) -> bool {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
        // LAW10: non-JSON bodies use the whole-word text contract below; verification stays conservative.
        return json_indicates_error(&json);
    }
    // Non-JSON fallback: whole-word match so embedded substrings
    // (e.g. `error_rate`, `myinvalidatedname`) do not trip the heuristic. An
    // error word is discounted when the preceding word negates it, so benign
    // plaintext like `no errors` / `never expired` / `0 errors` stays Live.
    let mut prev = "";
    for token in body.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
        if token.is_empty() {
            continue;
        }
        if is_error_contract_token(token) && !is_error_negation_token(prev) {
            return true;
        }
        prev = token;
    }
    false
}

/// Words that, immediately before an error token in a plaintext body, denote the
/// *absence* of an error (`no errors`, `never expired`, `zero errors`).
fn is_error_negation_token(token: &str) -> bool {
    matches!(
        token.to_ascii_lowercase().as_str(),
        "no" | "not" | "never" | "without" | "zero" | "non" | "0"
    )
}

#[derive(serde::Deserialize)]
struct JsonErrorKeysFile {
    keys: Vec<String>,
}

/// Error key names recognized inside a JSON response body.
fn parse_json_error_keys(raw: &str) -> Result<Vec<String>, String> {
    toml::from_str::<JsonErrorKeysFile>(raw)
        .map(|parsed| parsed.keys)
        .map_err(|error| error.to_string())
}

static JSON_ERROR_KEYS: LazyLock<Vec<String>> = LazyLock::new(|| {
    match parse_json_error_keys(include_str!("../../../../rules/json-error-keys.toml")) {
        Ok(keys) => keys,
        Err(error) => panic!(
            "rules/json-error-keys.toml is invalid: {error}. \
             Fix the bundled Tier-B json-error-keys data."
        ),
    }
});

/// Recursively decide whether a JSON body carries a *populated* error signal.
fn json_indicates_error(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => map.iter().any(|(key, val)| {
            (is_error_contract_token(key) && json_value_is_truthy_error(val))
                || json_indicates_error(val)
        }),
        serde_json::Value::Array(items) => items.iter().any(json_indicates_error),
        _ => false,
    }
}

fn is_error_contract_token(token: &str) -> bool {
    JSON_ERROR_KEYS
        .iter()
        .any(|candidate| token.eq_ignore_ascii_case(candidate))
}

/// Whether the value attached to an error key actually denotes a present error.
/// `null`, `false`, `0`, empty string, `[]`, and `{}` mean "no error".
fn json_value_is_truthy_error(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::Number(n) => n.as_f64().map_or(true, |f| f != 0.0), // LAW10: non-f64-representable number => treated as a present error (true), conservative; never misses a real error signal
        serde_json::Value::String(s) => !s.is_empty(),
        serde_json::Value::Array(a) => !a.is_empty(),
        serde_json::Value::Object(o) => !o.is_empty(),
    }
}

pub(crate) fn extract_metadata(specs: &[MetadataSpec], body: &str) -> HashMap<String, String> {
    let mut metadata = HashMap::new();
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
        // LAW10: non-JSON verifier bodies simply have no JSON metadata; verification result still uses response status/body rules.
        for spec in specs {
            if let Some(val) = json.pointer(&spec.json_path) {
                metadata.insert(spec.name.clone(), json_value_to_contract_string(val));
            }
        }
    }
    metadata
}

fn json_value_to_contract_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        _ => value.to_string(),
    }
}
