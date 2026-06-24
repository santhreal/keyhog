use std::collections::HashMap;

use futures_util::StreamExt;
use keyhog_core::{MetadataSpec, VerificationResult};

use crate::verify::request::{execute_request, RequestError};

pub(crate) const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;

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

pub(crate) async fn read_response_body(
    response: reqwest::Response,
) -> std::result::Result<String, RequestError> {
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| RequestError {
            result: VerificationResult::Error("body read failed".into()),
            transient: true,
        })?;
        if body.len() + chunk.len() > MAX_RESPONSE_BODY_BYTES {
            return Err(RequestError {
                result: VerificationResult::Error("response body exceeds 1MB limit".into()),
                transient: false,
            });
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| RequestError {
        result: VerificationResult::Error("body is not utf-8".into()),
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
        return json_indicates_error(&json);
    }
    // Non-JSON fallback: whole-word match so embedded substrings
    // (e.g. `error_rate`, `myinvalidatedname`) do not trip the heuristic.
    body.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(is_error_contract_token)
}

/// Error key names recognized inside a JSON response body.
const JSON_ERROR_KEYS: &[&str] = &["error", "errors", "invalid", "expired", "revoked"];

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
