use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use futures_util::StreamExt;
use keyhog_core::{
    MetadataSpec, ProviderEvidenceRole, ProviderEvidenceSensitivity, VerificationResult,
};
use sha2::{Digest, Sha256};

use crate::verify::request::{execute_request, RequestError};

pub(crate) const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;
const MAX_PROVIDER_EVIDENCE_VALUE_BYTES: usize = 256;

/// The connection dropped mid-body while reading the API response. Transient.
/// Leads with the legacy `body read failed` phrase so existing `.contains`
/// checks keep matching (Law 3), then states the actionable fix.
pub const BODY_READ_FAILED_ERROR: &str =
    "body read failed: the connection dropped while reading the verification response. \
     Fix: this is usually transient network or proxy instability, retry, or check egress \
     to the credential's host";

/// The endpoint returned more than the 1 MB the verifier reads, so the
/// live/dead signal can't be parsed from a truncated body.
pub const RESPONSE_TOO_LARGE_ERROR: &str =
    "response body exceeds 1MB limit: the endpoint returned more than the 1 MB the verifier \
     reads, so the success/failure signal cannot be parsed. \
     Fix: this usually means the verify URL points at a web page or download rather than the \
     JSON API: check the detector's verify URL";

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
    fn invalid_json(scope: &str, json_path: &str, error: serde_json::Error) -> Self {
        Self {
            message: format!(
                "response body is not valid JSON for {scope} selector `{json_path}`: {error}"
            ),
        }
    }

    fn invalid_selector(scope: &str, error: keyhog_core::json_selector::SelectorError) -> Self {
        Self {
            message: format!("{scope}: {error}"),
        }
    }

    fn invalid_evidence_role(name: &str) -> Self {
        Self {
            message: format!(
                "verification metadata name {name:?} is not a supported provider evidence role. Fix: use a reviewed provider-neutral role in the detector TOML"
            ),
        }
    }

    fn duplicate_evidence_role(role: &str) -> Self {
        Self {
            message: format!(
                "verification metadata repeats provider evidence role {role:?}. Fix: give each report role one detector-owned selector"
            ),
        }
    }

    fn non_scalar_evidence(role: &str, value: &serde_json::Value) -> Self {
        let kind = match value {
            serde_json::Value::Null => "null",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::Object(_) => "object",
            serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_) => "scalar",
        };
        Self {
            message: format!(
                "provider evidence role {role:?} selected a JSON {kind}, but report evidence must be a string, number, or boolean. Fix: point the detector TOML selector at one reviewed scalar field"
            ),
        }
    }

    fn oversized_evidence(role: &str, bytes: usize) -> Self {
        Self {
            message: format!(
                "provider evidence role {role:?} selected {bytes} bytes, above the {MAX_PROVIDER_EVIDENCE_VALUE_BYTES}-byte report limit. Fix: select a bounded identity field or mark the field hashed or secret"
            ),
        }
    }

    fn secret_evidence_boundary(role: &str) -> Self {
        Self {
            message: format!(
                "provider evidence role {role:?} is secret and cannot cross the reporting boundary"
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
        .map_or(0, |capacity| capacity)
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
        let chunk = chunk.map_err(|error| {
            let cause = error.without_url();
            RequestError {
                result: VerificationResult::Error(format!(
                    "{BODY_READ_FAILED_ERROR}. Cause: {cause}"
                )),
                transient: true,
            }
        })?;
        if body.len() + chunk.len() > MAX_RESPONSE_BODY_BYTES {
            return Err(RequestError {
                result: VerificationResult::Error(RESPONSE_TOO_LARGE_ERROR.into()),
                transient: false,
            });
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|error| RequestError {
        result: VerificationResult::Error(format!("{BODY_NOT_UTF8_ERROR}. Cause: {error}")),
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
            .map_err(|error| ResponseContractError::invalid_json("success", json_path, error))?;
        if let Some(val) = keyhog_core::json_selector::select(&json, json_path)
            .map_err(|error| ResponseContractError::invalid_selector("success selector", error))?
        {
            return Ok(!val.is_null()
                && spec.equals.as_ref().map_or(true, |expected| {
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
/// in a live JSON payload: `"errors":[]`, `"error":null`, `"error_rate":0`,
/// `"invalid_count":0`, `"expired":false`, or any field/account/repo name that
/// merely embeds one of those words, and silently flips confirmed-live
/// credentials to Dead (a recall regression).
///
/// To avoid clobbering an explicitly-matched success signal, the check is now
/// conservative: an error token only counts when it is paired with a value
/// that actually denotes a present error. For JSON bodies that means an error
/// key whose value is a non-empty string, a non-empty array/object, or boolean
/// `true` / numeric non-zero: `null`, `false`, `0`, `[]`, and `{}` are treated
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
    match parse_json_error_keys(include_str!("../../rules/json-error-keys.toml")) {
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

pub(crate) fn extract_provider_evidence(
    specs: &[MetadataSpec],
    body: &str,
) -> Result<HashMap<String, String>, ResponseContractError> {
    let mut metadata = HashMap::new();
    let Some(first) = specs.first() else {
        return Ok(metadata);
    };
    let json = serde_json::from_str::<serde_json::Value>(body).map_err(|error| {
        ResponseContractError::invalid_json("metadata", &first.json_path, error)
    })?;
    let mut roles = HashSet::with_capacity(specs.len());
    for spec in specs {
        let role = ProviderEvidenceRole::from_metadata_name(&spec.name)
            .ok_or_else(|| ResponseContractError::invalid_evidence_role(&spec.name))?;
        if !roles.insert(role) {
            return Err(ResponseContractError::duplicate_evidence_role(
                role.as_str(),
            ));
        }
        let selected =
            keyhog_core::json_selector::select(&json, &spec.json_path).map_err(|error| {
                ResponseContractError::invalid_selector(
                    &format!("metadata {:?} selector", spec.name),
                    error,
                )
            })?;
        if let Some(val) = selected {
            if spec.sensitivity == ProviderEvidenceSensitivity::Secret {
                continue;
            }
            let role = role.as_str();
            let value = provider_evidence_value(role, spec.sensitivity, val)?;
            metadata.insert(role.to_string(), value);
        }
    }
    Ok(metadata)
}

pub(crate) fn extract_metadata(
    specs: &[MetadataSpec],
    body: &str,
) -> Result<HashMap<String, String>, ResponseContractError> {
    let mut metadata = HashMap::new();
    let Some(first) = specs.first() else {
        return Ok(metadata);
    };
    let json = serde_json::from_str::<serde_json::Value>(body).map_err(|error| {
        ResponseContractError::invalid_json("metadata", &first.json_path, error)
    })?;
    for spec in specs {
        let selected =
            keyhog_core::json_selector::select(&json, &spec.json_path).map_err(|error| {
                ResponseContractError::invalid_selector(
                    &format!("metadata {:?} selector", spec.name),
                    error,
                )
            })?;
        if let Some(value) = selected {
            metadata.insert(spec.name.clone(), json_value_to_contract_string(value));
        }
    }
    Ok(metadata)
}

fn provider_evidence_value(
    role: &str,
    sensitivity: ProviderEvidenceSensitivity,
    value: &serde_json::Value,
) -> Result<String, ResponseContractError> {
    match sensitivity {
        ProviderEvidenceSensitivity::Public => {
            let scalar = match value {
                serde_json::Value::String(value) => value.clone(),
                serde_json::Value::Number(value) => value.to_string(),
                serde_json::Value::Bool(value) => value.to_string(),
                serde_json::Value::Null
                | serde_json::Value::Array(_)
                | serde_json::Value::Object(_) => {
                    return Err(ResponseContractError::non_scalar_evidence(role, value));
                }
            };
            if scalar.len() > MAX_PROVIDER_EVIDENCE_VALUE_BYTES {
                return Err(ResponseContractError::oversized_evidence(
                    role,
                    scalar.len(),
                ));
            }
            Ok(scalar)
        }
        ProviderEvidenceSensitivity::Hashed => Ok(format!(
            "sha256:{}",
            hex::encode(hash_provider_evidence(value))
        )),
        ProviderEvidenceSensitivity::Secret => {
            Err(ResponseContractError::secret_evidence_boundary(role))
        }
    }
}

fn hash_provider_evidence(value: &serde_json::Value) -> impl AsRef<[u8]> {
    let mut hasher = Sha256::new();
    match value {
        serde_json::Value::String(value) => hasher.update(value.as_bytes()),
        serde_json::Value::Number(value) => hasher.update(value.to_string().as_bytes()),
        serde_json::Value::Bool(value) => hasher.update(if *value {
            b"true".as_slice()
        } else {
            b"false".as_slice()
        }),
        serde_json::Value::Null => hasher.update(b"null"),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            // The response body is already capped. Hash the structured value
            // directly so legacy object and array evidence remains useful
            // without ever crossing the report boundary in plaintext.
            hasher.update(value.to_string().as_bytes());
        }
    }
    hasher.finalize()
}

fn json_value_to_contract_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        _ => value.to_string(),
    }
}
