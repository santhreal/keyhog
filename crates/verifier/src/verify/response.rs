use std::collections::HashMap;

use futures_util::StreamExt;
use keyhog_core::{MetadataSpec, VerificationResult};

use crate::verify::request::RequestError;

pub(crate) const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;

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

pub(crate) fn evaluate_success(spec: &keyhog_core::SuccessSpec, status: u16, body: &str) -> bool {
    if let Some(expected_status) = spec.status {
        if status != expected_status {
            return false;
        }
    }
    if let Some(not_status) = spec.status_not {
        if status == not_status {
            return false;
        }
    }
    if let Some(ref contains) = spec.body_contains {
        if !body.contains(contains) {
            return false;
        }
    }
    if let Some(ref not_contains) = spec.body_not_contains {
        if body.contains(not_contains) {
            return false;
        }
    }
    if let Some(ref json_path) = spec.json_path {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
            if let Some(val) = json.pointer(json_path) {
                if let Some(ref expected) = spec.equals {
                    return val.as_str() == Some(expected);
                }
                return !val.is_null();
            }
        }
        return false;
    }
    true
}

pub(crate) fn body_indicates_error(body: &str) -> bool {
    let lower = body.to_lowercase();
    lower.contains("invalid")
        || lower.contains("error")
        || lower.contains("expired")
        || lower.contains("revoked")
}

pub(crate) fn extract_metadata(specs: &[MetadataSpec], body: &str) -> HashMap<String, String> {
    let mut metadata = HashMap::new();
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
        for spec in specs {
            if let Some(val) = json.pointer(&spec.json_path) {
                let val_str = match val {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    _ => val.to_string(),
                };
                metadata.insert(spec.name.clone(), val_str);
            }
        }
    }
    metadata
}
