use super::{
    line::{finalize_pending_pairs, PendingExtractedPair},
    ExtractedPair,
};
use serde::Deserialize;

/// Parse a Kubernetes Secret YAML and decode base64 values under `data:`.
///
/// Line-number lookup anchors on the key (`<key>:`) rather than the
/// encoded value: two different keys in the same Secret CAN encode the
/// same byte body, and matching on the encoded blob would route both
/// findings to the first occurrence.
pub(crate) fn parse_k8s_secret(text: &str) -> Vec<ExtractedPair> {
    let values = match parse_yaml_documents(text, "k8s-secret", "base64 data: values") {
        Some(values) => values,
        None => return Vec::new(),
    };

    let mut pending = Vec::new();
    for value in &values {
        extract_k8s_secret(value, &mut pending, 0);
    }

    finalize_pending_pairs(text, pending)
}

fn extract_k8s_secret(
    value: &serde_yaml::Value,
    pending: &mut Vec<PendingExtractedPair>,
    depth: usize,
) {
    if depth >= MAX_YAML_TRAVERSAL_DEPTH {
        return;
    }
    match yaml_kind(value) {
        Some("Secret") => extract_k8s_secret_maps(value, pending),
        Some("List") => {
            if let Some(serde_yaml::Value::Sequence(items)) = value.get("items") {
                for item in items {
                    extract_k8s_secret(item, pending, depth + 1);
                }
            }
        }
        _ => {}
    }
}

fn extract_k8s_secret_maps(value: &serde_yaml::Value, pending: &mut Vec<PendingExtractedPair>) {
    if let Some(serde_yaml::Value::Mapping(map)) = value.get("data") {
        for (k, v) in map {
            let key = k.as_str().unwrap_or_default(); // LAW10: missing/non-string field => empty; value then fails downstream shape/length checks, recall-safe
            let Some(encoded) = yaml_scalar_value_text(v) else {
                continue;
            };
            if key.is_empty() || encoded.is_empty() {
                continue;
            }
            let (line_anchor, fallback_anchor) = yaml_mapping_anchors(key, &encoded);
            let decoded = match keyhog_core::decode_standard_base64(&encoded) {
                Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                Err(error) => {
                    crate::telemetry::record_structured_parse_failure();
                    // LAW10: invalid k8s Secret base64 is counted as a
                    // structured parse/decode coverage gap before debug detail.
                    tracing::debug!(
                        target: "keyhog::structured",
                        key,
                        %error,
                        "k8s secret data: value is not valid standard base64; skipping decode-through"
                    );
                    continue;
                }
            };
            pending.push(PendingExtractedPair::owned_anchor_with_fallback(
                key,
                decoded,
                line_anchor,
                fallback_anchor,
            ));
        }
    }

    if let Some(serde_yaml::Value::Mapping(map)) = value.get("stringData") {
        for (k, v) in map {
            let key = k.as_str().unwrap_or_default(); // LAW10: missing/non-string field => empty; value then fails downstream shape/length checks, recall-safe
            let Some(secret_value) = yaml_scalar_value_text(v) else {
                continue;
            };
            if key.is_empty() {
                continue;
            }
            let (line_anchor, fallback_anchor) = yaml_mapping_anchors(key, &secret_value);
            pending.push(PendingExtractedPair::owned_anchor_with_fallback(
                key,
                secret_value,
                line_anchor,
                fallback_anchor,
            ));
        }
    }
}

fn yaml_kind(value: &serde_yaml::Value) -> Option<&str> {
    value.get("kind").and_then(serde_yaml::Value::as_str)
}

/// Parse docker-compose.yml environment blocks.
pub(crate) fn parse_docker_compose(text: &str) -> Vec<ExtractedPair> {
    let value = match parse_yaml_value(text, "docker-compose", "environment-block values") {
        Some(value) => value,
        None => return Vec::new(),
    };
    let mut pending = Vec::new();
    find_environment_pairs(&value, &mut pending, 0);
    finalize_pending_pairs(text, pending)
}

/// serde_yaml 0.9.34 enforces this parser recursion limit before building a
/// Value. Keep the contract local and tested so the parse-time guard is visible
/// instead of being mistaken for the post-parse compose traversal cap below.
const SERDE_YAML_PARSE_RECURSION_LIMIT: usize = 128;

fn parse_yaml_value(
    text: &str,
    surface: &'static str,
    lost_decode_surface: &'static str,
) -> Option<serde_yaml::Value> {
    match serde_yaml::from_str(text) {
        Ok(value) => Some(value),
        Err(error) => {
            // Law 10: a structured YAML file that won't parse loses its
            // decode-through surface. Count + keep the debug detail; serde_yaml
            // also rejects deeply nested YAML before Value construction.
            crate::telemetry::record_structured_parse_failure();
            match surface {
                "k8s-secret" => tracing::warn!(
                    target: "keyhog::structured",
                    %error,
                    surface,
                    lost_decode_surface,
                    serde_yaml_parse_recursion_limit = SERDE_YAML_PARSE_RECURSION_LIMIT,
                    "k8s secret YAML parse failed; decode-through disabled"
                ),
                "docker-compose" => tracing::warn!(
                    target: "keyhog::structured",
                    %error,
                    surface,
                    lost_decode_surface,
                    serde_yaml_parse_recursion_limit = SERDE_YAML_PARSE_RECURSION_LIMIT,
                    "docker-compose YAML parse failed; decode-through disabled"
                ),
                _ => tracing::warn!(
                    target: "keyhog::structured",
                    %error,
                    surface,
                    lost_decode_surface,
                    serde_yaml_parse_recursion_limit = SERDE_YAML_PARSE_RECURSION_LIMIT,
                    "structured YAML parse failed; decode-through disabled"
                ),
            }
            None
        }
    }
}

fn parse_yaml_documents(
    text: &str,
    surface: &'static str,
    lost_decode_surface: &'static str,
) -> Option<Vec<serde_yaml::Value>> {
    let mut values = Vec::new();
    let mut had_error = false;
    for document in serde_yaml::Deserializer::from_str(text) {
        match serde_yaml::Value::deserialize(document) {
            Ok(value) => values.push(value),
            Err(error) => {
                had_error = true;
                crate::telemetry::record_structured_parse_failure();
                tracing::warn!(
                    target: "keyhog::structured",
                    %error,
                    surface,
                    lost_decode_surface,
                    serde_yaml_parse_recursion_limit = SERDE_YAML_PARSE_RECURSION_LIMIT,
                    "structured YAML document parse failed; decode-through disabled for that document"
                );
                break;
            }
        }
    }
    if values.is_empty() && had_error {
        None
    } else {
        Some(values)
    }
}

/// Cap recursion depth on adversarial YAML. Real docker-compose schemas and
/// Kubernetes List wrappers nest shallowly; 256 stays permissive while
/// preventing stack overflow.
const MAX_YAML_TRAVERSAL_DEPTH: usize = 256;

fn find_environment_pairs(
    value: &serde_yaml::Value,
    pending: &mut Vec<PendingExtractedPair>,
    depth: usize,
) {
    if depth >= MAX_YAML_TRAVERSAL_DEPTH {
        return;
    }
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map {
                if k.as_str() == Some("environment") {
                    extract_environment_block(v, pending);
                } else {
                    find_environment_pairs(v, pending, depth + 1);
                }
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for v in seq {
                find_environment_pairs(v, pending, depth + 1);
            }
        }
        _ => {}
    }
}

fn extract_environment_block(value: &serde_yaml::Value, pending: &mut Vec<PendingExtractedPair>) {
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map {
                let key = k.as_str().unwrap_or_default(); // LAW10: missing/non-string field => empty; value then fails downstream shape/length checks, recall-safe
                let Some(val) = yaml_scalar_value_text(v) else {
                    continue;
                };
                if key.is_empty() {
                    continue;
                }
                let (line_anchor, fallback_anchor) = yaml_mapping_anchors(key, &val);
                pending.push(PendingExtractedPair::owned_anchor_with_fallback(
                    key,
                    val,
                    line_anchor,
                    fallback_anchor,
                ));
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for item in seq {
                if let Some(s) = item.as_str() {
                    if let Some((key, val)) = s.split_once('=') {
                        if key.is_empty() {
                            continue;
                        }
                        pending.push(PendingExtractedPair::owned_anchor(
                            key,
                            val.to_string(),
                            s.to_string(),
                        ));
                    }
                }
            }
        }
        _ => {}
    }
}

fn yaml_mapping_anchors(key: &str, value: &str) -> (String, String) {
    (format!("{key}: {value}"), format!("{key}:"))
}

fn yaml_scalar_value_text(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}
