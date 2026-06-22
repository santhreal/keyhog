use super::{
    line::{finalize_pending_pairs, PendingExtractedPair},
    ExtractedPair,
};

/// Parse a Kubernetes Secret YAML and decode base64 values under `data:`.
///
/// Line-number lookup anchors on the key (`<key>:`) rather than the
/// encoded value: two different keys in the same Secret CAN encode the
/// same byte body, and matching on the encoded blob would route both
/// findings to the first occurrence.
pub(crate) fn parse_k8s_secret(text: &str) -> Vec<ExtractedPair> {
    let value: serde_yaml::Value = match serde_yaml::from_str(text) {
        Ok(v) => v,
        Err(error) => {
            // Law 10: this file declared `kind: Secret` but won't parse, so its
            // base64 `data:` values are never decoded — the exact secrets a k8s
            // Secret hides. Count it (the file MATCHED the format, so this is a
            // real coverage gap, not generic YAML noise); keep the debug detail.
            crate::telemetry::record_structured_parse_failure();
            tracing::warn!(target: "keyhog::structured", %error, "k8s secret YAML parse failed; base64 data: values will not be decoded-through");
            return Vec::new();
        }
    };

    let mut pending = Vec::new();
    if let Some(serde_yaml::Value::Mapping(map)) = value.get("data") {
        for (k, v) in map {
            let key = k.as_str().unwrap_or_default(); // LAW10: missing/non-string field => empty; value then fails downstream shape/length checks, recall-safe
            let encoded = v.as_str().unwrap_or_default(); // LAW10: missing/non-string field => empty; value then fails downstream shape/length checks, recall-safe
            if key.is_empty() || encoded.is_empty() {
                continue;
            }
            let decoded = match keyhog_core::decode_standard_base64(encoded) {
                Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                Err(error) => {
                    crate::telemetry::record_structured_parse_failure();
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
                format!("{}:", key),
                encoded.to_string(),
            ));
        }
    }

    if let Some(serde_yaml::Value::Mapping(map)) = value.get("stringData") {
        for (k, v) in map {
            let key = k.as_str().unwrap_or_default(); // LAW10: missing/non-string field => empty; value then fails downstream shape/length checks, recall-safe
            let secret_value = v.as_str().unwrap_or_default().to_string(); // LAW10: missing/non-string field => empty; value then fails downstream shape/length checks, recall-safe
            if key.is_empty() {
                continue;
            }
            pending.push(PendingExtractedPair::owned_anchor(
                key,
                secret_value,
                key.to_string(),
            ));
        }
    }

    finalize_pending_pairs(text, pending)
}

/// Parse docker-compose.yml environment blocks.
pub(crate) fn parse_docker_compose(text: &str) -> Vec<ExtractedPair> {
    let value: serde_yaml::Value = match serde_yaml::from_str(text) {
        Ok(v) => v,
        Err(error) => {
            // Law 10: a docker-compose file that won't parse loses its
            // environment-block decode-through (inline `environment:` secrets
            // never become scannable lines). Count + keep the debug detail.
            crate::telemetry::record_structured_parse_failure();
            tracing::warn!(target: "keyhog::structured", %error, "docker-compose YAML parse failed; environment-block decode-through disabled");
            return Vec::new();
        }
    };
    let mut pending = Vec::new();
    find_environment_pairs(&value, &mut pending, 0);
    finalize_pending_pairs(text, pending)
}

/// Cap recursion depth on adversarial YAML. Real docker-compose schemas nest
/// about six levels deep; 256 stays permissive while preventing stack overflow.
const MAX_COMPOSE_DEPTH: usize = 256;

fn find_environment_pairs(
    value: &serde_yaml::Value,
    pending: &mut Vec<PendingExtractedPair>,
    depth: usize,
) {
    if depth >= MAX_COMPOSE_DEPTH {
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
                let val = v.as_str().unwrap_or_default().to_string(); // LAW10: missing/non-string field => empty; value then fails downstream shape/length checks, recall-safe
                if key.is_empty() {
                    continue;
                }
                pending.push(PendingExtractedPair::owned_anchor(
                    key,
                    val,
                    key.to_string(),
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
