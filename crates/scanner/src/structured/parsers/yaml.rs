use super::{line::find_line_number, ExtractedPair};

/// Parse a Kubernetes Secret YAML and decode base64 values under `data:`.
///
/// Line-number lookup anchors on the key (`<key>:`) rather than the
/// encoded value: two different keys in the same Secret CAN encode the
/// same byte body, and matching on the encoded blob would route both
/// findings to the first occurrence.
pub(crate) fn parse_k8s_secret(text: &str) -> Vec<ExtractedPair> {
    let mut pairs = Vec::new();
    let value: serde_yaml::Value = match serde_yaml::from_str(text) {
        Ok(v) => v,
        Err(error) => {
            // Law 10: this file declared `kind: Secret` but won't parse, so its
            // base64 `data:` values are never decoded — the exact secrets a k8s
            // Secret hides. Count it (the file MATCHED the format, so this is a
            // real coverage gap, not generic YAML noise); keep the debug detail.
            crate::telemetry::record_structured_parse_failure();
            tracing::warn!(target: "keyhog::structured", %error, "k8s secret YAML parse failed; base64 data: values will not be decoded-through");
            return pairs;
        }
    };

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
            let line = find_line_number(text, &format!("{}:", key))
                .or_else(|| find_line_number(text, encoded))
                .unwrap_or(1); // LAW10: empty/absent => documented numeric/sentinel default, recall-safe
            pairs.push(ExtractedPair {
                context: key.to_string(),
                value: decoded,
                line,
            });
        }
    }

    if let Some(serde_yaml::Value::Mapping(map)) = value.get("stringData") {
        for (k, v) in map {
            let key = k.as_str().unwrap_or_default(); // LAW10: missing/non-string field => empty; value then fails downstream shape/length checks, recall-safe
            let secret_value = v.as_str().unwrap_or_default().to_string(); // LAW10: missing/non-string field => empty; value then fails downstream shape/length checks, recall-safe
            if key.is_empty() {
                continue;
            }
            let line = find_line_number(text, key).unwrap_or(1); // LAW10: line not located => placeholder line for REPORTING only; finding still emitted, recall-safe
            pairs.push(ExtractedPair {
                context: key.to_string(),
                value: secret_value,
                line,
            });
        }
    }

    pairs
}

/// Parse docker-compose.yml environment blocks.
pub(crate) fn parse_docker_compose(text: &str) -> Vec<ExtractedPair> {
    let mut pairs = Vec::new();
    let value: serde_yaml::Value = match serde_yaml::from_str(text) {
        Ok(v) => v,
        Err(error) => {
            // Law 10: a docker-compose file that won't parse loses its
            // environment-block decode-through (inline `environment:` secrets
            // never become scannable lines). Count + keep the debug detail.
            crate::telemetry::record_structured_parse_failure();
            tracing::warn!(target: "keyhog::structured", %error, "docker-compose YAML parse failed; environment-block decode-through disabled");
            return pairs;
        }
    };
    find_environment_pairs(&value, text, &mut pairs, 0);
    pairs
}

/// Cap recursion depth on adversarial YAML. Real docker-compose schemas nest
/// about six levels deep; 256 stays permissive while preventing stack overflow.
const MAX_COMPOSE_DEPTH: usize = 256;

fn find_environment_pairs(
    value: &serde_yaml::Value,
    text: &str,
    pairs: &mut Vec<ExtractedPair>,
    depth: usize,
) {
    if depth >= MAX_COMPOSE_DEPTH {
        return;
    }
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map {
                if k.as_str() == Some("environment") {
                    extract_environment_block(v, text, pairs);
                } else {
                    find_environment_pairs(v, text, pairs, depth + 1);
                }
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for v in seq {
                find_environment_pairs(v, text, pairs, depth + 1);
            }
        }
        _ => {}
    }
}

fn extract_environment_block(
    value: &serde_yaml::Value,
    text: &str,
    pairs: &mut Vec<ExtractedPair>,
) {
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map {
                let key = k.as_str().unwrap_or_default(); // LAW10: missing/non-string field => empty; value then fails downstream shape/length checks, recall-safe
                let val = v.as_str().unwrap_or_default().to_string(); // LAW10: missing/non-string field => empty; value then fails downstream shape/length checks, recall-safe
                if key.is_empty() {
                    continue;
                }
                let line = find_line_number(text, key).unwrap_or(1); // LAW10: line not located => placeholder line for REPORTING only; finding still emitted, recall-safe
                pairs.push(ExtractedPair {
                    context: key.to_string(),
                    value: val,
                    line,
                });
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for item in seq {
                if let Some(s) = item.as_str() {
                    if let Some((key, val)) = s.split_once('=') {
                        if key.is_empty() {
                            continue;
                        }
                        let line = find_line_number(text, s).unwrap_or(1); // LAW10: line not located => placeholder line for REPORTING only; finding still emitted, recall-safe
                        pairs.push(ExtractedPair {
                            context: key.to_string(),
                            value: val.to_string(),
                            line,
                        });
                    }
                }
            }
        }
        _ => {}
    }
}
