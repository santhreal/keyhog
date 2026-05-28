use super::ExtractedPair;

/// Parse KEY=VALUE lines from an .env file.
pub fn parse_env(text: &str) -> Vec<ExtractedPair> {
    let mut pairs = Vec::new();
    for (line_idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let after_export = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        if let Some((key, value)) = after_export.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() {
                continue;
            }
            let unquoted = strip_quotes(value);
            pairs.push(ExtractedPair {
                context: key.to_string(),
                value: unquoted.to_string(),
                line: line_idx + 1,
            });
        }
    }
    pairs
}

fn strip_quotes(s: &str) -> &str {
    if s.len() >= 2 {
        let first = s.as_bytes()[0] as char;
        let last = s.as_bytes()[s.len() - 1] as char;
        if (first == '"' || first == '\'') && first == last {
            return &s[1..s.len() - 1];
        }
    }
    s
}

/// Parse a Kubernetes Secret YAML and decode base64 values under `data:`.
pub fn parse_k8s_secret(text: &str) -> Vec<ExtractedPair> {
    let mut pairs = Vec::new();
    let value: serde_yaml::Value = match serde_yaml::from_str(text) {
        Ok(v) => v,
        Err(error) => {
            tracing::debug!(target: "keyhog::structured", %error, "k8s secret YAML parse failed");
            return pairs;
        }
    };

    if let Some(serde_yaml::Value::Mapping(map)) = value.get("data") {
        for (k, v) in map {
            let key = k.as_str().unwrap_or_default();
            let encoded = v.as_str().unwrap_or_default();
            if key.is_empty() || encoded.is_empty() {
                continue;
            }
            let decoded = match keyhog_core::encoding::decode_standard_base64(encoded) {
                Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                Err(_) => continue,
            };
            let line = find_line_number(text, encoded).unwrap_or(1);
            pairs.push(ExtractedPair {
                context: key.to_string(),
                value: decoded,
                line,
            });
        }
    }

    if let Some(serde_yaml::Value::Mapping(map)) = value.get("stringData") {
        for (k, v) in map {
            let key = k.as_str().unwrap_or_default();
            let secret_value = v.as_str().unwrap_or_default().to_string();
            if key.is_empty() {
                continue;
            }
            let line = find_line_number(text, key).unwrap_or(1);
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
pub fn parse_docker_compose(text: &str) -> Vec<ExtractedPair> {
    let mut pairs = Vec::new();
    let value: serde_yaml::Value = match serde_yaml::from_str(text) {
        Ok(v) => v,
        Err(error) => {
            tracing::debug!(target: "keyhog::structured", %error, "docker-compose YAML parse failed");
            return pairs;
        }
    };
    find_environment_pairs(&value, text, &mut pairs, 0);
    pairs
}

/// Cap recursion depth on adversarial YAML - same threat as
/// [`MAX_TFSTATE_DEPTH`] for JSON. Real docker-compose schemas nest
/// ~6 levels deep (`services.<name>.environment.<list>`); 256 leaves
/// the policy permissive but guards against a malicious YAML that
/// embeds deep `services:` chains to stack-overflow the scanner.
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
                let key = k.as_str().unwrap_or_default();
                let val = v.as_str().unwrap_or_default().to_string();
                if key.is_empty() {
                    continue;
                }
                let line = find_line_number(text, key).unwrap_or(1);
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
                        // A leading `=` (e.g. `=secretvalue`) produces an
                        // empty key - that's malformed compose and the empty
                        // context would be useless downstream. Skip in line
                        // with the k8s parser's empty-key policy.
                        if key.is_empty() {
                            continue;
                        }
                        let line = find_line_number(text, s).unwrap_or(1);
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

/// Parse Terraform state JSON and recursively extract `value` fields.
pub fn parse_tfstate(text: &str) -> Vec<ExtractedPair> {
    let mut pairs = Vec::new();
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(error) => {
            tracing::debug!(target: "keyhog::structured", %error, "tfstate JSON parse failed");
            return pairs;
        }
    };
    extract_tfstate_values(&value, text, &mut pairs, 0);
    pairs
}

/// Cap recursion depth on adversarial JSON. A 2 MiB document of
/// nothing but `[[[...]]]` can nest >500k levels deep - beyond the
/// 8 MiB default stack of most Linux threads. 256 is enough for any
/// real Terraform statefile (the deepest natural nesting in the
/// schema is ~12 levels) but bails before stack overflow.
const MAX_TFSTATE_DEPTH: usize = 256;

fn extract_tfstate_values(
    value: &serde_json::Value,
    text: &str,
    pairs: &mut Vec<ExtractedPair>,
    depth: usize,
) {
    if depth >= MAX_TFSTATE_DEPTH {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if k == "value" {
                    let val_str = match v {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Number(n) => n.to_string(),
                        serde_json::Value::Bool(b) => b.to_string(),
                        _ => String::new(),
                    };
                    if !val_str.is_empty() {
                        let line = find_line_number(text, &val_str).unwrap_or(1);
                        pairs.push(ExtractedPair {
                            context: "tfstate-value".to_string(),
                            value: val_str,
                            line,
                        });
                    }
                }
                extract_tfstate_values(v, text, pairs, depth + 1);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                extract_tfstate_values(v, text, pairs, depth + 1);
            }
        }
        _ => {}
    }
}

/// Parse Jupyter notebook JSON and extract code cell sources.
pub fn parse_jupyter(text: &str) -> Vec<ExtractedPair> {
    let mut pairs = Vec::new();
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(error) => {
            tracing::debug!(target: "keyhog::structured", %error, "Jupyter notebook JSON parse failed");
            return pairs;
        }
    };
    let cells = match value.get("cells") {
        Some(serde_json::Value::Array(arr)) => arr,
        _ => return pairs,
    };
    for (idx, cell) in cells.iter().enumerate() {
        let cell_type = cell.get("cell_type").and_then(|c| c.as_str()).unwrap_or("");
        if cell_type != "code" {
            continue;
        }
        let source = match cell.get("source") {
            Some(v) => v,
            None => continue,
        };
        let (source_text, line) = match source {
            serde_json::Value::String(s) => {
                let line = find_line_number(text, s).unwrap_or(1);
                (s.clone(), line)
            }
            serde_json::Value::Array(arr) => {
                let parts: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
                let joined = parts.join("");
                // The joined source contains literal `\n` characters, but
                // the on-disk JSON encodes them as the escape sequence
                // `\\n`. Searching for the joined whole - or even a
                // single fragment that still ends in `\n` - therefore
                // never matches, collapsing line attribution to 1 for
                // every multi-string cell. Anchor on the first non-empty
                // fragment with trailing newlines stripped: the leading
                // bytes ARE present verbatim in the source JSON.
                let anchor = parts
                    .iter()
                    .find_map(|p| {
                        let trimmed_end = p.trim_end_matches(['\n', '\r']);
                        if trimmed_end.is_empty() {
                            None
                        } else {
                            Some(trimmed_end.to_string())
                        }
                    })
                    .unwrap_or_else(|| joined.clone());
                let line = find_line_number(text, &anchor).unwrap_or(1);
                (joined, line)
            }
            _ => continue,
        };
        if !source_text.trim().is_empty() {
            pairs.push(ExtractedPair {
                context: format!("jupyter-cell-{}", idx),
                value: source_text,
                line,
            });
        }
    }
    pairs
}

fn find_line_number(text: &str, needle: &str) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let pos = text.find(needle)?;
    let line = text[..pos].chars().filter(|&c| c == '\n').count() + 1;
    Some(line)
}
