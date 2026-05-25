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
        Err(_) => return pairs,
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
        Err(_) => return pairs,
    };
    find_environment_pairs(&value, text, &mut pairs);
    pairs
}

fn find_environment_pairs(value: &serde_yaml::Value, text: &str, pairs: &mut Vec<ExtractedPair>) {
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map {
                if k.as_str() == Some("environment") {
                    extract_environment_block(v, text, pairs);
                } else {
                    find_environment_pairs(v, text, pairs);
                }
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for v in seq {
                find_environment_pairs(v, text, pairs);
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
                        // empty key — that's malformed compose and the empty
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
        Err(_) => return pairs,
    };
    extract_tfstate_values(&value, text, &mut pairs);
    pairs
}

fn extract_tfstate_values(value: &serde_json::Value, text: &str, pairs: &mut Vec<ExtractedPair>) {
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
                extract_tfstate_values(v, text, pairs);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                extract_tfstate_values(v, text, pairs);
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
        Err(_) => return pairs,
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
                // `\\n`. Searching for the joined whole — or even a
                // single fragment that still ends in `\n` — therefore
                // never matches, collapsing line attribution to 1 for
                // every multi-string cell. Anchor on the first non-empty
                // fragment with trailing newlines stripped: the leading
                // bytes ARE present verbatim in the source JSON.
                let anchor = parts
                    .iter()
                    .find_map(|p| {
                        let trimmed_end = p.trim_end_matches(|c: char| c == '\n' || c == '\r');
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `parse_env` round-trips simple KEY=VALUE lines and tracks line
    /// numbers correctly.
    #[test]
    fn env_basic_parses_key_value_with_line_numbers() {
        let text = "FOO=bar\nBAZ=qux\n# comment\nexport TOK=abc";
        let pairs = parse_env(text);
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0].context, "FOO");
        assert_eq!(pairs[0].value, "bar");
        assert_eq!(pairs[0].line, 1);
        assert_eq!(pairs[1].context, "BAZ");
        assert_eq!(pairs[1].line, 2);
        assert_eq!(pairs[2].context, "TOK");
        assert_eq!(pairs[2].value, "abc");
        assert_eq!(pairs[2].line, 4);
    }

    /// `parse_env` strips matching quotes.
    #[test]
    fn env_strips_matching_quotes() {
        let text = "DOUBLE=\"hello world\"\nSINGLE='another'";
        let pairs = parse_env(text);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].value, "hello world");
        assert_eq!(pairs[1].value, "another");
    }

    /// Regression: a docker-compose `environment:` sequence entry like
    /// `=secretvalue` (leading `=`) used to produce an ExtractedPair
    /// with an empty `context`. That's malformed compose and the empty
    /// context would be useless downstream — must be skipped, matching
    /// the k8s parser's empty-key policy.
    #[test]
    fn docker_compose_sequence_skips_empty_key_with_leading_equals() {
        let text = "\
services:
  app:
    environment:
      - FOO=bar
      - =should_be_skipped
      - BAZ=qux
";
        let pairs = parse_docker_compose(text);
        // Three entries in the YAML, but the one with the empty key
        // must be dropped — so we expect FOO and BAZ only.
        let contexts: Vec<_> = pairs.iter().map(|p| p.context.as_str()).collect();
        assert!(contexts.contains(&"FOO"));
        assert!(contexts.contains(&"BAZ"));
        assert!(
            !contexts.iter().any(|c| c.is_empty()),
            "empty-context entry must be skipped, got {contexts:?}"
        );
        assert_eq!(pairs.len(), 2, "expected two pairs after dropping the empty-key entry");
    }

    /// Docker-compose sequence form `FOO=` (empty value, non-empty key)
    /// MUST still be preserved — env vars are legitimately allowed to
    /// be set to empty.
    #[test]
    fn docker_compose_sequence_preserves_empty_value_with_present_key() {
        let text = "\
services:
  app:
    environment:
      - EMPTY_VAR=
      - SET_VAR=value
";
        let pairs = parse_docker_compose(text);
        let by_key: std::collections::HashMap<_, _> = pairs
            .iter()
            .map(|p| (p.context.clone(), p.value.clone()))
            .collect();
        assert_eq!(by_key.get("EMPTY_VAR"), Some(&String::new()));
        assert_eq!(by_key.get("SET_VAR"), Some(&"value".to_string()));
    }

    /// Regression: a Jupyter notebook code cell with `source` as an
    /// array of strings (the canonical .ipynb form) used to attribute
    /// every cell to line 1 because the joined source contained literal
    /// `\n` while the on-disk JSON encodes them as the escape sequence
    /// `\\n`. The line lookup therefore always missed. Now we anchor
    /// on the first non-empty fragment, which IS present verbatim in
    /// the source JSON.
    #[test]
    fn jupyter_array_source_attributes_to_first_fragment_line() {
        let nb = r#"{
            "cells": [
                {"cell_type": "markdown", "source": "header"},
                {"cell_type": "code", "source": ["import os\n", "secret='abc'\n"]}
            ]
        }"#;
        let pairs = parse_jupyter(nb);
        assert_eq!(pairs.len(), 1, "only the code cell should be extracted");
        let cell = &pairs[0];
        assert!(cell.value.contains("import os"));
        assert!(cell.value.contains("secret='abc'"));
        // The first fragment `"import os\n"` appears in the JSON on
        // a line >= 3, so the line attribution must not collapse to 1.
        assert!(
            cell.line >= 3,
            "expected line attribution to first fragment (>=3), got {}",
            cell.line
        );
    }

    /// Jupyter cell with single string source still works (string path,
    /// not the array path).
    #[test]
    fn jupyter_string_source_extracts_code_cell() {
        let nb = r#"{
            "cells": [
                {"cell_type": "code", "source": "import os\nsecret='abc'"}
            ]
        }"#;
        let pairs = parse_jupyter(nb);
        assert_eq!(pairs.len(), 1);
        assert!(pairs[0].value.contains("secret='abc'"));
    }

    /// k8s Secret `data:` values are base64-decoded and surfaced with
    /// their key as context.
    #[test]
    fn k8s_secret_decodes_data_field() {
        // base64("hunter2") = "aHVudGVyMg=="
        let text = "\
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
data:
  password: aHVudGVyMg==
  username: dXNlcg==
";
        let pairs = parse_k8s_secret(text);
        assert_eq!(pairs.len(), 2);
        let by_key: std::collections::HashMap<_, _> = pairs
            .iter()
            .map(|p| (p.context.clone(), p.value.clone()))
            .collect();
        assert_eq!(by_key.get("password"), Some(&"hunter2".to_string()));
        assert_eq!(by_key.get("username"), Some(&"user".to_string()));
    }

    /// k8s `stringData:` values are surfaced verbatim (no base64).
    #[test]
    fn k8s_secret_passes_through_string_data() {
        let text = "\
apiVersion: v1
kind: Secret
stringData:
  token: my-plain-token
";
        let pairs = parse_k8s_secret(text);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].context, "token");
        assert_eq!(pairs[0].value, "my-plain-token");
    }
}
