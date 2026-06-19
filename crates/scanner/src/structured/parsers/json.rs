use super::{line::find_line_number, ExtractedPair};

/// Parse Terraform state JSON and recursively extract `value` fields.
pub(crate) fn parse_tfstate(text: &str) -> Vec<ExtractedPair> {
    let mut pairs = Vec::new();
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(error) => {
            // Law 10: a `.tfstate` file that won't parse loses its structured
            // decode-through (the `value` fields never become scannable lines).
            // Count it so the scan surfaces the coverage gap; keep the debug log
            // for the `-v` error detail.
            crate::telemetry::record_structured_parse_failure();
            tracing::warn!(target: "keyhog::structured", %error, "tfstate JSON parse failed; value fields will not be decoded-through");
            return pairs;
        }
    };
    extract_tfstate_values(&value, text, &mut pairs, 0);
    pairs
}

/// Cap recursion depth on adversarial JSON. A 2 MiB document of nested arrays
/// can exceed the default thread stack; 256 is beyond real Terraform state.
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
                        let line = find_line_number(text, &val_str).unwrap_or(1); // LAW10: line not located => placeholder line for REPORTING only; finding still emitted, recall-safe
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
pub(crate) fn parse_jupyter(text: &str) -> Vec<ExtractedPair> {
    let mut pairs = Vec::new();
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(error) => {
            // Law 10: a `.ipynb` that won't parse loses its code-cell
            // decode-through (secrets pasted into notebook cells never become
            // scannable lines). Count + keep the debug detail.
            crate::telemetry::record_structured_parse_failure();
            tracing::warn!(target: "keyhog::structured", %error, "Jupyter notebook JSON parse failed; code cells will not be decoded-through");
            return pairs;
        }
    };
    let cells = match value.get("cells") {
        Some(serde_json::Value::Array(arr)) => arr,
        _ => return pairs,
    };
    for (idx, cell) in cells.iter().enumerate() {
        let cell_type = cell.get("cell_type").and_then(|c| c.as_str()).unwrap_or(""); // LAW10: missing/non-string field => empty; value then fails downstream shape/length checks, recall-safe
        if cell_type != "code" {
            continue;
        }
        let source = match cell.get("source") {
            Some(v) => v,
            None => continue,
        };
        let (source_text, line) = match source {
            serde_json::Value::String(s) => {
                let line = find_line_number(text, s).unwrap_or(1); // LAW10: line not located => placeholder line for REPORTING only; finding still emitted, recall-safe
                (s.clone(), line)
            }
            serde_json::Value::Array(arr) => {
                let parts: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
                let joined = parts.join("");
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
                    .unwrap_or_else(|| joined.clone()); // LAW10: missing/non-string field => empty; value then fails downstream shape/length checks, recall-safe
                let line = find_line_number(text, &anchor).unwrap_or(1); // LAW10: line not located => placeholder line for REPORTING only; finding still emitted, recall-safe
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
