use super::{line::resolve_line_numbers, ExtractedPair};

enum LineAnchor {
    Value,
    Owned(String),
}

struct PendingExtractedPair {
    context: String,
    value: String,
    line_anchor: LineAnchor,
}

impl PendingExtractedPair {
    fn value_anchor(context: impl Into<String>, value: String) -> Self {
        Self {
            context: context.into(),
            value,
            line_anchor: LineAnchor::Value,
        }
    }

    fn owned_anchor(context: impl Into<String>, value: String, line_anchor: String) -> Self {
        Self {
            context: context.into(),
            value,
            line_anchor: LineAnchor::Owned(line_anchor),
        }
    }

    fn line_anchor(&self) -> &str {
        match &self.line_anchor {
            LineAnchor::Value => &self.value,
            LineAnchor::Owned(anchor) => anchor,
        }
    }
}

/// Parse Terraform state JSON and recursively extract `value` fields.
pub(crate) fn parse_tfstate(text: &str) -> Vec<ExtractedPair> {
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(error) => {
            // Law 10: a `.tfstate` file that won't parse loses its structured
            // decode-through (the `value` fields never become scannable lines).
            // Count it so the scan surfaces the coverage gap; keep the debug log
            // for the `-v` error detail.
            crate::telemetry::record_structured_parse_failure();
            tracing::warn!(target: "keyhog::structured", %error, "tfstate JSON parse failed; value fields will not be decoded-through");
            return Vec::new();
        }
    };
    let mut pending = Vec::new();
    extract_tfstate_values(&value, &mut pending, 0);
    finalize_pending_pairs(text, pending)
}

/// Cap recursion depth on adversarial JSON. A 2 MiB document of nested arrays
/// can exceed the default thread stack; 256 is beyond real Terraform state.
const MAX_TFSTATE_DEPTH: usize = 256;

fn extract_tfstate_values(
    value: &serde_json::Value,
    pending: &mut Vec<PendingExtractedPair>,
    depth: usize,
) {
    if depth >= MAX_TFSTATE_DEPTH {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if k == "value" {
                    if let Some(val_str) = scalar_value_text(v) {
                        pending.push(PendingExtractedPair::value_anchor("tfstate-value", val_str));
                    }
                }
                extract_tfstate_values(v, pending, depth + 1);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                extract_tfstate_values(v, pending, depth + 1);
            }
        }
        _ => {}
    }
}

/// Parse Jupyter notebook JSON and extract code cell sources.
pub(crate) fn parse_jupyter(text: &str) -> Vec<ExtractedPair> {
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(error) => {
            // Law 10: a `.ipynb` that won't parse loses its code-cell
            // decode-through (secrets pasted into notebook cells never become
            // scannable lines). Count + keep the debug detail.
            crate::telemetry::record_structured_parse_failure();
            tracing::warn!(target: "keyhog::structured", %error, "Jupyter notebook JSON parse failed; code cells will not be decoded-through");
            return Vec::new();
        }
    };
    let cells = match value.get("cells") {
        Some(serde_json::Value::Array(arr)) => arr,
        _ => return Vec::new(),
    };
    let mut pending = Vec::new();
    for (idx, cell) in cells.iter().enumerate() {
        let cell_type = match cell.get("cell_type").and_then(|c| c.as_str()) {
            Some(cell_type) => cell_type,
            None => "",
        };
        if cell_type != "code" {
            continue;
        }
        let source = match cell.get("source") {
            Some(v) => v,
            None => continue,
        };
        match source {
            serde_json::Value::String(s) => {
                if !s.trim().is_empty() {
                    pending.push(PendingExtractedPair::value_anchor(
                        format!("jupyter-cell-{idx}"),
                        s.clone(),
                    ));
                }
            }
            serde_json::Value::Array(arr) => {
                let mut malformed_source_fragment = false;
                let mut parts = Vec::with_capacity(arr.len());
                for fragment in arr {
                    match fragment.as_str() {
                        Some(text) => parts.push(text.to_string()),
                        None => malformed_source_fragment = true,
                    }
                }
                if malformed_source_fragment {
                    crate::telemetry::record_structured_parse_failure();
                    tracing::warn!(
                        target: "keyhog::structured",
                        cell = idx,
                        "Jupyter notebook code cell source array contains a non-string fragment; valid fragments will be decoded-through"
                    );
                }
                let joined = parts.join("");
                if !joined.trim().is_empty() {
                    match first_nonempty_fragment_anchor(&parts) {
                        Some(anchor) => pending.push(PendingExtractedPair::owned_anchor(
                            format!("jupyter-cell-{idx}"),
                            joined,
                            anchor,
                        )),
                        None => pending.push(PendingExtractedPair::value_anchor(
                            format!("jupyter-cell-{idx}"),
                            joined,
                        )),
                    }
                }
            }
            _ => {
                crate::telemetry::record_structured_parse_failure();
                tracing::warn!(
                    target: "keyhog::structured",
                    cell = idx,
                    "Jupyter notebook code cell source has unsupported shape; code cell will not be decoded-through"
                );
                continue;
            }
        };
    }
    finalize_pending_pairs(text, pending)
}

fn scalar_value_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn first_nonempty_fragment_anchor(parts: &[String]) -> Option<String> {
    for part in parts {
        let trimmed_end = part.trim_end_matches(['\n', '\r']);
        if !trimmed_end.is_empty() {
            return Some(trimmed_end.to_string());
        }
    }
    None
}

fn finalize_pending_pairs(text: &str, pending: Vec<PendingExtractedPair>) -> Vec<ExtractedPair> {
    let anchors: Vec<&str> = pending
        .iter()
        .map(PendingExtractedPair::line_anchor)
        .collect();
    let lines = resolve_line_numbers(text, &anchors);
    let mut pairs = Vec::with_capacity(pending.len());
    for (index, pending_pair) in pending.into_iter().enumerate() {
        let line = match lines.get(index) {
            Some(line) => *line,
            None => 1,
        };
        pairs.push(ExtractedPair {
            context: pending_pair.context,
            value: pending_pair.value,
            line,
        });
    }
    pairs
}
