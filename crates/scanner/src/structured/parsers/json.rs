use super::{
    line::{finalize_pending_pairs, PendingExtractedPair},
    ExtractedPair,
};

/// Parse Terraform state JSON and recursively extract output `value` fields and
/// resource instance attributes.
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
    extract_tfstate_resource_attributes(&value, &mut pending, 0);
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

fn extract_tfstate_resource_attributes(
    value: &serde_json::Value,
    pending: &mut Vec<PendingExtractedPair>,
    depth: usize,
) {
    if depth >= MAX_TFSTATE_DEPTH {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::Array(resources)) = map.get("resources") {
                for resource in resources {
                    extract_tfstate_resource(resource, pending);
                }
            }
            for v in map.values() {
                extract_tfstate_resource_attributes(v, pending, depth + 1);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                extract_tfstate_resource_attributes(v, pending, depth + 1);
            }
        }
        _ => {}
    }
}

fn extract_tfstate_resource(resource: &serde_json::Value, pending: &mut Vec<PendingExtractedPair>) {
    let serde_json::Value::Object(map) = resource else {
        return;
    };
    let resource_type = map
        .get("type")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty());
    let resource_name = map
        .get("name")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty());
    let base_context = match (resource_type, resource_name) {
        (Some(resource_type), Some(resource_name)) => format!("{resource_type}.{resource_name}"),
        (Some(resource_type), None) => resource_type.to_string(),
        (None, Some(resource_name)) => resource_name.to_string(),
        (None, None) => "tfstate-resource".to_string(),
    };
    let Some(instances) = map.get("instances").and_then(serde_json::Value::as_array) else {
        return;
    };
    let include_index = instances.len() > 1;
    for (idx, instance) in instances.iter().enumerate() {
        let instance_context = if include_index {
            format!("{base_context}[{idx}]")
        } else {
            base_context.clone()
        };
        if let Some(attributes) = instance.get("attributes") {
            extract_tfstate_attribute_scalars(attributes, pending, &instance_context, "", None, 0);
        }
    }
}

fn extract_tfstate_attribute_scalars(
    value: &serde_json::Value,
    pending: &mut Vec<PendingExtractedPair>,
    context_prefix: &str,
    attribute_path: &str,
    anchor_key: Option<&str>,
    depth: usize,
) {
    if depth >= MAX_TFSTATE_DEPTH {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let next_path = if attribute_path.is_empty() {
                    key.to_string()
                } else {
                    format!("{attribute_path}.{key}")
                };
                extract_tfstate_attribute_scalars(
                    child,
                    pending,
                    context_prefix,
                    &next_path,
                    Some(key),
                    depth + 1,
                );
            }
        }
        serde_json::Value::Array(arr) => {
            for (idx, child) in arr.iter().enumerate() {
                let next_path = format!("{attribute_path}[{idx}]");
                extract_tfstate_attribute_scalars(
                    child,
                    pending,
                    context_prefix,
                    &next_path,
                    None,
                    depth + 1,
                );
            }
        }
        _ => {
            let Some(val_str) = scalar_value_text(value) else {
                return;
            };
            let context = if attribute_path.is_empty() {
                context_prefix.to_string()
            } else {
                format!("{context_prefix}.{attribute_path}")
            };
            match anchor_key.and_then(|key| json_mapping_anchors(key, value)) {
                Some((line_anchor, fallback_anchor)) => {
                    pending.push(PendingExtractedPair::owned_anchor_with_fallback(
                        context,
                        val_str,
                        line_anchor,
                        fallback_anchor,
                    ));
                }
                None => pending.push(PendingExtractedPair::value_anchor(context, val_str)),
            }
        }
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

fn json_mapping_anchors(key: &str, value: &serde_json::Value) -> Option<(String, String)> {
    let key_literal = json_string_literal(key);
    let value_literal = json_scalar_literal(value)?;
    Some((
        format!("{key_literal}: {value_literal}"),
        format!("{key_literal}:"),
    ))
}

fn json_scalar_literal(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(json_string_literal(s)),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn json_string_literal(s: &str) -> String {
    serde_json::Value::String(s.to_string()).to_string()
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
