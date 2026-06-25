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
    extract_tfstate_outputs(&value, &mut pending, 0);
    extract_tfstate_resource_collections(&value, &mut pending, 0);
    finalize_pending_pairs(text, pending)
}

/// Cap recursion depth on adversarial JSON. A 2 MiB document of nested arrays
/// can exceed the default thread stack; 256 is beyond real Terraform state.
const MAX_TFSTATE_DEPTH: usize = 256;

fn extract_tfstate_outputs(
    value: &serde_json::Value,
    pending: &mut Vec<PendingExtractedPair>,
    depth: usize,
) {
    if depth >= MAX_TFSTATE_DEPTH {
        return;
    }
    let serde_json::Value::Object(map) = value else {
        return;
    };
    if let Some(outputs) = map.get("outputs") {
        extract_tfstate_output_values(outputs, pending, depth + 1);
    }
    if let Some(values) = map.get("values") {
        extract_tfstate_outputs(values, pending, depth + 1);
    }
}

fn extract_tfstate_output_values(
    value: &serde_json::Value,
    pending: &mut Vec<PendingExtractedPair>,
    depth: usize,
) {
    if depth >= MAX_TFSTATE_DEPTH {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            if let Some(v) = map.get("value") {
                if let Some(val_str) = scalar_value_text(v) {
                    pending.push(PendingExtractedPair::value_anchor("tfstate-value", val_str));
                }
                return;
            }
            for (key, output) in map {
                if let Some(v) = output.get("value") {
                    if let Some(val_str) = scalar_value_text(v) {
                        let context = if key.is_empty() {
                            "tfstate-value".to_string()
                        } else {
                            format!("tfstate-output.{key}")
                        };
                        pending.push(PendingExtractedPair::value_anchor(context, val_str));
                    }
                } else {
                    extract_tfstate_output_values(output, pending, depth + 1);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                extract_tfstate_output_values(v, pending, depth + 1);
            }
        }
        _ => {}
    }
}

fn extract_tfstate_resource_collections(
    value: &serde_json::Value,
    pending: &mut Vec<PendingExtractedPair>,
    depth: usize,
) {
    if depth >= MAX_TFSTATE_DEPTH {
        return;
    }
    let serde_json::Value::Object(map) = value else {
        return;
    };
    if let Some(serde_json::Value::Array(resources)) = map.get("resources") {
        for resource in resources {
            extract_tfstate_resource(resource, pending);
        }
    }
    if let Some(values) = map.get("values") {
        extract_tfstate_resource_collections(values, pending, depth + 1);
    }
    if let Some(root_module) = map.get("root_module") {
        extract_tfstate_module_resources(root_module, pending, depth + 1);
    }
}

fn extract_tfstate_module_resources(
    module: &serde_json::Value,
    pending: &mut Vec<PendingExtractedPair>,
    depth: usize,
) {
    if depth >= MAX_TFSTATE_DEPTH {
        return;
    }
    let serde_json::Value::Object(map) = module else {
        return;
    };
    if let Some(serde_json::Value::Array(resources)) = map.get("resources") {
        for resource in resources {
            extract_tfstate_resource(resource, pending);
        }
    }
    if let Some(serde_json::Value::Array(child_modules)) = map.get("child_modules") {
        for child in child_modules {
            extract_tfstate_module_resources(child, pending, depth + 1);
        }
    }
}

fn extract_tfstate_resource(resource: &serde_json::Value, pending: &mut Vec<PendingExtractedPair>) {
    let serde_json::Value::Object(map) = resource else {
        return;
    };
    let address = map
        .get("address")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty());
    let module = map
        .get("module")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty());
    let resource_type = map
        .get("type")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty());
    let resource_name = map
        .get("name")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty());
    let base_context = match address {
        Some(address) => address.to_string(),
        None => match (module, resource_type, resource_name) {
            (Some(module), Some(resource_type), Some(resource_name)) => {
                format!("{module}.{resource_type}.{resource_name}")
            }
            (_, Some(resource_type), Some(resource_name)) => {
                format!("{resource_type}.{resource_name}")
            }
            (_, Some(resource_type), None) => resource_type.to_string(),
            (_, None, Some(resource_name)) => resource_name.to_string(),
            (_, None, None) => "tfstate-resource".to_string(),
        },
    };
    let Some(instances) = map.get("instances").and_then(serde_json::Value::as_array) else {
        return;
    };
    let include_index = instances.len() > 1;
    for (idx, instance) in instances.iter().enumerate() {
        let instance_context =
            tfstate_instance_context(&base_context, instance, idx, include_index);
        if let Some(attributes) = instance.get("attributes") {
            extract_tfstate_attribute_scalars(attributes, pending, &instance_context, "", None, 0);
        }
    }
}

fn tfstate_instance_context(
    base_context: &str,
    instance: &serde_json::Value,
    fallback_idx: usize,
    include_index: bool,
) -> String {
    match instance.get("index_key").and_then(json_index_key_literal) {
        Some(index_key) => format!("{base_context}[{index_key}]"),
        None if include_index => format!("{base_context}[{fallback_idx}]"),
        None => base_context.to_string(),
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
        if let Some(source) = cell.get("source") {
            extract_jupyter_source(source, idx, &mut pending);
        }
        extract_jupyter_outputs(cell, idx, &mut pending);
    }
    finalize_pending_pairs(text, pending)
}

fn extract_jupyter_source(
    source: &serde_json::Value,
    idx: usize,
    pending: &mut Vec<PendingExtractedPair>,
) {
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
            let (joined, anchor, malformed) = jupyter_join_text_fragments(arr);
            if malformed {
                crate::telemetry::record_structured_parse_failure();
                tracing::warn!(
                    target: "keyhog::structured",
                    cell = idx,
                    "Jupyter notebook code cell source array contains a non-string fragment; valid fragments will be decoded-through"
                );
            }
            push_jupyter_text_pair(pending, format!("jupyter-cell-{idx}"), joined, anchor);
        }
        _ => {
            crate::telemetry::record_structured_parse_failure();
            tracing::warn!(
                target: "keyhog::structured",
                cell = idx,
                "Jupyter notebook code cell source has unsupported shape; code cell will not be decoded-through"
            );
        }
    }
}

fn extract_jupyter_outputs(
    cell: &serde_json::Value,
    idx: usize,
    pending: &mut Vec<PendingExtractedPair>,
) {
    let Some(outputs) = cell.get("outputs") else {
        return;
    };
    let serde_json::Value::Array(outputs) = outputs else {
        crate::telemetry::record_structured_parse_failure();
        tracing::warn!(
            target: "keyhog::structured",
            cell = idx,
            "Jupyter notebook code cell outputs field has unsupported shape; outputs will not be decoded-through"
        );
        return;
    };
    for (output_idx, output) in outputs.iter().enumerate() {
        extract_jupyter_output(output, idx, output_idx, pending);
    }
}

fn extract_jupyter_output(
    output: &serde_json::Value,
    cell_idx: usize,
    output_idx: usize,
    pending: &mut Vec<PendingExtractedPair>,
) {
    let context = format!("jupyter-cell-{cell_idx}-output-{output_idx}");
    if let Some(text) = output.get("text") {
        extract_jupyter_output_text(text, &context, pending, cell_idx, output_idx, "text");
    }
    if let Some(text_plain) = output.get("data").and_then(|data| data.get("text/plain")) {
        extract_jupyter_output_text(
            text_plain,
            &format!("{context}.text/plain"),
            pending,
            cell_idx,
            output_idx,
            "text/plain",
        );
    }
    if let Some(traceback) = output.get("traceback") {
        extract_jupyter_output_text(
            traceback,
            &format!("{context}.traceback"),
            pending,
            cell_idx,
            output_idx,
            "traceback",
        );
    }
}

fn extract_jupyter_output_text(
    value: &serde_json::Value,
    context: &str,
    pending: &mut Vec<PendingExtractedPair>,
    cell_idx: usize,
    output_idx: usize,
    surface: &'static str,
) {
    match value {
        serde_json::Value::String(s) => {
            push_jupyter_text_pair(pending, context.to_string(), s.clone(), None);
        }
        serde_json::Value::Array(arr) => {
            let (joined, anchor, malformed) = jupyter_join_text_fragments(arr);
            if malformed {
                crate::telemetry::record_structured_parse_failure();
                tracing::warn!(
                    target: "keyhog::structured",
                    cell = cell_idx,
                    output = output_idx,
                    surface,
                    "Jupyter notebook output text array contains a non-string fragment; valid fragments will be decoded-through"
                );
            }
            push_jupyter_text_pair(pending, context.to_string(), joined, anchor);
        }
        _ => {
            crate::telemetry::record_structured_parse_failure();
            tracing::warn!(
                target: "keyhog::structured",
                cell = cell_idx,
                output = output_idx,
                surface,
                "Jupyter notebook output text has unsupported shape; output will not be decoded-through"
            );
        }
    }
}

fn jupyter_join_text_fragments(arr: &[serde_json::Value]) -> (String, Option<String>, bool) {
    let mut malformed = false;
    let mut parts = Vec::with_capacity(arr.len());
    for fragment in arr {
        match fragment.as_str() {
            Some(text) => parts.push(text.to_string()),
            None => malformed = true,
        }
    }
    let anchor = first_nonempty_fragment_anchor(&parts);
    (parts.join(""), anchor, malformed)
}

fn push_jupyter_text_pair(
    pending: &mut Vec<PendingExtractedPair>,
    context: String,
    value: String,
    anchor: Option<String>,
) {
    if value.trim().is_empty() {
        return;
    }
    match anchor {
        Some(anchor) => pending.push(PendingExtractedPair::owned_anchor(context, value, anchor)),
        None => pending.push(PendingExtractedPair::value_anchor(context, value)),
    }
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
        format!("{key_literal}:{value_literal}"),
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

fn json_index_key_literal(value: &serde_json::Value) -> Option<String> {
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
