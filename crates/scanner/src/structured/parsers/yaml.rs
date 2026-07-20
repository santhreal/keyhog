use super::{
    line::{finalize_pending_pairs, PendingExtractedPair},
    ExtractedPair,
};
use serde::Deserialize;

fn sanitize_helm_actions(text: &str) -> Option<String> {
    let mut output = String::with_capacity(text.len());
    let mut active = true;
    let mut control_stack = Vec::new();
    let mut changed = false;

    for line in text.split_inclusive('\n') {
        if let Some(action) = whole_line_helm_action(line) {
            let Some(keyword) = action.split_ascii_whitespace().next() else {
                comment_helm_line(&mut output, line);
                changed = true;
                continue;
            };
            match keyword {
                "if" | "range" | "with" => control_stack.push(active),
                "else" => active = false,
                "end" => active = control_stack.pop()?,
                _ => {}
            }
            comment_helm_line(&mut output, line);
            changed = true;
            continue;
        }
        if !active {
            comment_helm_line(&mut output, line);
            changed = true;
            continue;
        }

        let mut cursor = 0;
        while let Some(relative_start) = line[cursor..].find("{{") {
            let start = cursor + relative_start;
            let relative_end = line[start + 2..].find("}}")?;
            let end = start + 2 + relative_end + 2;
            output.push_str(&line[cursor..start]);
            output.extend(std::iter::repeat_n('_', end - start));
            cursor = end;
            changed = true;
        }
        output.push_str(&line[cursor..]);
    }
    if !control_stack.is_empty() {
        return None;
    }
    changed.then_some(output)
}

fn whole_line_helm_action(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    let mut action = trimmed.strip_prefix("{{")?.strip_suffix("}}")?.trim();
    if action.contains("}}") || action.contains("{{") {
        return None;
    }
    if let Some(stripped) = action.strip_prefix('-') {
        action = stripped.trim_start();
    }
    if let Some(stripped) = action.strip_suffix('-') {
        action = stripped.trim_end();
    }
    Some(action)
}

fn comment_helm_line(output: &mut String, line: &str) {
    let content_len = line.strip_suffix('\n').map_or(line.len(), str::len);
    if content_len > 0 {
        output.push('#');
        output.extend(std::iter::repeat_n(' ', content_len - 1));
    }
    if line.ends_with('\n') {
        output.push('\n');
    }
}

fn deserialize_yaml_documents(
    text: &str,
) -> Result<Vec<serde_yaml::Value>, (serde_yaml::Error, Vec<serde_yaml::Value>)> {
    let mut values = Vec::new();
    for document in serde_yaml::Deserializer::from_str(text) {
        match serde_yaml::Value::deserialize(document) {
            Ok(value) => values.push(value),
            Err(error) => return Err((error, values)),
        }
    }
    Ok(values)
}

/// Return whether any valid YAML document is a Kubernetes Secret or contains
/// one through a Kubernetes `List`. A parse error remains distinct from a valid
/// non-Secret document so classification can route hinted malformed Secrets to
/// the parser that records the coverage gap.
pub(crate) fn contains_k8s_secret_document(text: &str) -> Result<bool, ()> {
    let values = match deserialize_yaml_documents(text) {
        Ok(values) => values,
        Err((_error, _partial)) => {
            // LAW10: recall-preserving; only balanced Helm actions are sanitized, then the complete document must parse
            let sanitized = sanitize_helm_actions(text).ok_or(())?;
            deserialize_yaml_documents(&sanitized).map_err(|_| ())?
        }
    };
    Ok(values
        .iter()
        .any(|value| contains_k8s_secret_value(value, 0)))
}

fn contains_k8s_secret_value(value: &serde_yaml::Value, depth: usize) -> bool {
    if depth >= super::MAX_STRUCTURED_TRAVERSAL_DEPTH {
        return false;
    }
    match yaml_kind(value) {
        Some("Secret") => true,
        Some("List") => value
            .get("items")
            .and_then(serde_yaml::Value::as_sequence)
            .is_some_and(|items| {
                items
                    .iter()
                    .any(|item| contains_k8s_secret_value(item, depth + 1))
            }),
        _ => false,
    }
}

/// Parse a Kubernetes Secret YAML and decode base64 values under `data:`.
///
/// Line-number lookup anchors on the key (`<key>:`) rather than the
/// encoded value: two different keys in the same Secret CAN encode the
/// same byte body, and matching on the encoded blob would route both
/// findings to the first occurrence.
///
/// `decode_derived` is true when `text` is not the original file but a buffer
/// the decode-through pipeline produced by splicing a decoded payload back into
/// the parent (`ChunkMetadata::decoded_span.is_some()`). On a derived buffer a
/// YAML parse failure is EXPECTED and loses nothing, the encoded surface was
/// already decoded and scanned by the pipeline that produced this buffer, so it
/// must not be counted or announced as a lost decode surface (that would be a
/// false Law-10 alarm and would inflate the structured-parse-failure telemetry).
pub(crate) fn parse_k8s_secret(text: &str, decode_derived: bool) -> Vec<ExtractedPair> {
    let values =
        match parse_yaml_documents(text, "k8s-secret", "base64 data: values", decode_derived) {
            Some(values) => values,
            None => return Vec::new(),
        };

    let mut pending = Vec::new();
    for value in &values {
        extract_k8s_secret(value, &mut pending, 0, decode_derived);
    }

    finalize_pending_pairs(text, pending)
}

fn extract_k8s_secret(
    value: &serde_yaml::Value,
    pending: &mut Vec<PendingExtractedPair>,
    depth: usize,
    decode_derived: bool,
) {
    if depth >= super::MAX_STRUCTURED_TRAVERSAL_DEPTH {
        return;
    }
    match yaml_kind(value) {
        Some("Secret") => extract_k8s_secret_maps(value, pending, decode_derived),
        Some("List") => {
            if let Some(serde_yaml::Value::Sequence(items)) = value.get("items") {
                for item in items {
                    extract_k8s_secret(item, pending, depth + 1, decode_derived);
                }
            }
        }
        _ => {}
    }
}

fn extract_k8s_secret_maps(
    value: &serde_yaml::Value,
    pending: &mut Vec<PendingExtractedPair>,
    decode_derived: bool,
) {
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
                    // LAW10: supplementary diagnostic only, recall is preserved by the
                    // whole-chunk scan, so this debug line is not the sole surface.
                    tracing::debug!(
                        target: "keyhog::structured",
                        key,
                        %error,
                        decode_derived,
                        "k8s secret data: value is not valid standard base64; skipping decode-through"
                    );
                    continue;
                }
            };
            if key == ".dockerconfigjson" {
                push_docker_config_passwords(&decoded, pending, &line_anchor, &fallback_anchor);
            }
            pending.push(
                PendingExtractedPair::owned_anchor_with_fallback(
                    key,
                    decoded,
                    line_anchor,
                    fallback_anchor,
                )
                .transport_decoded(),
            );
        }
    }

    if let Some(serde_yaml::Value::Mapping(map)) = value.get("stringData") {
        push_scalar_mapping_pairs(map, pending);
    }
}

/// Extract passwords from Kubernetes' standard `.dockerconfigjson` payload.
/// The outer Secret `data:` value contains JSON, while each registry `auth`
/// member is another base64 layer containing `username:password`. Emitting a
/// password-owned synthetic pair lets the normal detector policy score the
/// actual credential rather than the two encoded wrappers.
fn push_docker_config_passwords(
    decoded: &str,
    pending: &mut Vec<PendingExtractedPair>,
    line_anchor: &str,
    fallback_anchor: &str,
) {
    let Ok(document) = serde_json::from_str::<serde_json::Value>(decoded) else {
        return;
    };
    let Some(auths) = document.get("auths").and_then(serde_json::Value::as_object) else {
        return;
    };

    for (registry, entry) in auths {
        let Some(encoded_auth) = entry.get("auth").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Ok(decoded_auth) = keyhog_core::decode_standard_base64(encoded_auth) else {
            continue;
        };
        let Ok(user_password) = std::str::from_utf8(&decoded_auth) else {
            continue;
        };
        let Some((_, password)) = user_password.split_once(':') else {
            continue;
        };
        if password.is_empty() {
            continue;
        }
        pending.push(
            PendingExtractedPair::owned_anchor_with_fallback(
                format!("{registry}.password"),
                password.to_owned(),
                line_anchor.to_owned(),
                fallback_anchor.to_owned(),
            )
            .transport_decoded(),
        );
    }
}

fn yaml_kind(value: &serde_yaml::Value) -> Option<&str> {
    value.get("kind").and_then(serde_yaml::Value::as_str)
}

/// Parse docker-compose.yml environment blocks.
///
/// `decode_derived` carries the same meaning as in [`parse_k8s_secret`].
pub(crate) fn parse_docker_compose(text: &str, decode_derived: bool) -> Vec<ExtractedPair> {
    let value = match parse_yaml_value(
        text,
        "docker-compose",
        "environment-block values",
        decode_derived,
    ) {
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

/// Report a YAML parse failure on a structured-format surface. Pure logging: the
/// file-level telemetry counter is the CALLER's decision (via
/// [`super::record_structured_gap`]) so a multi-document file that drops several
/// documents records the FILE once, not once per dropped document.
///
/// At decode depth 0 (`decode_derived == false`) the parsed `text` IS the
/// original file, so a parse failure genuinely loses the decode-through surface:
/// warn loudly (the caller records it, Law 10).
///
/// At depth > 0 (`decode_derived == true`) the `text` is a buffer the
/// decode-through pipeline synthesised by splicing an already-decoded payload
/// back into the parent k8s/compose scaffold. Such a buffer is NOT guaranteed to
/// be valid YAML, e.g. a base64 `data:` value that decodes to a JWT whose own
/// base64url header decodes to inline JSON `{"alg":...}.<sig>` is not, yet the
/// secret it carried was already surfaced and scanned when the pipeline produced
/// this buffer. Announcing "decode-through disabled / lost surface" here is a
/// FALSE alarm, so the failure is logged only as debug detail.
///
/// `documents_parsed` is how many `---`-separated documents were decoded before
/// the failing one stopped the stream. libyaml cannot resync a multi-document
/// YAML past a syntax error (every subsequent `parser.next()` re-returns the same
/// error), so any documents AFTER the failure are truncated too, surfacing this
/// count makes that loss visible instead of silently dropping the tail.
fn report_yaml_parse_failure(
    error: &serde_yaml::Error,
    surface: &'static str,
    lost_decode_surface: &'static str,
    decode_derived: bool,
    documents_parsed: usize,
) {
    if !super::gap_is_real(decode_derived) {
        tracing::debug!(
            target: "keyhog::structured",
            %error,
            surface,
            documents_parsed,
            "decode-derived buffer is not valid YAML; nothing lost (payload already \
             decoded and scanned by the decode-through pipeline)"
        );
        return;
    }
    // Law 10: a structured file that won't parse loses its decode-through
    // surface (the caller records it). Warn loudly with a per-surface message so
    // the operator sees exactly which structured format dropped coverage, and how
    // many documents decoded before the stream was truncated at the parse error.
    // serde_yaml also rejects deeply nested YAML before Value construction,
    // hence the recursion-limit field.
    let message = match surface {
        "k8s-secret" => {
            "k8s secret YAML parse failed; decode-through disabled for the failing \
             document and any documents after it in the stream"
        }
        "docker-compose" => {
            "docker-compose YAML parse failed; decode-through disabled for the \
             failing document and any documents after it in the stream"
        }
        _ => {
            "structured YAML parse failed; decode-through disabled for the failing document and \
             any documents after it in the stream"
        }
    };
    tracing::warn!(
        target: "keyhog::structured",
        %error,
        surface,
        lost_decode_surface,
        documents_parsed,
        serde_yaml_parse_recursion_limit = SERDE_YAML_PARSE_RECURSION_LIMIT,
        "{message}"
    );
}

fn parse_yaml_value(
    text: &str,
    surface: &'static str,
    lost_decode_surface: &'static str,
    decode_derived: bool,
) -> Option<serde_yaml::Value> {
    match serde_yaml::from_str(text) {
        Ok(value) => Some(value),
        Err(error) => {
            if let Some(value) = sanitize_helm_actions(text)
                .and_then(|sanitized| serde_yaml::from_str(&sanitized).ok())
            // LAW10: fail-closed; invalid sanitization falls through to the counted original parse gap
            {
                tracing::warn!(
                    target: "keyhog::structured",
                    surface,
                    "render-time Helm actions were replaced with inert YAML values; \
                     every literal source byte remains covered"
                );
                return Some(value);
            }
            if super::gap_is_real(decode_derived) {
                super::record_structured_gap();
            }
            report_yaml_parse_failure(&error, surface, lost_decode_surface, decode_derived, 0);
            None
        }
    }
}

fn parse_yaml_documents(
    text: &str,
    surface: &'static str,
    lost_decode_surface: &'static str,
    decode_derived: bool,
) -> Option<Vec<serde_yaml::Value>> {
    match deserialize_yaml_documents(text) {
        Ok(values) => Some(values),
        Err((error, values)) => {
            if let Some(values) = sanitize_helm_actions(text)
                .and_then(|sanitized| deserialize_yaml_documents(&sanitized).ok())
            // LAW10: fail-closed; invalid sanitization falls through to the counted original parse gap
            {
                tracing::warn!(
                    target: "keyhog::structured",
                    surface,
                    "render-time Helm actions were replaced with inert YAML values; \
                     every literal source byte remains covered"
                );
                return Some(values);
            }

            // Record the file once and surface how many documents decoded before
            // the stream stopped. libyaml cannot resynchronize after an error.
            if super::gap_is_real(decode_derived) {
                super::record_structured_gap();
            }
            report_yaml_parse_failure(
                &error,
                surface,
                lost_decode_surface,
                decode_derived,
                values.len(),
            );
            if values.is_empty() {
                None
            } else {
                Some(values)
            }
        }
    }
}

fn find_environment_pairs(
    value: &serde_yaml::Value,
    pending: &mut Vec<PendingExtractedPair>,
    depth: usize,
) {
    if depth >= super::MAX_STRUCTURED_TRAVERSAL_DEPTH {
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
        serde_yaml::Value::Mapping(map) => push_scalar_mapping_pairs(map, pending),
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

/// Push every `<key>: <scalar>` entry of a YAML mapping as a pending pair with
/// the standard `<key>: <value>` line anchor and `<key>:` fallback anchor.
/// Shared by the k8s `stringData:` block and the docker-compose `environment:`
/// mapping form, both surface raw (non-base64) scalar values identically, so
/// the extraction lives in one owner instead of two byte-identical loops.
fn push_scalar_mapping_pairs(map: &serde_yaml::Mapping, pending: &mut Vec<PendingExtractedPair>) {
    for (k, v) in map {
        let key = k.as_str().unwrap_or_default(); // LAW10: missing/non-string field => empty; value then fails downstream shape/length checks, recall-safe
        let Some(value) = yaml_scalar_value_text(v) else {
            continue;
        };
        if key.is_empty() {
            continue;
        }
        let (line_anchor, fallback_anchor) = yaml_mapping_anchors(key, &value);
        pending.push(PendingExtractedPair::owned_anchor_with_fallback(
            key,
            value,
            line_anchor,
            fallback_anchor,
        ));
    }
}
