//! Template interpolation helpers for verification requests.

use std::collections::HashMap;

/// Resolve a field reference to an actual value.
/// - "match" → the primary credential
/// - `companion.<name>` -> the companion credential with given name
/// - anything else → literal string
pub fn resolve_field(
    field: &str,
    credential: &str,
    companions: &HashMap<String, String>,
) -> String {
    match field {
        "match" => credential.to_string(),
        s if s.starts_with("companion.") => {
            let name = &s["companion.".len()..];
            companions.get(name).cloned().unwrap_or_default()
        }
        "" => String::new(),
        other => other.to_string(),
    }
}

/// URL-encode a value for safe interpolation into URLs.
fn url_encode(s: &str) -> String {
    percent_encoding::percent_encode(s.as_bytes(), percent_encoding::NON_ALPHANUMERIC).to_string()
}

/// Strip control characters from raw credential values before they reach
/// HTTP client builders or log sinks.
///
/// kimi-wave1 audit finding 6.LOW.interpolate.32: previously this only
/// dropped CR/LF. Other ASCII controls (NUL, DEL, BEL, ESC, …) and C1
/// controls (0x80–0x9F) can crash unhinged downstream HTTP parsers,
/// truncate log lines, or terminate strings mid-write in C-FFI sinks.
/// Real credentials never contain control bytes, so dropping them is
/// safe and removes the entire attack surface.
fn sanitize_raw_value(s: &str) -> String {
    s.chars()
        .filter(|c| {
            // Allow tab (0x09) — some legitimate JWT segments / Basic
            // auth combinations contain it. Deny every other ASCII
            // control (0x00..0x1F, 0x7F) and the C1 controls
            // (0x80..0x9F).
            let cp = *c as u32;
            !(cp < 0x20 && cp != 0x09) && cp != 0x7F && !(0x80..=0x9F).contains(&cp)
        })
        .collect()
}

/// Replace `{{match}}` and `{{companion.*}}` placeholders in a template string.
pub fn interpolate(
    template: &str,
    credential: &str,
    companions: &HashMap<String, String>,
) -> String {
    const MAX_INTERPOLATION_REPLACEMENTS: usize = 1024;

    if template == "{{match}}" {
        return sanitize_raw_value(credential);
    }
    if template.starts_with("{{companion.")
        && template.ends_with("}}")
        && template.matches("{{").count() == 1
    {
        let name = &template["{{companion.".len()..template.len() - 2];
        return sanitize_raw_value(companions.get(name).map(String::as_str).unwrap_or(""));
    }

    let mut interpolated = template.replace("{{match}}", &url_encode(credential));

    let mut search_from = 0;
    let mut replacements = 0usize;
    while replacements < MAX_INTERPOLATION_REPLACEMENTS {
        let Some(offset) = interpolated[search_from..].find("{{companion.") else {
            break;
        };
        let start = search_from + offset;
        if let Some(end_offset) = interpolated[start..].find("}}") {
            let name_start = start + "{{companion.".len();
            let name_end = start + end_offset;
            let name = &interpolated[name_start..name_end];
            let replacement = url_encode(companions.get(name).map(String::as_str).unwrap_or(""));

            let end = start + end_offset + 2;
            interpolated = format!(
                "{}{}{}",
                &interpolated[..start],
                replacement,
                &interpolated[end..]
            );
            search_from = (start + replacement.len()).min(interpolated.len());
            replacements += 1;
        } else {
            break;
        }
    }
    interpolated
}
