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

    // OOB callback substitutions. Unlike `{{match}}` and `{{companion.*}}` we
    // do NOT URL-encode the value: the minted host is already URL-safe (only
    // `[a-z0-9.]`), and templates routinely embed it verbatim into JSON
    // bodies, headers, and URL paths where percent-encoding would corrupt
    // the structural punctuation. A hostile detector TOML can't smuggle
    // anything novel here — every value comes from `OobSession::mint()`,
    // which is keyed off our own RSA correlation id, never user input.
    for (token, key) in [
        ("{{interactsh.url}}", "__keyhog_oob_url"),
        ("{{interactsh.host}}", "__keyhog_oob_host"),
        ("{{interactsh.id}}", "__keyhog_oob_id"),
        // bare `{{interactsh}}` aliases the bare host — the form most useful
        // inside body templates: `"{\"text\":\"https://{{interactsh}}/x\"}"`.
        ("{{interactsh}}", "__keyhog_oob_host"),
    ] {
        if interpolated.contains(token) {
            let value = companions.get(key).map(String::as_str).unwrap_or("");
            interpolated = interpolated.replace(token, value);
        }
    }

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

/// Synthetic companion-map keys used to thread an OOB minted URL through
/// the existing interpolation surface without changing every call site's
/// signature. `__keyhog_oob_*` names are reserved — detectors that try to
/// declare companions with these names will be rejected at validation.
pub const OOB_COMPANION_URL: &str = "__keyhog_oob_url";
pub const OOB_COMPANION_HOST: &str = "__keyhog_oob_host";
pub const OOB_COMPANION_ID: &str = "__keyhog_oob_id";

/// Inject the OOB minted URL into a companions map for downstream
/// interpolation. Returns an owned map; callers pass the result wherever
/// a `&HashMap<String, String>` was previously taken.
pub fn companions_with_oob(
    base: &HashMap<String, String>,
    minted_host: &str,
    minted_url: &str,
    minted_id: &str,
) -> HashMap<String, String> {
    let mut out = base.clone();
    out.insert(OOB_COMPANION_HOST.to_string(), minted_host.to_string());
    out.insert(OOB_COMPANION_URL.to_string(), minted_url.to_string());
    out.insert(OOB_COMPANION_ID.to_string(), minted_id.to_string());
    out
}

#[cfg(test)]
mod oob_tests {
    use super::*;
    use std::collections::HashMap;

    fn oob_companions() -> HashMap<String, String> {
        let base = HashMap::new();
        companions_with_oob(
            &base,
            "abc123def456ghi789jkl0mnopqrstuv1.oast.fun",
            "https://abc123def456ghi789jkl0mnopqrstuv1.oast.fun",
            "abc123def456ghi789jkl0mnopqrstuv1",
        )
    }

    #[test]
    fn interactsh_bare_substitutes_host() {
        let c = oob_companions();
        let out = interpolate("https://{{interactsh}}/x", "credential", &c);
        assert_eq!(out, "https://abc123def456ghi789jkl0mnopqrstuv1.oast.fun/x");
    }

    #[test]
    fn interactsh_url_substitutes_full_url() {
        let c = oob_companions();
        let out = interpolate("{\"callback\":\"{{interactsh.url}}\"}", "credential", &c);
        assert!(out.contains("https://abc123def456ghi789jkl0mnopqrstuv1.oast.fun"));
        assert!(!out.contains("{{interactsh"));
    }

    #[test]
    fn interactsh_id_substitutes_correlation_id_only() {
        let c = oob_companions();
        let out = interpolate("oob_id={{interactsh.id}}", "credential", &c);
        assert_eq!(out, "oob_id=abc123def456ghi789jkl0mnopqrstuv1");
    }

    #[test]
    fn interactsh_token_with_no_value_collapses_to_empty() {
        let empty = HashMap::new();
        let out = interpolate("https://{{interactsh}}/x", "credential", &empty);
        // OOB disabled → token resolves to empty string. Caller is expected
        // to skip OOB-bearing detectors when the session isn't active; this
        // is a defense-in-depth fallback so a misconfigured run doesn't ship
        // the literal `{{interactsh}}` string to a real service.
        assert_eq!(out, "https:///x");
    }

    #[test]
    fn interactsh_does_not_url_encode_host() {
        // `.` would become `%2E` if URL-encoded — that breaks DNS lookup and
        // is the whole reason `{{interactsh}}` bypasses url_encode.
        let c = oob_companions();
        let out = interpolate("host={{interactsh}}", "x", &c);
        assert!(out.contains("oast.fun"));
        assert!(!out.contains("%2E"));
    }
}
