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

/// Reduce an OOB collector value to the DNS-hostname charset the no-encode
/// substitution path assumes (`[a-z0-9.-]`), uppercasing folded to lower.
///
/// disc audit (security.LOW.interpolate): the `{{interactsh*}}` tokens are
/// interpolated into URL / header / body templates WITHOUT URL-encoding, on
/// the stated invariant that the minted value is always `[a-z0-9.]` from
/// `OobSession::mint()`. But the host is `format!("{unique_id}.{server_host}")`
/// where `server_host` comes from the operator-supplied `--oob-server`, which
/// `normalize_server()` only trims of scheme/trailing-slash and never
/// validates for charset. A collector host carrying structural characters
/// (`/ ? # @ : " ' < > \` space, control bytes) would otherwise be injected
/// verbatim into request structure. We enforce the invariant the comment
/// relies on at the substitution boundary: any byte outside the DNS-hostname
/// charset is dropped, so a hostile `--oob-server` can never smuggle
/// structural punctuation into a URL, header, or body. ASCII uppercase is
/// folded to lowercase (DNS is case-insensitive); everything else outside the
/// allowed set is removed. This is belt-and-suspenders alongside any host
/// validation in `normalize_server()` and is correct even if that validation
/// is absent or weakened.
fn sanitize_oob_value(s: &str) -> String {
    s.chars()
        .filter_map(|c| {
            let lc = c.to_ascii_lowercase();
            if lc.is_ascii_lowercase() || c.is_ascii_digit() || lc == '.' || lc == '-' {
                Some(lc)
            } else {
                None
            }
        })
        .collect()
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
pub(crate) fn sanitize_raw_value(s: &str) -> String {
    s.chars()
        .filter(|c| {
            // Allow tab (0x09) - some legitimate JWT segments / Basic
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
    // the structural punctuation. The host is `<unique_id>.<server_host>` and
    // `server_host` derives from the operator-supplied `--oob-server`, which
    // `normalize_server()` does not validate for charset - so we enforce the
    // `[a-z0-9.]` invariant the no-encode path relies on right here, at the
    // substitution boundary, via `sanitize_oob_value()`. Any structural
    // punctuation or control byte that slipped through registration is
    // dropped before it can reach a URL, header, or body. The `id` token can
    // legitimately carry only `[a-z0-9]` (correlation id + alphanumeric
    // suffix from `mint_url`), so the same hostname charset is a safe
    // superset for it.
    for (token, key) in [
        ("{{interactsh.url}}", "__keyhog_oob_url"),
        ("{{interactsh.host}}", "__keyhog_oob_host"),
        ("{{interactsh.id}}", "__keyhog_oob_id"),
        // bare `{{interactsh}}` aliases the bare host - the form most useful
        // inside body templates: `"{\"text\":\"https://{{interactsh}}/x\"}"`.
        ("{{interactsh}}", "__keyhog_oob_host"),
    ] {
        if interpolated.contains(token) {
            let raw = companions.get(key).map(String::as_str).unwrap_or("");
            // The url variant carries a leading scheme (`https://`) that the
            // hostname charset would strip; sanitize only the host portion
            // and re-prepend the (fixed, trusted) scheme so the value stays a
            // well-formed URL while the operator-influenced host is cleaned.
            let value = match raw.split_once("://") {
                Some((scheme, host)) if scheme.chars().all(|c| c.is_ascii_alphabetic()) => {
                    format!("{scheme}://{}", sanitize_oob_value(host))
                }
                _ => sanitize_oob_value(raw),
            };
            interpolated = interpolated.replace(token, &value);
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
/// signature. `__keyhog_oob_*` names are reserved - detectors that try to
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
mod tests {
    use super::*;

    // disc audit (security.LOW.interpolate): a hostile `--oob-server` whose
    // host carries structural punctuation must not be injected verbatim into
    // a body/header/URL template. The substitution boundary enforces the
    // `[a-z0-9.-]` invariant the no-encode comment relies on.
    #[test]
    fn oob_host_structural_chars_stripped() {
        // Operator-supplied collector host carrying a path-break, query, and
        // quote that would otherwise escape the JSON string / URL structure.
        let hostile_host = "abc123.evil.com/x?q=1\"";
        let comps = companions_with_oob(
            &HashMap::new(),
            hostile_host,
            &format!("https://{hostile_host}"),
            "abc123",
        );

        let body = interpolate("{\"u\":\"https://{{interactsh}}/cb\"}", "cred", &comps);
        // No structural byte from the hostile host survives into the output.
        assert!(!body.contains('?'), "query separator leaked: {body}");
        assert!(!body.contains("?q=1"), "query string leaked: {body}");
        // Exactly the template's own 4 quotes remain; none injected by the host.
        assert_eq!(
            body.matches('"').count(),
            4,
            "stray quote leaked into JSON: {body}"
        );
        // The slash present in the output is only the template's own `/cb`,
        // never the injected `/x`.
        assert!(!body.contains("/x"), "injected path leaked: {body}");
        assert!(
            body.contains("abc123.evil.com"),
            "legit host bytes dropped: {body}"
        );

        let url = interpolate("{{interactsh.url}}/cb", "cred", &comps);
        // Scheme is preserved, host is sanitized, injected query/path gone.
        assert!(
            url.starts_with("https://abc123.evil.com/cb"),
            "url malformed: {url}"
        );
        assert!(!url.contains("?q=1"), "query leaked into url: {url}");
    }

    // Positive twin: a well-formed collector host and id pass through the
    // no-encode path unchanged (sanitization is identity on legal input).
    #[test]
    fn oob_legit_host_passes_through() {
        let comps = companions_with_oob(
            &HashMap::new(),
            "deadbeefcafe0.oast.fun",
            "https://deadbeefcafe0.oast.fun",
            "deadbeefcafe0",
        );
        assert_eq!(
            interpolate("h={{interactsh.host}}", "cred", &comps),
            "h=deadbeefcafe0.oast.fun"
        );
        assert_eq!(
            interpolate("u={{interactsh.url}}", "cred", &comps),
            "u=https://deadbeefcafe0.oast.fun"
        );
        assert_eq!(
            interpolate("id={{interactsh.id}}", "cred", &comps),
            "id=deadbeefcafe0"
        );
        assert_eq!(
            interpolate("https://{{interactsh}}/p", "cred", &comps),
            "https://deadbeefcafe0.oast.fun/p"
        );
    }

    #[test]
    fn sanitize_oob_value_charset() {
        // Folds case, keeps `[a-z0-9.-]`, drops everything else.
        assert_eq!(sanitize_oob_value("AbC-1.2_x/y@z "), "abc-1.2xyz");
        assert_eq!(
            sanitize_oob_value("good.host-1.oast.fun"),
            "good.host-1.oast.fun"
        );
        assert_eq!(sanitize_oob_value("\u{0}\u{7f}<>'\""), "");
    }
}
