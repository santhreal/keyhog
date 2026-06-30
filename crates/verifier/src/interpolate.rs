//! Template interpolation helpers for verification requests.

use std::collections::HashMap;

/// Resolve a field reference to an actual value.
/// - "match" → the primary credential
/// - `companion.<name>` -> the companion credential with given name
/// - anything else → literal string
pub(crate) fn resolve_field(
    field: &str,
    credential: &str,
    companions: &HashMap<String, String>,
) -> String {
    match field {
        "match" => credential.to_string(),
        s if s.starts_with("companion.") => {
            let name = &s["companion.".len()..];
            companions.get(name).cloned().unwrap_or_default() // LAW10: missing/non-string field => empty/placeholder; recall-safe
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
///
/// Exposed via `testing::sanitize_oob_value` for the charset unit test migrated
/// out of this module (KH-GAP-004).
pub(crate) fn sanitize_oob_value(s: &str) -> String {
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
///
/// Exposed via `testing::sanitize_raw_value` for the control-byte integration
/// tests migrated out of this module.
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
pub(crate) fn interpolate(
    template: &str,
    credential: &str,
    companions: &HashMap<String, String>,
) -> String {
    interpolate_url(template, credential, companions)
}

/// Interpolate a URL template. Embedded match/companion values are
/// percent-encoded because they occupy URL component positions.
pub(crate) fn interpolate_url(
    template: &str,
    credential: &str,
    companions: &HashMap<String, String>,
) -> String {
    interpolate_with_context(template, credential, companions, InterpolationContext::Url)
}

/// Interpolate an HTTP header or body template. Embedded match/companion values
/// are control-stripped but not percent-encoded; callers that need JSON or form
/// escaping must express that in the detector template itself.
pub(crate) fn interpolate_http_value(
    template: &str,
    credential: &str,
    companions: &HashMap<String, String>,
) -> String {
    interpolate_with_context(
        template,
        credential,
        companions,
        InterpolationContext::HttpValue,
    )
}

pub(crate) fn missing_companion_field(
    field: &str,
    companions: &HashMap<String, String>,
) -> Option<String> {
    field
        .strip_prefix("companion.")
        .filter(|name| !companions.contains_key(*name))
        .map(str::to_string)
}

pub(crate) fn missing_companion_refs(
    template: &str,
    companions: &HashMap<String, String>,
) -> Vec<String> {
    const MAX_COMPANION_REF_SCAN: usize = 1024;

    let mut missing = Vec::new();
    let mut search_from = 0usize;
    let mut scanned = 0usize;
    while scanned < MAX_COMPANION_REF_SCAN {
        let Some(offset) = template[search_from..].find("{{companion.") else {
            break;
        };
        let start = search_from + offset;
        let Some(end_offset) = template[start..].find("}}") else {
            break;
        };
        let name_start = start + "{{companion.".len();
        let name_end = start + end_offset;
        let name = &template[name_start..name_end];
        if !companions.contains_key(name) && !missing.iter().any(|m| m == name) {
            missing.push(name.to_string());
        }
        search_from = start + end_offset + 2;
        scanned += 1;
    }
    missing
}

#[derive(Copy, Clone)]
enum InterpolationContext {
    Url,
    HttpValue,
}

fn interpolate_placeholder_value(value: &str, context: InterpolationContext) -> String {
    match context {
        InterpolationContext::Url => url_encode(value),
        InterpolationContext::HttpValue => sanitize_raw_value(value),
    }
}

/// Resolve the OOB collector URL companion, preserving a leading `scheme://`
/// (which the DNS-hostname charset would otherwise strip) while reducing the
/// operator-influenced host to `[a-z0-9.-]`. A value with no `scheme://` is
/// sanitized whole. The scheme is accepted only when it is purely alphabetic,
/// so no structural punctuation can masquerade as one.
fn resolve_oob_url(companions: &HashMap<String, String>) -> String {
    let raw = companions
        .get(OOB_COMPANION_URL)
        .map(String::as_str)
        .unwrap_or(""); // LAW10: missing field => empty placeholder; recall-safe
    match raw.split_once("://") {
        Some((scheme, host)) if scheme.chars().all(|c| c.is_ascii_alphabetic()) => {
            format!("{scheme}://{}", sanitize_oob_value(host))
        }
        _ => sanitize_oob_value(raw),
    }
}

/// Resolve a single `{{…}}` placeholder body to its substituted value, or
/// `None` when the token is unrecognized (the caller then emits it verbatim).
///
/// Every returned value is already neutralized for its position:
///   - `match` / `companion.*` → percent-encoded (URL context) or
///     control-stripped (header/body context) via [`interpolate_placeholder_value`].
///   - `interactsh.url` → host reduced to the DNS charset, scheme preserved.
///   - `interactsh.host` / bare `interactsh` / `interactsh.id` → reduced to the
///     DNS-hostname charset `[a-z0-9.-]`. A host or id never carries a scheme,
///     so — unlike the url token — no `scheme://` survives here.
fn resolve_placeholder(
    inner: &str,
    credential: &str,
    companions: &HashMap<String, String>,
    context: InterpolationContext,
) -> Option<String> {
    let oob = |key| {
        sanitize_oob_value(companions.get(key).map(String::as_str).unwrap_or(""))
        // LAW10: missing field => empty placeholder; recall-safe
    };
    match inner {
        "match" => Some(interpolate_placeholder_value(credential, context)),
        "interactsh.url" => Some(resolve_oob_url(companions)),
        "interactsh.host" | "interactsh" => Some(oob(OOB_COMPANION_HOST)),
        "interactsh.id" => Some(oob(OOB_COMPANION_ID)),
        _ => inner.strip_prefix("companion.").map(|name| {
            let raw = companions.get(name).map(String::as_str).unwrap_or(""); // LAW10: missing companion => empty placeholder; recall-safe
            interpolate_placeholder_value(raw, context)
        }),
    }
}

fn interpolate_with_context(
    template: &str,
    credential: &str,
    companions: &HashMap<String, String>,
    context: InterpolationContext,
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
        let raw = match companions.get(name) {
            Some(value) => value.as_str(),
            None => "",
        };
        return sanitize_raw_value(raw);
    }

    // Single left-to-right pass over the TEMPLATE. Each `{{…}}` token is
    // resolved to its (already position-sanitized) value and appended to `out`;
    // literal text between tokens is copied verbatim. The scan never re-reads an
    // emitted value, so a substituted credential or companion — both untrusted,
    // scanned content — can never introduce a `{{…}}` token that a later phase
    // would expand.
    //
    // This is the security property the prior three-phase replace (match → OOB →
    // companion) lacked: the header/body path control-strips values but does not
    // percent-encode them, so a `{{match}}` whose scanned value was literally
    // `{{companion.other}}` survived with its braces intact and the following
    // companion phase expanded it — leaking a *different* companion secret into
    // the outbound request. One pass with inert substitutions closes that
    // entirely, for every token kind, in both contexts.
    //
    // OOB tokens are intentionally NOT percent-encoded (the minted host is
    // already `[a-z0-9.-]` and templates embed it verbatim into JSON/headers/
    // URLs); `resolve_placeholder` enforces that charset at this boundary so a
    // hostile `--oob-server` cannot smuggle structural punctuation through.
    // Unrecognized tokens are emitted verbatim, exactly as the phased replace
    // left them.
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    let mut replacements = 0usize;
    while replacements < MAX_INTERPOLATION_REPLACEMENTS {
        let Some(open) = rest.find("{{") else { break };
        let after_open = &rest[open + 2..];
        let Some(close_rel) = after_open.find("}}") else {
            break;
        };
        let inner = &after_open[..close_rel];
        out.push_str(&rest[..open]);
        match resolve_placeholder(inner, credential, companions, context) {
            Some(value) => out.push_str(&value),
            None => {
                // Unrecognized placeholder: preserve it verbatim.
                out.push_str("{{");
                out.push_str(inner);
                out.push_str("}}");
            }
        }
        rest = &after_open[close_rel + 2..];
        replacements += 1;
    }
    // Tail after the last resolved token (or the whole remainder once the scan
    // breaks on no-more-tokens / an unterminated `{{` / the replacement cap).
    out.push_str(rest);
    out
}

/// Synthetic companion-map keys used to thread an OOB minted URL through
/// the existing interpolation surface without changing every call site's
/// signature. `__keyhog_oob_*` names are reserved - detectors that try to
/// declare companions with these names will be rejected at validation.
pub(crate) const OOB_COMPANION_URL: &str = "__keyhog_oob_url";
pub(crate) const OOB_COMPANION_HOST: &str = "__keyhog_oob_host";
pub(crate) const OOB_COMPANION_ID: &str = "__keyhog_oob_id";

/// Inject the OOB minted URL into a companions map for downstream
/// interpolation. Returns an owned map; callers pass the result wherever
/// a `&HashMap<String, String>` was previously taken.
pub(crate) fn companions_with_oob(
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
