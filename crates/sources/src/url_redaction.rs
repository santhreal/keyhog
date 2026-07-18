//! URL credential redaction for operator-visible output (error messages, log
//! lines). A URL can carry a secret in TWO places: the `user:password@`
//! userinfo component, and sensitive query parameters (presigned-URL
//! `X-Amz-Signature`/`X-Amz-Credential`, SAS `sig=`, `?access_token=`,
//! `?token=`, …). This module masks BOTH with `***` before the URL is ever
//! printed, so a fetch/DNS error never leaks the credential (engineering
//! standard: never log secrets). It is the ONE PLACE that decides what "safe to
//! log" means, every logger routes through `redact_url` rather than
//! re-implementing masking.

use std::borrow::Cow;

/// Query-parameter keys (case-insensitive) whose VALUE is a credential and must
/// be masked before a URL is logged. Presigned S3 / Azure SAS / OAuth callbacks
/// carry the whole secret here. ONE PLACE owner, extend here, never inline a
/// second list at a call site.
const SENSITIVE_QUERY_KEYS: &[&str] = &[
    "sig",
    "signature",
    "x-amz-signature",
    "x-amz-credential",
    "x-amz-security-token",
    "access_token",
    "token",
    "id_token",
    "refresh_token",
    "sas",
    "code",
    "api_key",
    "apikey",
    "secret",
    "password",
    "auth",
];

fn is_sensitive_query_key(key: &str) -> bool {
    SENSITIVE_QUERY_KEYS
        .iter()
        .any(|candidate| key.eq_ignore_ascii_case(candidate))
}

/// Mask the values of any sensitive `key=value` pairs in a query string (the
/// span between `?` and `#`, without the leading `?`). Returns `Some` with the
/// rewritten query only when at least one value was masked, so an all-benign
/// query keeps the borrowed fast path.
fn redact_query_params(query: &str) -> Option<String> {
    let mut changed = false;
    let mut out = String::with_capacity(query.len());
    for (index, pair) in query.split('&').enumerate() {
        if index > 0 {
            out.push('&');
        }
        match pair.split_once('=') {
            Some((key, _value)) if is_sensitive_query_key(key) => {
                out.push_str(key);
                out.push_str("=***");
                changed = true;
            }
            _ => out.push_str(pair),
        }
    }
    changed.then_some(out)
}

/// Redact a URL for logging: mask `user:password@` userinfo AND the values of
/// sensitive query parameters, returning `scheme://***@host…?sig=***…`.
///
/// Borrows the input unchanged when there is nothing to redact, and only
/// allocates when it actually rewrites.
///
/// ## Userinfo boundary: the LAST `@`, not the first
///
/// Per RFC 3986 / the WHATWG URL standard, the authority is
/// `[ userinfo "@" ] host [ ":" port ]`, and `host` (reg-name / IP-literal /
/// IPv4address) cannot contain `@`: so any `@` in the authority belongs to the
/// userinfo, and the userinfo/host separator is the *last* `@`. A password may
/// itself contain an (improperly unescaped) `@`, e.g. `https://u:pa@ss@host/`.
///
/// Splitting on the FIRST `@` (`find`) would treat `pa` as the whole userinfo
/// and leave `ss@host` as the "host", emitting `https://***@ss@host/`: leaking
/// `ss`, a fragment of the password, into the log. Splitting on the LAST `@`
/// (`rfind`) redacts the entire userinfo to `https://***@host/`. The `@` search
/// is confined to the authority (the span before the first `/`, `?`, or `#`), so
/// an `@` later in the path/query/fragment, e.g. `?email=a@b.com`: is never
/// treated as a userinfo separator.
pub(crate) fn redact_url(url: &str) -> Cow<'_, str> {
    let scheme_end = match url.find("://") {
        Some(idx) => idx + 3,
        None => return Cow::Borrowed(url),
    };
    let after_scheme = &url[scheme_end..];
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len()); // LAW10: reporting-only redaction boundary; no delimiter means authority is whole remainder
    let authority = &after_scheme[..authority_end];
    // LAST `@` in the authority: the RFC 3986 userinfo/host separator. `rfind`
    // (not `find`) so a literal `@` inside the password is redacted with the
    // rest of the userinfo instead of leaking the password tail (see fn docs).
    let userinfo_at = authority.rfind('@');

    // Query span lives in the remainder after the authority: `?` … up to `#`.
    let rest = &after_scheme[authority_end..];
    let redacted_query = rest.find('?').and_then(|q| {
        let after_q = &rest[q + 1..];
        let query_len = after_q.find('#').map_or(after_q.len(), |index| index);
        redact_query_params(&after_q[..query_len]).map(|masked| (q + 1, query_len, masked))
    });

    if userinfo_at.is_none() && redacted_query.is_none() {
        return Cow::Borrowed(url);
    }

    let mut out = String::with_capacity(url.len() + 8);
    out.push_str(&url[..scheme_end]);
    match userinfo_at {
        Some(at) => {
            out.push_str("***@");
            out.push_str(&authority[at + 1..]);
        }
        None => out.push_str(authority),
    }
    match redacted_query {
        Some((query_start, query_len, masked)) => {
            out.push_str(&rest[..query_start]); // path + '?'
            out.push_str(&masked);
            out.push_str(&rest[query_start + query_len..]); // '#' fragment onward
        }
        None => out.push_str(rest),
    }
    Cow::Owned(out)
}

#[cfg(test)]
#[path = "../tests/unit/url_redaction.rs"]
mod tests;
