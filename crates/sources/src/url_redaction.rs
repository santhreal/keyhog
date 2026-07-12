//! URL credential redaction for operator-visible output (error messages, log
//! lines). A URL can carry a secret in TWO places: the `user:password@`
//! userinfo component, and sensitive query parameters (presigned-URL
//! `X-Amz-Signature`/`X-Amz-Credential`, SAS `sig=`, `?access_token=`,
//! `?token=`, …). This module masks BOTH with `***` before the URL is ever
//! printed, so a fetch/DNS error never leaks the credential (engineering
//! standard: never log secrets). It is the ONE PLACE that decides what "safe to
//! log" means — every logger routes through `redact_url` rather than
//! re-implementing masking.

use std::borrow::Cow;

/// Query-parameter keys (case-insensitive) whose VALUE is a credential and must
/// be masked before a URL is logged. Presigned S3 / Azure SAS / OAuth callbacks
/// carry the whole secret here. ONE PLACE owner — extend here, never inline a
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
/// IPv4address) cannot contain `@` — so any `@` in the authority belongs to the
/// userinfo, and the userinfo/host separator is the *last* `@`. A password may
/// itself contain an (improperly unescaped) `@`, e.g. `https://u:pa@ss@host/`.
///
/// Splitting on the FIRST `@` (`find`) would treat `pa` as the whole userinfo
/// and leave `ss@host` as the "host", emitting `https://***@ss@host/` — leaking
/// `ss`, a fragment of the password, into the log. Splitting on the LAST `@`
/// (`rfind`) redacts the entire userinfo to `https://***@host/`. The `@` search
/// is confined to the authority (the span before the first `/`, `?`, or `#`), so
/// an `@` later in the path/query/fragment — e.g. `?email=a@b.com` — is never
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
mod tests {
    use super::redact_url;
    use std::borrow::Cow;

    #[test]
    fn no_scheme_returns_input_borrowed() {
        let got = redact_url("user:pass@host/path");
        assert_eq!(got, "user:pass@host/path");
        assert!(matches!(got, Cow::Borrowed(_)));
    }

    #[test]
    fn scheme_without_userinfo_is_borrowed_unchanged() {
        let got = redact_url("https://host:5432/db");
        assert_eq!(got, "https://host:5432/db");
        assert!(matches!(got, Cow::Borrowed(_)));
    }

    #[test]
    fn basic_userinfo_is_redacted() {
        assert_eq!(redact_url("https://u:p@host/path"), "https://***@host/path");
    }

    #[test]
    fn port_and_path_survive_redaction() {
        assert_eq!(
            redact_url("postgres://user:pass@db:5432/x"),
            "postgres://***@db:5432/x"
        );
    }

    #[test]
    fn at_inside_password_uses_last_at_not_first() {
        // rfind, not find: the whole userinfo (including the literal `@`) is
        // redacted; splitting on the first `@` would leak `ss`.
        assert_eq!(redact_url("https://u:pa@ss@host/"), "https://***@host/");
    }

    #[test]
    fn at_only_in_query_is_not_treated_as_userinfo() {
        let got = redact_url("https://host/p?email=a@b.com");
        assert_eq!(got, "https://host/p?email=a@b.com");
        assert!(matches!(got, Cow::Borrowed(_)));
    }

    #[test]
    fn userinfo_without_password_is_redacted() {
        assert_eq!(redact_url("https://token@host/"), "https://***@host/");
    }

    #[test]
    fn presigned_s3_signature_and_credential_are_masked() {
        assert_eq!(
            redact_url(
                "https://bucket.s3.amazonaws.com/key?X-Amz-Algorithm=AWS4-HMAC-SHA256\
                 &X-Amz-Credential=AKIAEXAMPLE%2Fus-east-1&X-Amz-Signature=deadbeefcafe\
                 &X-Amz-Expires=900"
            ),
            "https://bucket.s3.amazonaws.com/key?X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential=***&X-Amz-Signature=***&X-Amz-Expires=900"
        );
    }

    #[test]
    fn access_token_query_is_masked() {
        assert_eq!(
            redact_url("https://host/cb?token=s3cr3tvalue&state=xyz"),
            "https://host/cb?token=***&state=xyz"
        );
    }

    #[test]
    fn azure_sas_sig_is_masked() {
        assert_eq!(
            redact_url("https://acct.blob.core.windows.net/c/b?sv=2021&sig=AbC%2Bdef&se=2030"),
            "https://acct.blob.core.windows.net/c/b?sv=2021&sig=***&se=2030"
        );
    }

    #[test]
    fn userinfo_and_query_secret_are_both_masked() {
        assert_eq!(
            redact_url("https://u:p@host/x?sig=abc"),
            "https://***@host/x?sig=***"
        );
    }

    #[test]
    fn fragment_after_masked_query_is_preserved() {
        assert_eq!(
            redact_url("https://host/x?token=abc#section"),
            "https://host/x?token=***#section"
        );
    }

    #[test]
    fn benign_query_only_stays_borrowed() {
        let got = redact_url("https://host/x?page=2&sort=name");
        assert_eq!(got, "https://host/x?page=2&sort=name");
        assert!(matches!(got, Cow::Borrowed(_)));
    }

    #[test]
    fn sensitive_key_matching_is_case_insensitive() {
        assert_eq!(
            redact_url("https://host/x?ACCESS_TOKEN=abc"),
            "https://host/x?ACCESS_TOKEN=***"
        );
    }

    #[test]
    fn valueless_sensitive_key_is_left_alone() {
        let got = redact_url("https://host/x?token");
        assert_eq!(got, "https://host/x?token");
        assert!(matches!(got, Cow::Borrowed(_)));
    }
}
