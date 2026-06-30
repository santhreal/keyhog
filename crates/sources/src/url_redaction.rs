//! URL credential redaction for operator-visible output (error messages, log
//! lines). A `scheme://user:password@host/path` URL carries the secret in its
//! userinfo component; this module replaces that userinfo with `***` before the
//! URL is ever printed, so a fetch error never leaks the credential
//! (engineering standard: never log secrets).

/// Redact the `user:password@` userinfo of a URL, returning `scheme://***@host…`.
///
/// Borrows the input unchanged when there is nothing to redact (no scheme, or no
/// userinfo in the authority), and only allocates when it actually rewrites.
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
/// treated as a userinfo separator and the URL is returned unchanged.
pub(crate) fn redact_url(url: &str) -> std::borrow::Cow<'_, str> {
    let scheme_end = match url.find("://") {
        Some(idx) => idx + 3,
        None => return std::borrow::Cow::Borrowed(url),
    };
    let after_scheme = &url[scheme_end..];
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len()); // LAW10: reporting-only redaction boundary; no delimiter means authority is whole remainder
    let authority = &after_scheme[..authority_end];
    // LAST `@` in the authority: the RFC 3986 userinfo/host separator. `rfind`
    // (not `find`) so a literal `@` inside the password is redacted with the
    // rest of the userinfo instead of leaking the password tail (see fn docs).
    let Some(at_offset) = authority.rfind('@') else {
        return std::borrow::Cow::Borrowed(url);
    };
    let mut out = String::with_capacity(url.len());
    out.push_str(&url[..scheme_end]);
    out.push_str("***@");
    out.push_str(&after_scheme[at_offset + 1..]);
    std::borrow::Cow::Owned(out)
}
