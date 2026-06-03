use keyhog_core::SourceError;

const REDIRECT_LIMIT: usize = 5;

pub(crate) fn redact_url(url: &str) -> std::borrow::Cow<'_, str> {
    let scheme_end = match url.find("://") {
        Some(idx) => idx + 3,
        None => return std::borrow::Cow::Borrowed(url),
    };
    let after_scheme = &url[scheme_end..];
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    let Some(at_offset) = authority.find('@') else {
        return std::borrow::Cow::Borrowed(url);
    };
    let mut out = String::with_capacity(url.len());
    out.push_str(&url[..scheme_end]);
    out.push_str("***@");
    out.push_str(&after_scheme[at_offset + 1..]);
    std::borrow::Cow::Owned(out)
}

pub(crate) fn is_disallowed_web_host(url: &str) -> bool {
    let parsed = match reqwest::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return true,
    };
    let Some(host) = parsed.host() else {
        return true;
    };
    match host {
        url::Host::Ipv4(ip) => is_disallowed_ip(std::net::IpAddr::V4(ip)),
        url::Host::Ipv6(ip) => is_disallowed_ip(std::net::IpAddr::V6(ip)),
        url::Host::Domain(d) => {
            let lower = d.to_ascii_lowercase();
            lower == "localhost"
                || lower.ends_with(".local")
                || lower.ends_with(".internal")
                || lower.ends_with(".localdomain")
                || lower == "metadata.google.internal"
        }
    }
}

/// SSRF IP-classification for the WebSource fetch surface.
///
/// This delegates to the fleet-canonical classifier
/// `keyhog_verifier::ssrf::is_private_ip_addr`, which is the single
/// source of truth for "is this address one an SSRF guard must
/// refuse?". That predicate composes the fast reserved-range bitwise
/// checks (`is_private_ip_addr_fast` — loopback, RFC 1918, link-local,
/// multicast, 0.0.0.0/8, 100.64.0.0/10 CGN, 240.0.0.0/4 Class E, ...)
/// on top of `bogon::ip_addr_is_bogon` (CGN, 192.0.0.0/24 IETF
/// protocol assignment, 198.18.0.0/15 benchmark, IPv6 unique-local /
/// link-local / Teredo / ORCHIDv2 / documentation / 6to4-wrapped
/// bogons, ...) — exactly the "layer additional checks on top of
/// `ip_addr_is_bogon`, do not fork it" contract the bogon module docs
/// mandate (`crates/verifier/src/bogon.rs`).
///
/// Previously WebSource shipped a hand-rolled copy (`is_loopback ||
/// is_private || is_link_local || is_multicast || is_broadcast ||
/// is_unspecified`) that was a strict subset of the canonical and
/// silently let CGN, benchmark, IETF, Class E, and 0.0.0.0/8 (minus
/// the single 0.0.0.0) addresses through — an SSRF pivot into
/// internal/provider space. The fork is gone; both the direct
/// `resolve_and_screen` path and the redirect-revalidation path now
/// resolve to this one predicate.
pub(crate) fn is_disallowed_ip(ip: std::net::IpAddr) -> bool {
    keyhog_verifier::ssrf::is_private_ip_addr(&ip)
}

fn ssrf_revalidating_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= REDIRECT_LIMIT {
            return attempt.error(SourceError::Other(format!(
                "too many redirects (> {REDIRECT_LIMIT})"
            )));
        }
        let (target_str, host, port) = {
            let url = attempt.url();
            (
                url.as_str().to_string(),
                url.host_str().map(str::to_owned),
                url.port_or_known_default().unwrap_or(443),
            )
        };
        if is_disallowed_web_host(&target_str) {
            let redacted = redact_url(&target_str);
            return attempt.error(SourceError::Other(format!(
                "refusing to follow redirect to {redacted}: target resolves to a \
                 private / loopback / link-local / metadata-service address"
            )));
        }
        if let Some(host) = host {
            if let Err(e) = resolve_and_screen(&host, port) {
                return attempt.error(e);
            }
        }
        attempt.follow()
    })
}

pub(crate) fn build_web_client(
    cfg: &crate::http::HttpClientConfig,
    url: &str,
    proxy_in_use: bool,
) -> Result<reqwest::blocking::Client, SourceError> {
    let mut builder = crate::http::blocking_client_builder(cfg)
        .map_err(SourceError::Other)?
        .timeout(crate::timeouts::HTTP_REQUEST)
        .redirect(ssrf_revalidating_redirect_policy());

    if !proxy_in_use {
        let parsed = reqwest::Url::parse(url)
            .map_err(|e| SourceError::Other(format!("invalid URL: {e}")))?;
        if let Some(host) = parsed.host_str() {
            let port = parsed.port_or_known_default().unwrap_or(443);
            let host = host.to_string();
            let addrs = resolve_and_screen(&host, port)?;
            builder = builder.resolve_to_addrs(&host, &addrs);
        }
    }

    builder
        .build()
        .map_err(|e| SourceError::Other(format!("failed to build HTTP client: {e}")))
}

pub(crate) fn resolve_and_screen(
    host: &str,
    port: u16,
) -> Result<Vec<std::net::SocketAddr>, SourceError> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<std::net::SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| {
            SourceError::Other(format!(
                "refusing to fetch {}: DNS resolution failed: {e}",
                redact_url(host)
            ))
        })?
        .collect();
    if addrs.is_empty() {
        return Err(SourceError::Other(format!(
            "refusing to fetch {}: DNS returned no addresses",
            redact_url(host)
        )));
    }
    if addrs.iter().any(|a| is_disallowed_ip(a.ip())) {
        return Err(SourceError::Other(format!(
            "refusing to fetch {}: host resolves to a private / loopback / \
             link-local / metadata-service address - WebSource only fetches \
             public URLs",
            redact_url(host)
        )));
    }
    Ok(addrs)
}
