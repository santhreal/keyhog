use keyhog_core::SourceError;

pub(crate) fn redact_url(url: &str) -> std::borrow::Cow<'_, str> {
    crate::url_redaction::redact_url(url)
}

pub(crate) fn is_disallowed_web_host(url: &str) -> bool {
    keyhog_verifier::ssrf::is_private_url(url)
}

pub(crate) fn is_autoroute_loopback_calibration_url(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    if parsed.scheme() != "http" {
        return false;
    }
    parsed
        .host_str()
        .and_then(|host| host.parse::<std::net::IpAddr>().ok()) // LAW10: non-IP hosts fail closed as non-calibration URLs; the normal SSRF block remains active
        .is_some_and(|ip| ip.is_loopback())
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

pub(crate) fn build_web_client(
    cfg: &crate::http::HttpClientConfig,
    url: &str,
    proxy_in_use: bool,
    allow_autoroute_loopback_calibration_url: bool,
) -> Result<reqwest::blocking::Client, SourceError> {
    let mut builder = crate::http::blocking_client_builder(cfg)
        .map_err(SourceError::Other)?
        .redirect(reqwest::redirect::Policy::none());

    let parsed =
        reqwest::Url::parse(url).map_err(|e| SourceError::Other(format!("invalid URL: {e}")))?;
    if is_disallowed_web_host(url) && !allow_autoroute_loopback_calibration_url {
        let safe_url = redact_url(url);
        return Err(SourceError::Other(format!(
            "refusing to fetch {safe_url}: host resolves to a private / \
             loopback / link-local / metadata-service address - \
             WebSource only fetches public URLs"
        )));
    }

    if !proxy_in_use && !allow_autoroute_loopback_calibration_url {
        if let Some(host) = parsed.host_str() {
            let port = parsed.port_or_known_default().unwrap_or(443); // LAW10: 443 is the correct https default port, not a swallowed error
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
            super::web_unreadable_error(format!(
                "refusing to fetch {}: DNS resolution failed: {e}",
                redact_url(host)
            ))
        })?
        .collect();
    if addrs.is_empty() {
        return Err(super::web_unreadable_error(format!(
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
