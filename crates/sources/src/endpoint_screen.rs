//! Single owner of the "may this source open a connection to this endpoint
//! host?" SSRF decision shared by every operator-supplied remote endpoint.
//!
//! Two screens run in order, and both delegate the actual private/loopback/
//! link-local/cloud-metadata classification to the fleet-canonical
//! `keyhog_verifier::ssrf` predicates so the policy has exactly one definition:
//!
//! 1. the *literal host token* screen (`is_private_url`), which catches
//!    `127.0.0.1`, `10.0.0.5`, `169.254.169.254`, `[::1]`,
//!    `metadata.google.internal`, integer-encoded hosts, and (fail-closed) any
//!    URL that does not parse; and
//! 2. the *resolved address* screen (`is_private_ip_addr`), the DNS-rebinding
//!    half: a public hostname whose A/AAAA record points at a blocked address
//!    sails past screen 1.
//!
//! Callers run this only when the operator has NOT opted into private endpoints
//! (`HttpClientConfig::allow_private_endpoint`, surfaced on the CLI as
//! `--allow-private-cloud-endpoint`), so a loopback mock or an on-prem gateway
//! stays reachable behind one explicit consent flag.
//!
//! Previously the cloud object stores (S3/GCS/Azure) owned this screen locally
//! while the hosted-git API endpoints (`--gitlab-endpoint`,
//! `--bitbucket-endpoint`) had no host screen at all, so a self-hosted GitLab
//! endpoint pointed at a private or metadata address was accepted and the
//! operator's token was carried to it. Hosting the screen here removes that
//! divergence.

use keyhog_core::SourceError;
use std::net::SocketAddr;

/// A host that passed both SSRF screens, together with the exact addresses the
/// screen approved. Pinning these into the HTTP client is what makes the screen
/// binding: without the pin reqwest re-resolves at connect time and a
/// short-TTL DNS answer can serve a public address to the screen and
/// `169.254.169.254` to the connect.
pub(crate) struct ScreenedEndpoint {
    host: String,
    addrs: Vec<SocketAddr>,
}

/// Hand-written rather than derived, and deliberately lossy.
///
/// `host` is only ever the host component of an endpoint URL, so it carries no
/// userinfo, query, or fragment (the callers refuse endpoints that have any of
/// those before this type is constructed) - but a derived `Debug` would still
/// dump the full resolved address list into every `expect`/`assert` panic
/// message. The screened set is unbounded in principle, so the count is the
/// useful fact; the addresses themselves are a connection detail, not evidence.
impl std::fmt::Debug for ScreenedEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScreenedEndpoint")
            .field("host", &self.host)
            .field("screened_addrs", &self.addrs.len())
            .finish()
    }
}

/// Refuse `parsed` when its literal host, or any address it resolves to, is one
/// the canonical SSRF classifier blocks. `source` names the caller in the
/// diagnostic (`"GCS"`, `"gitlab"`, ...).
///
/// Returns the screened host/address pair for [`pin_screened_addrs`], or `None`
/// when there was nothing resolvable to pin (see [`resolve_and_screen`]).
pub(crate) fn screen_endpoint_host(
    parsed: &reqwest::Url,
    source: &str,
) -> Result<Option<ScreenedEndpoint>, SourceError> {
    if keyhog_verifier::ssrf::is_private_url(parsed.as_str()) {
        return Err(SourceError::Other(format!(
            "refusing {source} endpoint: host is a private, loopback, link-local, or cloud-metadata address (SSRF)"
        )));
    }
    resolve_and_screen(parsed, source)
}

/// Bind a screened endpoint to the client by pinning the exact approved
/// addresses, closing the re-resolution window between screen and connect.
///
/// Skipped when a proxy is configured: the proxy owns DNS then, the client never
/// resolves the endpoint host itself, and pinning would misdirect the request.
/// This mirrors `web::ssrf::build_web_client`, the same policy for WebSource.
pub(crate) fn pin_screened_addrs(
    builder: reqwest::blocking::ClientBuilder,
    screened: Option<&ScreenedEndpoint>,
    proxy_in_use: bool,
) -> reqwest::blocking::ClientBuilder {
    match screened {
        Some(screened) if !proxy_in_use => {
            builder.resolve_to_addrs(&screened.host, &screened.addrs)
        }
        _ => builder,
    }
}

/// Resolve `parsed`'s host and refuse it if ANY resolved address is blocked.
///
/// A resolution *failure* is deliberately NOT a refusal: with no resolved
/// address there is no connection target and therefore no SSRF, and reqwest
/// re-resolves and surfaces the same failure at connect time. This can only ever
/// *narrow* what is allowed - a host is refused solely when it successfully
/// resolves to a blocked address, never when it merely fails to resolve - so it
/// is not a silent security downgrade (Law 10): the check that can be performed
/// (screen a resolved address) always runs, and the only "skipped" case is one
/// where there is nothing to screen and nothing to connect to.
fn resolve_and_screen(
    parsed: &reqwest::Url,
    source: &str,
) -> Result<Option<ScreenedEndpoint>, SourceError> {
    use std::net::ToSocketAddrs;

    let Some(host) = parsed.host_str() else {
        // Shape (`host_str().is_none()`) is already rejected by every caller;
        // this arm has nothing to screen.
        return Ok(None);
    };
    // `port_or_known_default` yields 80/443 for http/https (both already the
    // only permitted schemes), so this never falls back to a wrong port.
    let port = parsed.port_or_known_default().map_or(443, |port| port);
    let Ok(resolved) = (host, port).to_socket_addrs() else {
        // Resolution failed: no address to attack. reqwest will re-resolve and
        // surface the same failure at connect time (never an SSRF pivot).
        return Ok(None);
    };
    let mut addrs = Vec::new();
    for addr in resolved {
        if keyhog_verifier::ssrf::is_private_ip_addr(&addr.ip()) {
            return Err(SourceError::Other(format!(
                "refusing {source} endpoint: host {host} resolves to {} which is a private, loopback, link-local, or cloud-metadata address (SSRF / DNS rebinding)",
                addr.ip()
            )));
        }
        addrs.push(addr);
    }
    if addrs.is_empty() {
        return Ok(None);
    }
    Ok(Some(ScreenedEndpoint {
        host: host.to_string(),
        addrs,
    }))
}
