use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use keyhog_core::{HeaderSpec, HttpMethod, VerificationResult};
use reqwest::Client;

use crate::interpolate::{interpolate_http_value, missing_companion_refs};
use crate::ssrf::{is_private_ip_addr, is_private_url};

// ── refusal family ────────────────────────────────────────────────────────────
// Security/policy refusals: deliberately terse and uniformly `blocked:`-prefixed.
// They are NOT actionable in the operator sense (the credential's host is unsafe
// to contact), so they do not carry a `Fix:` — the refusal IS the correct outcome.
pub const PRIVATE_URL_ERROR: &str = "blocked: private URL";
pub const HTTPS_ONLY_ERROR: &str = "blocked: HTTPS only";
/// The host resolved to zero usable addresses; fail closed rather than proceed.
pub const DNS_NO_ADDRESSES_ERROR: &str = "blocked: DNS returned no addresses";

/// The verification target URL failed to parse. Leads with the legacy
/// `invalid URL:` phrase (Law 3) and preserves the underlying parse error, then
/// points at the most likely cause: the malformed URL is almost always the
/// detector's `[detector.verify] url` (or a credential-interpolated host), not
/// the scanned credential. This is an ACTIONABLE error (carries a `Fix:`), unlike
/// the `blocked:` refusals above.
pub fn invalid_url_error(parse_error: impl std::fmt::Display) -> String {
    format!(
        "invalid URL: {parse_error}. Fix: the verification target URL is malformed — check the \
         detector's `[detector.verify] url` (and any credential-interpolated host) in its TOML"
    )
}

// Operator-facing verification reasons for transport failures. Every message
// leads with the legacy short phrase (`timeout`, `connection failed`,
// `too many redirects`, `request failed`) so downstream substring checks keep
// matching, then states the concrete fix the operator can act on. These are the
// most user-visible verifier errors (they surface as a finding's verification
// status), so they carry context + remedy rather than a bare token.
/// The verification request exceeded its deadline before the endpoint responded.
pub const TIMEOUT_ERROR: &str = "timeout: the endpoint did not respond within the \
     verification deadline. Fix: raise the verification timeout with --timeout, or \
     check network egress / proxy reachability to the credential's host";
/// The TCP/TLS connection to the endpoint could not be opened.
pub const CONNECTION_FAILED_ERROR: &str = "connection failed: could not open a \
     connection to the endpoint. Fix: check DNS resolution, firewall/egress rules, \
     and proxy settings for the credential's host";
/// The endpoint tried to redirect, but redirects are disabled (Policy::none) to
/// keep the pre-connect SSRF screen sound — a redirect target is re-resolved and
/// would bypass the pin, so it is refused rather than followed.
pub const REDIRECT_LIMIT_ERROR: &str = "too many redirects: the endpoint issued a \
     redirect, but redirects are disabled for SSRF safety. Fix: set the detector's \
     verification URL to the canonical API host so it answers directly without \
     redirecting";
/// The request failed before any response arrived (TLS handshake, body write, or
/// another transport error that is not a timeout, connect, or redirect failure).
pub const REQUEST_FAILED_ERROR: &str = "request failed: the HTTP request errored \
     before any response was received. Fix: check the endpoint URL, TLS \
     configuration, and proxy settings for the credential's host";
const PINNED_CLIENT_CACHE_TTL: Duration = Duration::from_secs(60);
const PINNED_CLIENT_CACHE_MAX_ENTRIES: usize = 4096;

pub(crate) struct ResolvedTarget {
    pub client: Client,
    pub url: reqwest::Url,
}

pub(crate) enum RequestBuildResult {
    Ready(reqwest::RequestBuilder),
    Final {
        result: VerificationResult,
        metadata: HashMap<String, String>,
        transient: bool,
    },
}

pub(crate) struct RequestError {
    pub result: VerificationResult,
    pub transient: bool,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PinnedClientKey {
    host: String,
    addrs: Vec<SocketAddr>,
    timeout: Duration,
    insecure_tls: bool,
}

struct CachedPinnedClient {
    inserted_at: Instant,
    client: Client,
}

static PINNED_CLIENT_CACHE: OnceLock<DashMap<PinnedClientKey, CachedPinnedClient>> =
    OnceLock::new();

pub(crate) fn reject_private_resolved_addrs(
    addrs: &[std::net::SocketAddr],
    allow_private_ips: bool,
) -> std::result::Result<(), VerificationResult> {
    if !allow_private_ips && addrs.iter().any(|addr| is_private_ip_addr(&addr.ip())) {
        return Err(VerificationResult::Error(PRIVATE_URL_ERROR.into()));
    }
    Ok(())
}

fn screen_target_url_and_addrs(
    url: &reqwest::Url,
    addrs: &[std::net::SocketAddr],
    allow_private_ips: bool,
) -> std::result::Result<(), VerificationResult> {
    if !allow_private_ips && is_private_url(url.as_str()) {
        return Err(VerificationResult::Error(PRIVATE_URL_ERROR.into()));
    }
    reject_private_resolved_addrs(addrs, allow_private_ips)
}

pub(crate) fn ssrf_check_url_with_resolved_addrs_for_test(
    raw_url: &str,
    addrs: &[std::net::SocketAddr],
    allow_private_ips: bool,
) -> std::result::Result<(), VerificationResult> {
    let url = match reqwest::Url::parse(raw_url) {
        Ok(url) => url,
        Err(e) => return Err(VerificationResult::Error(invalid_url_error(e))),
    };
    screen_target_url_and_addrs(&url, addrs, allow_private_ips)
}

pub(crate) async fn resolved_client_for_url(
    base_client: &Client,
    raw_url: &str,
    timeout: Duration,
    allow_private_ips: bool,
    allow_http: bool,
    proxy_in_use: bool,
    insecure_tls: bool,
) -> std::result::Result<ResolvedTarget, VerificationResult> {
    let url = parse_target_url(raw_url)?;
    enforce_target_url_policy(&url, allow_private_ips, allow_http)?;

    // When a proxy is in use, keep the proxy-bearing base client, but still
    // resolve and screen the target locally before handing it to the proxy.
    // Without this preflight, single-label/custom internal domains and public
    // hostnames resolving to private IPs bypass the post-resolution SSRF veto
    // because the proxy owns DNS.
    if proxy_in_use {
        if !allow_private_ips {
            let host = target_host(&url);
            let _screened_addrs =
                resolve_direct_target_addrs(&url, &host, allow_private_ips).await?;
        }
        return Ok(proxied_target(base_client, url));
    }

    // Direct connection (no proxy): resolve the host once and PIN that
    // resolution into the per-request client via `resolve_to_addrs`. The
    // DNS-rebinding fix (kimi-wave1 audit finding 4.2). Previously we
    // only validated the first lookup; reqwest then re-resolved at
    // connect time, allowing an attacker DNS server to return 1.1.1.1
    // the first time and 127.0.0.1 the second. Pinning means the TCP
    // connect uses the IP we already accepted - the second lookup never
    // happens.
    let host = target_host(&url);
    let pinned_addrs = resolve_direct_target_addrs(&url, &host, allow_private_ips).await?;
    let client = direct_target_client(base_client, &host, &pinned_addrs, timeout, insecure_tls)?;

    Ok(ResolvedTarget { client, url })
}

fn parse_target_url(raw_url: &str) -> std::result::Result<reqwest::Url, VerificationResult> {
    reqwest::Url::parse(raw_url).map_err(|e| VerificationResult::Error(invalid_url_error(e)))
}

fn enforce_target_url_policy(
    url: &reqwest::Url,
    allow_private_ips: bool,
    allow_http: bool,
) -> std::result::Result<(), VerificationResult> {
    // SSRF check MUST come before HTTPS-only check to prevent information leakage
    // about internal network topology via error message differentiation.
    screen_target_url_and_addrs(url, &[], allow_private_ips)?;

    // Enforce HTTPS unconditionally in production. Plaintext loopback secret
    // transmission was a known leak vector - see audit release-2026-04-26.
    // Tests that need HTTP set `danger_allow_http=true` AND
    // `danger_allow_private_ips=true` so production paths can never opt
    // into either accidentally.
    if !allow_http && url.scheme() != "https" {
        return Err(VerificationResult::Error(HTTPS_ONLY_ERROR.into()));
    }

    Ok(())
}

fn proxied_target(base_client: &Client, url: reqwest::Url) -> ResolvedTarget {
    ResolvedTarget {
        client: base_client.clone(),
        url,
    }
}

fn target_host(url: &reqwest::Url) -> String {
    url.host_str().unwrap_or_default().to_string() // LAW10: missing/non-string field => empty/placeholder; recall-safe
}

async fn resolve_direct_target_addrs(
    url: &reqwest::Url,
    host: &str,
    allow_private_ips: bool,
) -> std::result::Result<Vec<SocketAddr>, VerificationResult> {
    if host.is_empty() {
        return Ok(Vec::new());
    }

    let port = url.port_or_known_default().unwrap_or(443); // LAW10: no explicit port => scheme default (443); recall-irrelevant
    let target = format!("{host}:{port}");
    match crate::ssrf::resolve_dns_cached(target.as_str()).await {
        Ok(addrs) if addrs.is_empty() => {
            Err(VerificationResult::Error(DNS_NO_ADDRESSES_ERROR.into()))
        }
        Ok(addrs) => {
            screen_target_url_and_addrs(url, &addrs, allow_private_ips)?;
            Ok(addrs)
        }
        Err(error) => {
            // Law 10: failure => fail-closed error (blocked/refused), never proceeds; security guard
            Err(VerificationResult::Error(format!(
                "blocked: DNS resolution failed: {error}"
            )))
        }
    }
}

fn direct_target_client(
    base_client: &Client,
    host: &str,
    pinned_addrs: &[SocketAddr],
    timeout: Duration,
    insecure_tls: bool,
) -> std::result::Result<Client, VerificationResult> {
    // Build or reuse a cached client that pins host->addresses. `.resolve_to_addrs`
    // bypasses the system resolver for this hostname, so reqwest's internal
    // connector cannot re-resolve to a private IP between the check above
    // and the TCP connect. Keep `base_client` for code paths that don't
    // resolve a URL (e.g. AwsV4 self-constructing auth).
    if pinned_addrs.is_empty() {
        return Ok(base_client.clone());
    }

    // The DNS-pinning rebuild MUST replicate the security-critical
    // config baked into `base_client`. Reqwest's default ClientBuilder
    // would otherwise:
    //   - follow redirects (Policy::limited(10)) - the base client sets
    //     Policy::none() to stop a public host from issuing a 302 to a
    //     private IP that bypasses the pre-connect SSRF check (the pin
    //     only covers the ORIGINAL host; the redirect target is
    //     re-resolved via the system resolver).
    //   - validate certs strictly - the base client honors
    //     `--insecure` (`config.insecure_tls`); dropping that here
    //     means the flag silently doesn't apply on the path that
    //     actually serves the request when no proxy is in use.
    // Both gaps were live until 2026-05-26.
    pinned_client_for(host, pinned_addrs, timeout, insecure_tls)
}

fn pinned_client_for(
    host: &str,
    pinned_addrs: &[SocketAddr],
    timeout: Duration,
    insecure_tls: bool,
) -> std::result::Result<Client, VerificationResult> {
    let key = PinnedClientKey {
        host: host.to_string(),
        addrs: pinned_addrs.to_vec(),
        timeout,
        insecure_tls,
    };
    let cache = PINNED_CLIENT_CACHE.get_or_init(DashMap::new);
    if let Some(entry) = cache.get(&key) {
        if entry.inserted_at.elapsed() < PINNED_CLIENT_CACHE_TTL {
            return Ok(entry.client.clone());
        }
        drop(entry);
        cache.remove(&key);
    }
    if cache.len() >= PINNED_CLIENT_CACHE_MAX_ENTRIES {
        cache.clear();
    }
    let client = build_pinned_client(host, pinned_addrs, timeout, insecure_tls)?;
    cache.insert(
        key,
        CachedPinnedClient {
            inserted_at: Instant::now(),
            client: client.clone(),
        },
    );
    Ok(client)
}

pub(crate) fn clear_pinned_client_cache_for_test() {
    if let Some(cache) = PINNED_CLIENT_CACHE.get() {
        cache.clear();
    }
}

pub(crate) fn pinned_client_cache_len_for_test() -> usize {
    PINNED_CLIENT_CACHE.get().map_or(0, DashMap::len)
}

pub(crate) fn pinned_client_cache_len_for_host_for_test(host: &str) -> usize {
    PINNED_CLIENT_CACHE.get().map_or(0, |cache| {
        cache
            .iter()
            .filter(|entry| entry.key().host == host)
            .count()
    })
}

pub(crate) fn pinned_client_for_test(
    host: &str,
    pinned_addrs: &[SocketAddr],
    timeout: Duration,
    insecure_tls: bool,
) -> std::result::Result<(), VerificationResult> {
    pinned_client_for(host, pinned_addrs, timeout, insecure_tls).map(|_| ())
}

fn build_pinned_client(
    host: &str,
    pinned_addrs: &[SocketAddr],
    timeout: Duration,
    insecure_tls: bool,
) -> std::result::Result<Client, VerificationResult> {
    // The DNS-pinning rebuild MUST replicate the security-critical config baked
    // into `base_client`; a build failure is a blocked verifier state, never a
    // license to use an unpinned client.
    Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(insecure_tls)
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_zstd()
        .no_deflate()
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, pinned_addrs)
        .build()
        .map_err(|e| {
            VerificationResult::Error(format!(
                "blocked: DNS pin client build failed ({e}); refusing to \
                 fall back to an unpinned client (would reopen the \
                 DNS-rebinding window). Fix: report this verifier build"
            ))
        })
}

pub(crate) async fn build_request_for_step(
    client: &Client,
    method: &HttpMethod,
    auth: &keyhog_core::AuthSpec,
    url: reqwest::Url,
    credential: &str,
    companions: &HashMap<String, String>,
    timeout: Duration,
    allow_private_ips: bool,
    allow_http: bool,
    proxy_in_use: bool,
    insecure_tls: bool,
    allow_script_verify: bool,
) -> RequestBuildResult {
    let request = request_for_method(client, method, url).timeout(timeout);
    crate::verify::auth::build_request_for_auth(
        request,
        auth,
        credential,
        companions,
        timeout,
        client,
        allow_private_ips,
        allow_http,
        proxy_in_use,
        insecure_tls,
        allow_script_verify,
    )
    .await
}

pub(crate) fn apply_header_body_templates(
    mut request: reqwest::RequestBuilder,
    headers: &[HeaderSpec],
    body_template: Option<&str>,
    credential: &str,
    companions: &HashMap<String, String>,
) -> reqwest::RequestBuilder {
    for header in headers {
        let value = interpolate_http_value(&header.value, credential, companions);
        request = request.header(&header.name, &value);
    }

    if let Some(body_template) = body_template {
        let body = interpolate_http_value(body_template, credential, companions);
        request = request.body(body);
    }

    request
}

pub(crate) fn missing_companion_error(context: &str, missing: &[String]) -> VerificationResult {
    VerificationResult::Error(format!(
        "failed to resolve verification companion(s) in {context}: {}. Fix: configure detector companions that populate every companion.<name> reference before verification",
        missing.join(", ")
    ))
}

pub(crate) fn validate_template_companions(
    context: &str,
    template: &str,
    companions: &HashMap<String, String>,
) -> Result<(), VerificationResult> {
    let missing = missing_companion_refs(template, companions);
    if missing.is_empty() {
        Ok(())
    } else {
        Err(missing_companion_error(context, &missing))
    }
}

pub(crate) fn validate_header_body_templates(
    headers: &[HeaderSpec],
    body_template: Option<&str>,
    companions: &HashMap<String, String>,
) -> Result<(), VerificationResult> {
    for header in headers {
        validate_template_companions("verification header", &header.value, companions)?;
    }
    if let Some(body_template) = body_template {
        validate_template_companions("verification body", body_template, companions)?;
    }
    Ok(())
}

fn request_for_method(
    client: &Client,
    method: &HttpMethod,
    url: reqwest::Url,
) -> reqwest::RequestBuilder {
    match method {
        HttpMethod::Get => client.get(url),
        HttpMethod::Post => client.post(url),
        HttpMethod::Put => client.put(url),
        HttpMethod::Delete => client.delete(url),
        HttpMethod::Patch => client.patch(url),
        HttpMethod::Head => client.head(url),
    }
}

pub(crate) async fn execute_request(
    request: reqwest::RequestBuilder,
) -> std::result::Result<reqwest::Response, RequestError> {
    request.send().await.map_err(|e| RequestError {
        result: if e.is_timeout() {
            VerificationResult::Error(TIMEOUT_ERROR.into())
        } else if e.is_redirect() {
            VerificationResult::Error(REDIRECT_LIMIT_ERROR.into())
        } else if e.is_connect() {
            VerificationResult::Error(CONNECTION_FAILED_ERROR.into())
        } else {
            VerificationResult::Error(REQUEST_FAILED_ERROR.into())
        },
        transient: e.is_timeout() || e.is_connect(),
    })
}
