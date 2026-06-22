use std::collections::HashMap;
use std::time::Duration;

use keyhog_core::{HttpMethod, VerificationResult};
use reqwest::Client;

use crate::ssrf::{is_private_ip_addr, is_private_url};

pub(crate) const PRIVATE_URL_ERROR: &str = "blocked: private URL";
pub(crate) const HTTPS_ONLY_ERROR: &str = "blocked: HTTPS only";

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

pub(crate) fn reject_private_resolved_addrs(
    addrs: &[std::net::SocketAddr],
    allow_private_ips: bool,
) -> std::result::Result<(), VerificationResult> {
    if !allow_private_ips && addrs.iter().any(|addr| is_private_ip_addr(&addr.ip())) {
        return Err(VerificationResult::Error(PRIVATE_URL_ERROR.into()));
    }
    Ok(())
}

pub(crate) fn ssrf_check_url_with_resolved_addrs_for_test(
    raw_url: &str,
    addrs: &[std::net::SocketAddr],
    allow_private_ips: bool,
) -> std::result::Result<(), VerificationResult> {
    let url = match reqwest::Url::parse(raw_url) {
        Ok(url) => url,
        Err(e) => return Err(VerificationResult::Error(format!("invalid URL: {}", e))),
    };
    if !allow_private_ips && is_private_url(url.as_str()) {
        return Err(VerificationResult::Error(PRIVATE_URL_ERROR.into()));
    }
    reject_private_resolved_addrs(addrs, allow_private_ips)
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
    let url = match reqwest::Url::parse(raw_url) {
        Ok(url) => url,
        Err(e) => return Err(VerificationResult::Error(format!("invalid URL: {}", e))),
    };

    // SSRF check MUST come before HTTPS-only check to prevent information leakage
    // about internal network topology via error message differentiation.
    if !allow_private_ips && is_private_url(url.as_str()) {
        return Err(VerificationResult::Error(PRIVATE_URL_ERROR.into()));
    }

    // Enforce HTTPS unconditionally in production. Plaintext loopback secret
    // transmission was a known leak vector - see audit release-2026-04-26.
    // Tests that need HTTP set `danger_allow_http=true` AND
    // `danger_allow_private_ips=true` so production paths can never opt
    // into either accidentally.
    if !allow_http && url.scheme() != "https" {
        return Err(VerificationResult::Error(HTTPS_ONLY_ERROR.into()));
    }

    // When a proxy is in use, DNS resolution is the proxy's job (the
    // verifier sends an absolute-form HTTP request or HTTP CONNECT and
    // the proxy resolves the target hostname). Pre-resolving on the
    // verifier side and pinning via `.resolve_to_addrs` would build a
    // per-request client that DROPS the proxy + insecure_tls config
    // baked into `base_client` - exactly the macro-wiring bug we'"'"'re
    // closing. Skip the pinning entirely; `base_client` already carries
    // the proxy. The DNS-rebinding mitigation that pinning provides is
    // moot through a proxy (the proxy resolves once; reqwest doesn'"'"'t
    // re-resolve).
    if proxy_in_use {
        return Ok(ResolvedTarget {
            client: base_client.clone(),
            url,
        });
    }

    // Direct connection (no proxy): resolve the host once and PIN that
    // resolution into the per-request client via `resolve_to_addrs`. The
    // DNS-rebinding fix (kimi-wave1 audit finding 4.2). Previously we
    // only validated the first lookup; reqwest then re-resolved at
    // connect time, allowing an attacker DNS server to return 1.1.1.1
    // the first time and 127.0.0.1 the second. Pinning means the TCP
    // connect uses the IP we already accepted - the second lookup never
    // happens.
    let mut pinned_addrs: Vec<std::net::SocketAddr> = Vec::new();
    let host = url.host_str().unwrap_or_default().to_string(); // LAW10: missing/non-string field => empty/placeholder; recall-safe
    let port = url.port_or_known_default().unwrap_or(443); // LAW10: no explicit port => scheme default (443); recall-irrelevant

    if !host.is_empty() {
        // Skip DNS for raw IP literals - `lookup_host` handles them, but
        // be explicit for clarity.
        let target = format!("{host}:{port}");
        let addrs: std::result::Result<Vec<std::net::SocketAddr>, std::io::Error> =
            crate::ssrf::resolve_dns_cached(target.as_str()).await;
        match addrs {
            Ok(addrs) if addrs.is_empty() => {
                return Err(VerificationResult::Error(
                    "blocked: DNS returned no addresses".into(),
                ));
            }
            Ok(addrs) => {
                reject_private_resolved_addrs(&addrs, allow_private_ips)?;
                pinned_addrs = addrs;
            }
            Err(error) => {
                // Law 10: failure => fail-closed error (blocked/refused), never proceeds; security guard
                return Err(VerificationResult::Error(format!(
                    "blocked: DNS resolution failed: {error}"
                )));
            }
        }
    }

    // Build a per-request client that pins host→addresses. `.resolve_to_addrs`
    // bypasses the system resolver for this hostname, so reqwest's internal
    // connector cannot re-resolve to a private IP between the check above
    // and the TCP connect. Keep `base_client` for code paths that don't
    // resolve a URL (e.g. AwsV4 self-constructing auth).
    let client = if !pinned_addrs.is_empty() {
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
        match Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(insecure_tls)
            // Mirror the base client's decompression-bomb posture: the DNS-pinned
            // rebuild is the client that actually serves the request on the
            // direct (no-proxy) path, so it MUST also refuse auto-inflate or the
            // 1 MB streaming cap in `read_response_body` would measure inflated
            // bytes on this path even though the base client measures wire bytes.
            // No-op today (the crate ships without the gzip/brotli/zstd/deflate
            // features) but load-bearing if a future Cargo.toml edit — or a
            // transitive dep's feature union — enables one.
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(&host, &pinned_addrs)
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                // LAW 10 — NO SILENT FALLBACK. Earlier this branch cloned the
                // unpinned `base_client` and called it "best-effort". That
                // reopened the DNS-rebinding window the pin exists to close:
                // the base client re-resolves `host` through the system
                // resolver at connect time, so an attacker DNS server that
                // returned a public IP for the pre-connect SSRF check could
                // return 127.0.0.1 / 169.254.169.254 for the actual connect.
                // The pin build failing is not a license to drop the
                // protection silently — fail CLOSED with a loud, blocked
                // result the operator can see in the finding. (KH-GAP-120.)
                return Err(VerificationResult::Error(format!(
                    "blocked: DNS pin client build failed ({e}); refusing to \
                     fall back to an unpinned client (would reopen the \
                     DNS-rebinding window). Fix: report this verifier build"
                )));
            }
        }
    } else {
        base_client.clone()
    };

    Ok(ResolvedTarget { client, url })
}

pub(crate) async fn build_request_for_step(
    client: &Client,
    method: &HttpMethod,
    auth: &keyhog_core::AuthSpec,
    url: reqwest::Url,
    credential: &str,
    companions: &HashMap<String, String>,
    timeout: Duration,
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
        allow_script_verify,
    )
    .await
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
            VerificationResult::Error("timeout".into())
        } else if e.is_redirect() {
            VerificationResult::Error("too many redirects".into())
        } else if e.is_connect() {
            VerificationResult::Error("connection failed".into())
        } else {
            VerificationResult::Error("request failed".into())
        },
        transient: e.is_timeout() || e.is_connect(),
    })
}
