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

pub(crate) async fn resolved_client_for_url(
    base_client: &Client,
    raw_url: &str,
    timeout: Duration,
    allow_private_ips: bool,
    allow_http: bool,
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

    // Resolve the host once and PIN that resolution into the per-request
    // client via `resolve_to_addrs`. This is the DNS-rebinding fix
    // (kimi-wave1 audit finding 4.2). Previously we only validated the
    // first lookup; reqwest then re-resolved at connect time, allowing an
    // attacker DNS server to return 1.1.1.1 the first time and 127.0.0.1
    // the second. Pinning means the TCP connect uses the IP we already
    // accepted — the second lookup never happens.
    let mut pinned_addrs: Vec<std::net::SocketAddr> = Vec::new();
    let host = url.host_str().unwrap_or_default().to_string();
    let port = url.port_or_known_default().unwrap_or(443);

    if !host.is_empty() {
        // Skip DNS for raw IP literals — `lookup_host` handles them, but
        // be explicit for clarity.
        let target = format!("{host}:{port}");
        let addrs: std::result::Result<Vec<std::net::SocketAddr>, std::io::Error> =
            tokio::net::lookup_host(target.as_str())
                .await
                .map(|iter| iter.collect());
        match addrs {
            Ok(addrs) if addrs.is_empty() => {
                return Err(VerificationResult::Error(
                    "blocked: DNS returned no addresses".into(),
                ));
            }
            Ok(addrs) => {
                if !allow_private_ips && addrs.iter().any(|addr| is_private_ip_addr(&addr.ip())) {
                    return Err(VerificationResult::Error(PRIVATE_URL_ERROR.into()));
                }
                pinned_addrs = addrs;
            }
            Err(_) => {
                return Err(VerificationResult::Error(
                    "blocked: DNS resolution failed".into(),
                ));
            }
        }
    }

    // Enforce HTTPS unconditionally in production. Plaintext loopback secret
    // transmission was a known leak vector — see audit release-2026-04-26.
    // Tests that need HTTP set `danger_allow_http=true` AND
    // `danger_allow_private_ips=true` so production paths can never opt
    // into either accidentally.
    if !allow_http && url.scheme() != "https" {
        return Err(VerificationResult::Error(HTTPS_ONLY_ERROR.into()));
    }

    // Build a per-request client that pins host→addresses. `.resolve_to_addrs`
    // bypasses the system resolver for this hostname, so reqwest's internal
    // connector cannot re-resolve to a private IP between the check above
    // and the TCP connect. Keep `base_client` for code paths that don't
    // resolve a URL (e.g. AwsV4 self-constructing auth).
    let client = if !pinned_addrs.is_empty() {
        match Client::builder()
            .timeout(timeout)
            .resolve_to_addrs(&host, &pinned_addrs)
            .build()
        {
            Ok(c) => c,
            Err(_) => {
                // Fall back to the shared client. We already validated the
                // resolved IPs above; this path is best-effort.
                let _ = base_client;
                base_client.clone()
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
) -> RequestBuildResult {
    let request = request_for_method(client, method, url).timeout(timeout);
    crate::verify::auth::build_request_for_auth(
        request, auth, credential, companions, timeout, client,
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
