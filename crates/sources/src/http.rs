//! Shared HTTP client builder for every source / verifier site that
//! goes over the network.
//!
//! Why this lives in one module
//! ----------------------------
//! `web.rs`, `github_org.rs`, the verifier's `verify/request.rs` and
//! `verify/mod.rs`, and the slack source all build their own
//! `reqwest::Client` directly. Without a shared builder, an operator
//! who puts `HTTP_PROXY=http://burp:8080` into their environment would
//! discover that *some* sites honor it (the ones that don't call
//! `.no_proxy()`) and *others* don't, with no good signal as to why.
//! Worse, adding `--proxy` to one site without the others would mean
//! the verifier silently bypasses the proxy that the scan sources are
//! routed through - so leaked-then-verified findings still leak the
//! credential straight to the upstream API.
//!
//! [`HttpClientConfig`] is the single point of policy and
//! [`blocking_client_builder`] / [`async_client_builder`] are the
//! single construction sites. Every HTTP call in the binary flows
//! through one of them.
//!
//! Policy summary
//! --------------
//! * **Proxy resolution.** ONLY explicit config (`HttpClientConfig::proxy`,
//!   set by the `--proxy` CLI flag / TOML) is honored. No environment
//!   variable sets or changes the proxy, and the builders call `.no_proxy()`
//!   when none is configured so reqwest's ambient `HTTPS_PROXY` /
//!   `HTTP_PROXY` / `ALL_PROXY` auto-detection can't silently reroute
//!   secret-bearing traffic. `--proxy off` disables proxying entirely.
//! * **TLS verification.** On by default. ONLY `--insecure` (CLI / TOML)
//!   accepts an invalid certificate - needed for Burp / mitmproxy
//!   interception. No environment variable can disable verification: an
//!   ambient toggle must never turn off the protection guarding exfiltrated
//!   secrets from a MITM.
//! * **Body-bomb defenses.** Auto-decompression OFF (the per-site
//!   chunk handlers opt in where they need it). 5-hop redirect cap.
//!   30 s connect / per-request timeout default.
//! * **User-Agent.** `keyhog/<version>` so operators can spot keyhog
//!   traffic in their proxy logs without grepping for "reqwest".

use std::time::Duration;

/// Single source of truth for outbound HTTP policy.
#[derive(Debug, Clone, Default)]
pub struct HttpClientConfig {
    /// Explicit proxy URL. Overrides env-var detection. Accepts
    /// `http://`, `https://`, `socks5://` schemes (forwarded to
    /// reqwest unchanged). The literal string `"off"` disables
    /// proxying entirely - including env-var inheritance.
    pub proxy: Option<String>,
    /// Accept invalid / self-signed TLS certs (Burp CA, mitmproxy CA).
    /// Off by default.
    pub insecure_tls: bool,
    /// Optional per-request timeout override. `None` falls back to
    /// the 30-second default below.
    pub timeout: Option<Duration>,
    /// User-Agent suffix appended after `keyhog/<version>`. Lets a
    /// per-source caller add its own identifier (e.g. `web`,
    /// `github-org`) without forcing every site to spell out the full
    /// version string.
    pub ua_suffix: Option<String>,
}

impl HttpClientConfig {
    /// The configured proxy, or `None`. ONLY the explicit `proxy` field (set by
    /// the `--proxy` CLI flag / TOML) is honored — no environment variable can
    /// change egress routing (config-policy mandate: env never overrides
    /// behavior). Ambient `HTTP(S)_PROXY` is separately neutralized in the
    /// builders via `.no_proxy()` so a stray CI/shell proxy can't silently
    /// reroute the secret-verification traffic. `Some("off")` disables proxying.
    pub(crate) fn effective_proxy(&self) -> Option<String> {
        self.proxy.clone()
    }

    /// Whether to accept invalid / self-signed TLS certs. ONLY the explicit
    /// `insecure_tls` field (set by `--insecure` / TOML) is honored — no
    /// environment variable can disable certificate verification. An ambient
    /// toggle must never be able to switch off the only thing protecting
    /// exfiltrated secrets from a MITM on the verifier's outbound calls.
    pub(crate) fn effective_insecure_tls(&self) -> bool {
        self.insecure_tls
    }
}

#[cfg(any(
    feature = "azure",
    feature = "web",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket",
    feature = "slack",
    feature = "s3",
    feature = "gcs"
))]
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(any(
    feature = "azure",
    feature = "web",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket",
    feature = "slack",
    feature = "s3",
    feature = "gcs"
))]
const REDIRECT_LIMIT: usize = 5;

pub(crate) fn user_agent(suffix: Option<&str>) -> String {
    let base = concat!("keyhog/", env!("CARGO_PKG_VERSION"));
    match suffix {
        Some(s) if !s.is_empty() => format!("{base} ({s})"),
        _ => base.to_string(),
    }
}

/// Build a `reqwest::blocking::ClientBuilder` populated with the
/// shared policy. Callers can chain extra builder methods (e.g.
/// `.default_headers(...)`) before `.build()`.
#[cfg(any(
    feature = "azure",
    feature = "web",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket",
    feature = "slack",
    feature = "s3",
    feature = "gcs"
))]
pub(crate) fn blocking_client_builder(
    cfg: &HttpClientConfig,
) -> Result<reqwest::blocking::ClientBuilder, String> {
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(cfg.timeout.unwrap_or(DEFAULT_TIMEOUT)) // LAW10: Tier-A config default — unset timeout uses the documented DEFAULT_TIMEOUT, not a silent error
        .redirect(reqwest::redirect::Policy::limited(REDIRECT_LIMIT))
        .user_agent(user_agent(cfg.ua_suffix.as_deref()))
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .danger_accept_invalid_certs(cfg.effective_insecure_tls());

    match cfg.effective_proxy().as_deref() {
        Some("off") | Some("none") | Some("") => {
            builder = builder.no_proxy();
        }
        Some(url) => {
            let proxy = reqwest::Proxy::all(url)
                .map_err(|e| format!("invalid --proxy URL {url:?}: {e}"))?;
            builder = builder.proxy(proxy);
        }
        None => {
            // No explicit proxy configured. Disable reqwest's ambient
            // HTTPS_PROXY / HTTP_PROXY / ALL_PROXY auto-detection so a stray env
            // proxy in a CI runner or shell profile can't silently reroute
            // secret-bearing verification traffic. Only `--proxy` / TOML sets one.
            builder = builder.no_proxy();
        }
    }

    Ok(builder)
}

/// Async sibling for the verifier's tokio-based call sites.
#[cfg(any(
    feature = "azure",
    feature = "web",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket",
    feature = "slack",
    feature = "s3",
    feature = "gcs"
))]
pub(crate) fn async_client_builder(
    cfg: &HttpClientConfig,
) -> Result<reqwest::ClientBuilder, String> {
    let mut builder = reqwest::Client::builder()
        .timeout(cfg.timeout.unwrap_or(DEFAULT_TIMEOUT)) // LAW10: Tier-A config default — unset timeout uses the documented DEFAULT_TIMEOUT, not a silent error
        .redirect(reqwest::redirect::Policy::limited(REDIRECT_LIMIT))
        .user_agent(user_agent(cfg.ua_suffix.as_deref()))
        .danger_accept_invalid_certs(cfg.effective_insecure_tls());

    match cfg.effective_proxy().as_deref() {
        Some("off") | Some("none") | Some("") => {
            builder = builder.no_proxy();
        }
        Some(url) => {
            let proxy = reqwest::Proxy::all(url)
                .map_err(|e| format!("invalid --proxy URL {url:?}: {e}"))?;
            builder = builder.proxy(proxy);
        }
        None => {
            // See the blocking builder: neutralize ambient HTTP(S)_PROXY so only
            // an explicit `--proxy` / TOML proxy is ever used.
            builder = builder.no_proxy();
        }
    }

    Ok(builder)
}
