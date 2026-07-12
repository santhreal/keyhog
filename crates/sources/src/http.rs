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
//!   30 s total per-request timeout default (no separate connect timeout;
//!   the total budget bounds the whole request including connect).
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
    /// Optional per-request timeout override. `None` falls back to the ONE
    /// shared default `crate::timeouts::HTTP_REQUEST` (30 s).
    pub timeout: Option<Duration>,
    /// User-Agent suffix appended after `keyhog/<version>`. Lets a
    /// per-source caller add its own identifier (e.g. `web`,
    /// `github-org`) without forcing every site to spell out the full
    /// version string.
    pub ua_suffix: Option<String>,
    /// Allow cloud endpoints (`--s3-endpoint`, GCS / Azure container URLs) whose
    /// literal host OR resolved address is private / loopback / link-local /
    /// cloud-metadata. OFF by default: the SSRF host-screen in
    /// `cloud::parse_http_endpoint` refuses every such endpoint. This is a
    /// Tier-A config knob (set by `--allow-private-cloud-endpoint` / TOML, NEVER
    /// an environment variable — scan/security behavior is resolved config, not
    /// env) for legit private-network deployments (MinIO / Ceph on an internal
    /// gateway) and loopback mock servers in integration tests.
    pub allow_private_endpoint: bool,
}

impl HttpClientConfig {
    /// The configured proxy, or `None`. ONLY the explicit `proxy` field (set by
    /// the `--proxy` CLI flag / TOML) is honored — no environment variable can
    /// change egress routing (config-policy mandate: env never overrides
    /// behavior). Ambient `HTTP(S)_PROXY` is separately neutralized in the
    /// builders via `.no_proxy()` so a stray CI/shell proxy can't silently
    /// reroute the secret-verification traffic. `Some("off")` disables proxying.
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
    pub(crate) fn effective_proxy(&self) -> Option<String> {
        self.proxy.clone()
    }

    /// Effective timeout used by both shared HTTP clients and pre-connect
    /// network policy checks such as WebSource DNS screening.
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
    pub(crate) fn effective_timeout(&self) -> Duration {
        self.timeout.unwrap_or(crate::timeouts::HTTP_REQUEST) // LAW10: Tier-A config default — unset timeout uses the ONE shared HTTP_REQUEST default, not a swallowed error
    }

    /// Whether to accept invalid / self-signed TLS certs. ONLY the explicit
    /// `insecure_tls` field (set by `--insecure` / TOML) is honored — no
    /// environment variable can disable certificate verification. An ambient
    /// toggle must never be able to switch off the only thing protecting
    /// exfiltrated secrets from a MITM on the verifier's outbound calls.
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
    pub(crate) fn effective_insecure_tls(&self) -> bool {
        self.insecure_tls
    }

    /// HTTP config identical to the default EXCEPT it permits private / loopback
    /// endpoints. The config-flag replacement for the retired
    /// `KEYHOG_ALLOW_PRIVATE_CLOUD_ENDPOINT` env opt-in — used by the source-test
    /// facade so httpmock (`127.0.0.1`) endpoints pass the cloud SSRF screen
    /// without any process-global env state.
    #[cfg(any(feature = "s3", feature = "gcs", feature = "azure"))]
    pub(crate) fn allowing_private_endpoint() -> Self {
        Self {
            allow_private_endpoint: true,
            ..Self::default()
        }
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
pub(crate) const REDIRECT_LIMIT: usize = 5;

/// Extract the bare media type from a `Content-Type` header value: the text
/// before the first `;` (dropping any `charset=`/`boundary=` parameters), with
/// surrounding whitespace trimmed. Single owner in this always-compiled module
/// so every content-type classifier — the `web` response router
/// (`crate::web`) AND the cloud binary/unknown checks (`crate::cloud`) — splits
/// the header the same way WITHOUT the `web` feature having to pull in a cloud
/// provider feature (the fn used to live in the `cfg`-gated `cloud` module,
/// which made `--features web` fail to compile standalone). Gated to exactly
/// the features whose code calls it (`web`, and the cloud providers behind
/// `crate::cloud`) so a minimal build carries no dead helper.
#[cfg(any(feature = "web", feature = "azure", feature = "s3", feature = "gcs"))]
pub(crate) fn media_type(content_type: &str) -> &str {
    content_type
        .split_once(';')
        .map_or(content_type, |(media_type, _)| media_type)
        .trim()
}

pub(crate) fn user_agent(suffix: Option<&str>) -> String {
    let base = concat!("keyhog/", env!("CARGO_PKG_VERSION"));
    match suffix {
        Some(s) if !s.is_empty() => format!("{base} ({s})"),
        _ => base.to_string(),
    }
}

/// The ONE outbound-HTTP policy, applied identically to the blocking and async
/// `ClientBuilder`s (which share every method name but no common trait, so a
/// macro is the single owner). Any new hardening — a decompression toggle, a
/// proxy sentinel, a TLS knob — is added here once and both builders inherit it,
/// preventing the two-copies drift this module exists to prevent.
///
/// `$builder` is a fresh `reqwest::{blocking,}::ClientBuilder`; expands inside a
/// `-> Result<_, String>` fn so the proxy-parse `?` propagates.
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
macro_rules! shared_http_policy {
    ($builder:expr, $cfg:expr) => {{
        let cfg = $cfg;
        let builder = $builder
            .timeout(cfg.effective_timeout()) // LAW10: unset timeout uses the ONE shared HTTP_REQUEST default, not a silent error
            .redirect(reqwest::redirect::Policy::limited(REDIRECT_LIMIT))
            .user_agent(user_agent(cfg.ua_suffix.as_deref()))
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .danger_accept_invalid_certs(cfg.effective_insecure_tls());

        // Ambient HTTPS_PROXY / HTTP_PROXY / ALL_PROXY is always neutralized via
        // `.no_proxy()`; ONLY an explicit `--proxy` / TOML URL routes traffic, so
        // a stray CI/shell proxy can't silently reroute secret-bearing requests.
        let builder = match cfg.effective_proxy().as_deref() {
            Some("off") | Some("none") | Some("") | None => builder.no_proxy(),
            Some(url) => {
                let proxy = reqwest::Proxy::all(url)
                    .map_err(|e| format!("invalid --proxy URL {url:?}: {e}"))?;
                builder.proxy(proxy)
            }
        };
        Ok(builder)
    }};
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
    shared_http_policy!(reqwest::blocking::Client::builder(), cfg)
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
    shared_http_policy!(reqwest::Client::builder(), cfg)
}
