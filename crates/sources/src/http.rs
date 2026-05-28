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
//! * **Proxy resolution.** Explicit config (`HttpClientConfig::proxy`,
//!   set by the `--proxy` CLI flag) wins. Otherwise the
//!   `KEYHOG_PROXY` env var, then reqwest's built-in handling of
//!   `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY`. To
//!   disable proxying entirely (e.g. an air-gapped scan that must not
//!   leak), set `--proxy off` or `KEYHOG_PROXY=off`.
//! * **TLS verification.** On by default. `--insecure` (or
//!   `KEYHOG_INSECURE_TLS=1`) accepts any certificate - needed for
//!   Burp / mitmproxy interception where the proxy MITMs HTTPS with a
//!   self-signed CA.
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
    /// Resolve proxy from env vars when no explicit value was set.
    /// Returns `Some("off")` if the operator disabled proxying.
    pub fn effective_proxy(&self) -> Option<String> {
        if let Some(p) = &self.proxy {
            return Some(p.clone());
        }
        if let Ok(p) = std::env::var("KEYHOG_PROXY") {
            if !p.is_empty() {
                return Some(p);
            }
        }
        None
    }

    /// Resolve insecure-TLS from env when not set explicitly.
    pub fn effective_insecure_tls(&self) -> bool {
        if self.insecure_tls {
            return true;
        }
        matches!(
            std::env::var("KEYHOG_INSECURE_TLS").as_deref(),
            Ok("1") | Ok("true") | Ok("TRUE")
        )
    }
}

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const REDIRECT_LIMIT: usize = 5;

fn user_agent(suffix: Option<&str>) -> String {
    let base = concat!("keyhog/", env!("CARGO_PKG_VERSION"));
    match suffix {
        Some(s) if !s.is_empty() => format!("{base} ({s})"),
        _ => base.to_string(),
    }
}

/// Build a `reqwest::blocking::ClientBuilder` populated with the
/// shared policy. Callers can chain extra builder methods (e.g.
/// `.default_headers(...)`) before `.build()`.
#[cfg(any(feature = "web", feature = "github", feature = "slack", feature = "s3"))]
pub fn blocking_client_builder(
    cfg: &HttpClientConfig,
) -> Result<reqwest::blocking::ClientBuilder, String> {
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(cfg.timeout.unwrap_or(DEFAULT_TIMEOUT))
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
                .map_err(|e| format!("invalid --proxy / KEYHOG_PROXY URL {url:?}: {e}"))?;
            builder = builder.proxy(proxy);
        }
        None => {
            // reqwest auto-detects HTTPS_PROXY / HTTP_PROXY /
            // ALL_PROXY / NO_PROXY by default; nothing to do.
        }
    }

    Ok(builder)
}

/// Async sibling for the verifier's tokio-based call sites.
#[cfg(any(feature = "web", feature = "github", feature = "slack", feature = "s3"))]
pub fn async_client_builder(cfg: &HttpClientConfig) -> Result<reqwest::ClientBuilder, String> {
    let mut builder = reqwest::Client::builder()
        .timeout(cfg.timeout.unwrap_or(DEFAULT_TIMEOUT))
        .redirect(reqwest::redirect::Policy::limited(REDIRECT_LIMIT))
        .user_agent(user_agent(cfg.ua_suffix.as_deref()))
        .danger_accept_invalid_certs(cfg.effective_insecure_tls());

    match cfg.effective_proxy().as_deref() {
        Some("off") | Some("none") | Some("") => {
            builder = builder.no_proxy();
        }
        Some(url) => {
            let proxy = reqwest::Proxy::all(url)
                .map_err(|e| format!("invalid --proxy / KEYHOG_PROXY URL {url:?}: {e}"))?;
            builder = builder.proxy(proxy);
        }
        None => {}
    }

    Ok(builder)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_proxy_overrides_env() {
        // SAFETY: tests run single-threaded by default per-binary, but
        // env mutation is still racy across `cargo test --jobs N`. The
        // env-var is namespaced under KEYHOG_ to avoid leaking into
        // other tests; nothing else in the crate reads it.
        std::env::set_var("KEYHOG_PROXY", "http://env-proxy:8080");
        let cfg = HttpClientConfig {
            proxy: Some("http://flag-proxy:9090".into()),
            ..Default::default()
        };
        assert_eq!(
            cfg.effective_proxy().as_deref(),
            Some("http://flag-proxy:9090")
        );
        std::env::remove_var("KEYHOG_PROXY");
    }

    #[test]
    fn proxy_off_string_is_preserved() {
        let cfg = HttpClientConfig {
            proxy: Some("off".into()),
            ..Default::default()
        };
        assert_eq!(cfg.effective_proxy().as_deref(), Some("off"));
    }

    #[test]
    fn insecure_tls_env_var_recognized() {
        std::env::set_var("KEYHOG_INSECURE_TLS", "1");
        let cfg = HttpClientConfig::default();
        assert!(cfg.effective_insecure_tls());
        std::env::remove_var("KEYHOG_INSECURE_TLS");
    }

    #[test]
    fn user_agent_includes_version() {
        let ua = user_agent(None);
        assert!(ua.starts_with("keyhog/"));
        assert!(ua.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn user_agent_appends_suffix() {
        let ua = user_agent(Some("web"));
        assert!(ua.contains("(web)"), "ua: {ua}");
    }
}
