//! Live credential verification: confirms whether detected secrets are actually
//! active by making HTTP requests to the service's API endpoint as specified in
//! each detector's `[detector.verify]` configuration.

#![doc = include_str!("../README.md")]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]

mod bogon;
/// Shared in-memory verification cache.
mod cache;
mod domain_allowlist;
pub mod engine;
mod interpolate;
pub mod oob;
pub mod rate_limit;
pub mod sigv4;
pub mod ssrf;
mod verify;

use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use keyhog_core::{DedupedMatch, DetectorSpec, VerificationResult, VerifiedFinding};

// Re-export dedup types from core so existing consumers (`use keyhog_verifier::DedupedMatch`)
// continue to work without source changes.
pub use engine::VerificationDeadline;
pub use keyhog_core::{dedup_matches, DedupScope};
use reqwest::{Client, Error as ReqwestError};
use thiserror::Error;
use tokio::sync::{Notify, Semaphore};

/// Errors returned while constructing or executing live verification.
#[derive(Debug, Error)]
pub enum VerifyError {
    #[error(
        "failed to send HTTP request: {0}. Fix: check network access, proxy settings, and the verification endpoint"
    )]
    Http(#[from] ReqwestError),
    #[error(
        "failed to build configured HTTP client: {0}. Fix: use a valid timeout and supported TLS/network configuration"
    )]
    ClientBuild(ReqwestError),
    #[error(
        "invalid verifier proxy configuration: {0}. Fix: use a valid http://, https://, or socks5:// URL, or set 'off' to disable proxying entirely"
    )]
    ProxyConfig(String),
    #[error(
        "failed to resolve verification field: {0}. Fix: use `match` or `companion.<name>` fields that exist in the detector spec"
    )]
    FieldResolution(String),
    #[error(
        "invalid detector verification response contract: {0}. Fix: correct the owning detector TOML before enabling live verification"
    )]
    DetectorConfig(String),
}

/// Live-verification engine with shared client, cache, and concurrency limits.
pub struct VerificationEngine {
    client: Client,
    detectors: Arc<HashMap<Arc<str>, DetectorSpec>>,
    /// Per-service concurrency limit to avoid hammering APIs.
    service_semaphores: Arc<HashMap<Arc<str>, Arc<Semaphore>>>,
    /// Configured per-service concurrency, reused as the fallback bound when a
    /// group's service is absent from `service_semaphores`. Single owner for the
    /// value (no second hardcoded default that could silently diverge).
    pub(crate) max_concurrent_per_service: usize,
    /// Global concurrency limit.
    global_semaphore: Arc<Semaphore>,
    timeout: Duration,
    /// Response cache to avoid re-verifying the same credential.
    cache: Arc<cache::VerificationCache>,
    /// One in-flight request per complete hashed verification identity.
    /// Companion values participate because detector TOML may interpolate them
    /// into authentication, tenant, account, or endpoint fields.
    pub(crate) inflight: Arc<DashMap<cache::VerificationIdentity, Arc<Notify>>>,
    pub(crate) inflight_count: Arc<AtomicUsize>,
    pub(crate) max_inflight_keys: usize,
    pub(crate) danger_allow_private_ips: bool,
    pub(crate) danger_allow_http: bool,
    /// Mirrors `VerifyConfig.insecure_tls`. The base `client` is built
    /// with `danger_accept_invalid_certs(insecure_tls)`, but the
    /// per-request DNS-pinning rebuild path needs the bool itself so
    /// it can match the base client's posture. See
    /// `verify/request.rs::resolved_client_for_url`.
    pub(crate) insecure_tls: bool,
    /// Snapshot of "was the base client built with a proxy" - propagated
    /// to per-request rebuild paths so they skip the rebuild (which would
    /// strip the proxy). See `verify/request.rs::resolved_client_for_url`.
    pub(crate) proxy_in_use: bool,
    /// Script-auth policy bit captured from [`VerifyConfig`]. Defaults false;
    /// only the visible CLI flag may turn it on.
    pub(crate) allow_script_verify: bool,
    /// Optional OOB session. When `Some`, detectors with `[detector.verify.oob]`
    /// receive a per-finding callback URL and the engine waits for the
    /// service to call back. When `None`, those detectors fail closed with a
    /// verification error before any HTTP probe is sent. Set via
    /// [`VerificationEngine::enable_oob`].
    pub(crate) oob_session: Option<Arc<oob::OobSession>>,
}

/// Runtime configuration for live verification.
///
/// Config-surface boundary: `VerifyConfig` is an **orthogonal subsystem**
/// config, NOT part of the detection/bench config surface. Only
/// `ScanConfig` + `ScannerConfig` (+ nested `MultilineConfig`) influence
/// detection accuracy and are exercised by the benchmark. `VerifyConfig`
/// governs live HTTP verification (network I/O, concurrency, proxy, TLS)
/// and is constructed only on the `--verify` path
/// (`cli/src/orchestrator/postprocess.rs`); the bench runs with
/// `--no-verification` and never touches it. The sibling orthogonal configs
/// are `OobConfig` (verifier/src/oob/session.rs, `--verify-oob` only),
/// `HttpClientConfig` (sources/src/http.rs, per-source network I/O),
/// `MegakernelSessionConfig` (scanner GPU slot geometry), and
/// `AwsSigV4Config` (S3 request signing). Do NOT fold any of these into the
/// canonical scan config: they are legitimately separate axes.
pub struct VerifyConfig {
    /// End-to-end timeout for one verification attempt.
    pub timeout: Duration,
    /// Maximum concurrent requests allowed per service.
    pub max_concurrent_per_service: usize,
    /// Maximum concurrent verification tasks overall.
    pub max_concurrent_global: usize,
    /// Upper bound for distinct in-flight deduplication keys.
    pub max_inflight_keys: usize,
    /// Whether to skip SSRF protection for private IP addresses.
    pub danger_allow_private_ips: bool,
    /// Whether to allow plaintext HTTP verification URLs. Default `false`:
    /// production paths must use HTTPS so credentials are never sent in the
    /// clear. Test fixtures (mock HTTP servers, in-memory listeners) opt in.
    pub danger_allow_http: bool,
    /// Explicit upstream proxy URL applied to every verifier request and OOB
    /// poll, set ONLY by `--proxy` / TOML. `None` means no proxy and also
    /// neutralizes reqwest's ambient proxy-env detection; no environment
    /// variable is consulted (config-policy mandate + security: an ambient proxy
    /// must never silently reroute secret-bearing traffic). The literal
    /// `"off"`/`"none"` sentinels disable proxying explicitly.
    pub proxy: Option<String>,
    /// Accept invalid / self-signed TLS certs for verifier + OOB traffic.
    /// Off by default. Required when intercepting through a MITM proxy
    /// (Burp, mitmproxy) that re-signs HTTPS with its own CA.
    pub insecure_tls: bool,
    /// Permit `AuthSpec::Script` verification. Off by default because detector
    /// TOML can otherwise execute verifier-supplied code with credential
    /// context. The CLI sets this only from the visible `--allow-script-verify`
    /// flag and prints a warning when active; no environment variable can
    /// weaken the policy.
    pub allow_script_verify: bool,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            max_concurrent_per_service: 5,
            max_concurrent_global: 20,
            max_inflight_keys: 10_000,
            danger_allow_private_ips: false,
            danger_allow_http: false,
            proxy: None,
            insecure_tls: false,
            allow_script_verify: false,
        }
    }
}

/// Resolve a proxy spec into an applied `reqwest::ClientBuilder`. ONLY the
/// explicit value (from `--proxy` / TOML) is honored, no environment variable
/// is consulted, and when no proxy is configured the builder is given
/// `.no_proxy()` so reqwest's ambient proxy-env detection cannot silently
/// reroute secret-bearing verification + OOB traffic (config-policy mandate +
/// security). The `"off"`/`"none"`/`""` sentinels also
/// disable proxying. Shared by the verifier client and the OOB client so both
/// carry the identical, env-free contract.
pub(crate) fn apply_proxy_config(
    builder: reqwest::ClientBuilder,
    explicit: Option<&str>,
) -> Result<reqwest::ClientBuilder, String> {
    match resolve_proxy_mode(explicit) {
        ProxyMode::Disabled => Ok(builder.no_proxy()),
        ProxyMode::Explicit(url) => {
            let parsed = url::Url::parse(&url).map_err(|_| invalid_proxy_url_diagnostic(None))?;
            if !matches!(parsed.scheme(), "http" | "https" | "socks5")
                || parsed.host_str().is_none()
            {
                return Err(invalid_proxy_url_diagnostic(Some(&parsed)));
            }

            // Deliberately discard reqwest's parser error and its source chain:
            // either may repeat the original URL, including userinfo or query
            // secrets. The diagnostic below contains only URL-parser-normalized
            // scheme/host components.
            let proxy = reqwest::Proxy::all(&url)
                .map_err(|_| invalid_proxy_url_diagnostic(Some(&parsed)))?;
            Ok(builder.proxy(proxy))
        }
    }
}

/// Build the only diagnostic emitted for a rejected verifier proxy URL.
///
/// A successful `url` parse makes its normalized scheme and host safe to name.
/// Userinfo, path, query, and fragment are never copied. If parsing did not
/// establish a host, echo none of the untrusted input.
fn invalid_proxy_url_diagnostic(parsed: Option<&url::Url>) -> String {
    if let Some((scheme, host)) =
        parsed.and_then(|url| url.host_str().map(|host| (url.scheme(), host)))
    {
        format!("invalid verifier proxy URL (scheme `{scheme}`, host `{host}`)")
    } else {
        "invalid verifier proxy URL".to_owned()
    }
}

enum ProxyMode {
    Disabled,
    Explicit(String),
}

/// Map an explicit proxy spec to a mode. No environment variable is read: an
/// unset proxy (`None`) disables proxying entirely, which also neutralizes
/// reqwest's ambient env-proxy detection via `.no_proxy()`.
fn resolve_proxy_mode(explicit: Option<&str>) -> ProxyMode {
    match explicit {
        Some(raw) => proxy_mode_from_raw(raw),
        None => ProxyMode::Disabled,
    }
}

fn proxy_mode_from_raw(raw: &str) -> ProxyMode {
    match raw {
        "off" | "none" | "" => ProxyMode::Disabled,
        url => ProxyMode::Explicit(url.to_string()),
    }
}

/// Returns true iff an explicit proxy is configured (and not a disable
/// sentinel). No environment variable is consulted, neither the old keyhog
/// proxy env var nor reqwest's ambient proxy-env vars, because those are
/// neutralized via `.no_proxy()` and can never route verifier traffic. This is
/// the signal `resolved_client_for_url()` uses to decide whether to apply DNS
/// pinning: with no proxy active it pins (SSRF / DNS-rebinding protection on the
/// direct connection); with an explicit proxy the proxy resolves DNS, so pinning
/// is skipped. Because an ambient proxy is now impossible, the old hazard of a
/// pinned rebuild silently dropping an env-proxy (and connecting direct, past
/// the operator's interception) cannot occur.
pub fn proxy_is_active(explicit: Option<&str>) -> bool {
    matches!(resolve_proxy_mode(explicit), ProxyMode::Explicit(_))
}

/// Scheme default reused wherever a verifier/OOB URL is resolved to a
/// `host:port` for DNS screening. ONE owner for the `.unwrap_or(443)` that was
/// pasted at every `port_or_known_default()` call site.
pub(crate) const DEFAULT_HTTPS_PORT: u16 = 443;

/// Apply the security-critical decompression + redirect posture EVERY verifier
/// and OOB reqwest client must carry, from ONE definitional home. Decompression
/// is disabled so the streaming body cap measures real wire bytes
/// (decompression-bomb defense); redirects are refused so a public host cannot
/// 302 to a private IP past the pre-connect SSRF screen. Shared by the base
/// verifier client, the DNS-pinned per-request rebuild, and the OOB collector
/// client so the posture can never diverge between them.
pub(crate) fn harden_verifier_client_builder(
    builder: reqwest::ClientBuilder,
) -> reqwest::ClientBuilder {
    builder
        .no_gzip()
        .no_brotli()
        .no_zstd()
        .no_deflate()
        .redirect(reqwest::redirect::Policy::none())
}

/// Build a DNS-pinned reqwest client carrying the full verifier posture
/// (hardened decompression/redirect + `no_proxy` + host→addr pin). ONE owner for
/// the two byte-identical pinned rebuilds (per-request verify + OOB collector);
/// each caller maps the reqwest build error into its own fail-closed refusal.
pub(crate) fn build_pinned_verifier_client(
    host: &str,
    pinned_addrs: &[std::net::SocketAddr],
    timeout: std::time::Duration,
    insecure_tls: bool,
) -> Result<reqwest::Client, reqwest::Error> {
    harden_verifier_client_builder(
        reqwest::Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(insecure_tls)
            .no_proxy(),
    )
    .resolve_to_addrs(host, pinned_addrs)
    .build()
}

/// Convert a [`DedupedMatch`] into a [`VerifiedFinding`] with the given verification result.
pub(crate) fn into_finding(
    group: DedupedMatch,
    verification: VerificationResult,
    mut metadata: HashMap<String, String>,
) -> VerifiedFinding {
    // Severity shift on verification (docs/src/verification.md "Severity shift"
    // table; docs/src/first-scan.md "downgraded one"). A credential the provider
    // rejects (`Dead`) or has explicitly revoked (`Revoked`) is still a leak, a
    // developer typed it into a file once, but it is strictly less urgent than a
    // credential an attacker can authenticate with right now. Drop exactly one
    // severity tier (`critical → high`, `high → medium`, …) via the canonical
    // `Severity::downgrade_one`; never collapse to a fixed level. `Live` keeps
    // the detector's declared severity (it really is what it claims to be), and
    // every non-conclusive result (`Error`/`RateLimited`/`Unverifiable`/
    // `Skipped`) is treated as unverified and leaves severity unchanged.
    let severity = match verification {
        VerificationResult::Dead | VerificationResult::Revoked => group.severity.downgrade_one(),
        _ => group.severity,
    };
    let credential = group.credential.as_ref();
    // Backstop every live and cached path against a misclassified credential echo.
    metadata.retain(|_, value| {
        (credential.is_empty() || !value.contains(credential))
            && group
                .companions
                .values()
                .all(|secret| secret.is_empty() || !value.contains(secret))
    });
    VerifiedFinding::from_deduped(group, severity, verification, metadata)
}

/// Hidden hooks for integration tests. Not covered by semver.
#[doc(hidden)]
pub mod testing;
