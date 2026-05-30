//! Live credential verification: confirms whether detected secrets are actually
//! active by making HTTP requests to the service's API endpoint as specified in
//! each detector's `[detector.verify]` configuration.

#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]

/// Local HTTP compatibility shim backed by reqwest..
pub mod reqwest {
    pub use reqwest::*;
}

mod bogon;
/// Shared in-memory verification cache.
pub mod cache;
pub mod domain_allowlist;
pub mod interpolate;
pub mod oob;
pub mod rate_limit;
pub mod ssrf;
mod verify;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use keyhog_core::{redact, DedupedMatch, DetectorSpec, VerificationResult, VerifiedFinding};

// Re-export dedup types from core so existing consumers (`use keyhog_verifier::DedupedMatch`)
// continue to work without source changes.
use crate::reqwest::{Client, Error as ReqwestError};
pub use keyhog_core::{dedup_matches, DedupScope};
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
}

/// Live-verification engine with shared client, cache, and concurrency limits.
pub struct VerificationEngine {
    client: Client,
    detectors: Arc<HashMap<Arc<str>, DetectorSpec>>,
    /// Per-service concurrency limit to avoid hammering APIs.
    service_semaphores: Arc<HashMap<Arc<str>, Arc<Semaphore>>>,
    /// Global concurrency limit.
    global_semaphore: Arc<Semaphore>,
    timeout: Duration,
    /// Response cache to avoid re-verifying the same credential.
    cache: Arc<cache::VerificationCache>,
    /// One in-flight request per (detector_id, credential). DashMap (per-shard
    /// locking) replaces the previous parking_lot::Mutex<HashMap> which was an
    /// async anti-pattern - see audits/legendary-2026-04-26.
    pub(crate) inflight: Arc<DashMap<(Arc<str>, Arc<str>), Arc<Notify>>>,
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
    /// Optional OOB session. When `Some`, detectors with `[detector.verify.oob]`
    /// receive a per-finding callback URL and the engine waits for the
    /// service to call back. When `None`, those detectors fall through to
    /// HTTP-only success criteria. Set via [`VerificationEngine::enable_oob`].
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
    /// poll. `None` falls back to the `KEYHOG_PROXY` env var; literal `"off"`
    /// disables proxying entirely. Until this was added, `--proxy` only
    /// reached the WebSource scanner - verification traffic and interactsh
    /// polls bypassed it silently, surprising operators who pointed Burp at
    /// keyhog and saw only half the traffic.
    pub proxy: Option<String>,
    /// Accept invalid / self-signed TLS certs for verifier + OOB traffic.
    /// Off by default. Required when intercepting through a MITM proxy
    /// (Burp, mitmproxy) that re-signs HTTPS with its own CA.
    pub insecure_tls: bool,
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
        }
    }
}

/// Resolve a proxy spec into an applied `reqwest::ClientBuilder`. Handles
/// the literal `"off"` sentinel (disables proxying inc. env-var inheritance)
/// and the `KEYHOG_PROXY` env-var fallback when no explicit value is set.
/// Extracted so the verifier client and OOB client share one resolver and
/// the same env-var contract.
pub(crate) fn apply_proxy_config(
    builder: reqwest::ClientBuilder,
    explicit: Option<&str>,
) -> Result<reqwest::ClientBuilder, String> {
    let resolved = if let Some(p) = explicit {
        Some(p.to_string())
    } else {
        std::env::var("KEYHOG_PROXY").ok().filter(|s| !s.is_empty())
    };
    match resolved.as_deref() {
        Some("off") | Some("none") | Some("") => Ok(builder.no_proxy()),
        Some(url) => {
            let proxy = reqwest::Proxy::all(url)
                .map_err(|e| format!("invalid verifier proxy URL {url:?}: {e}"))?;
            Ok(builder.proxy(proxy))
        }
        None => Ok(builder),
    }
}

/// Returns true iff the resolved proxy policy actually routes traffic
/// through a proxy. Mirrors [`apply_proxy_config`]'s mode resolution:
///   - explicit `Some(url)` or `KEYHOG_PROXY=<url>` → `true`
///   - explicit `Some("off"|"none"|"")` or `KEYHOG_PROXY=off|none|""` → `false`
///   - none of those set → checks reqwest's standard env-proxy vars
///     (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`). `NO_PROXY` alone does
///     not make a proxy active. Empty strings count as unset, matching
///     reqwest's own builder behavior.
///
/// Issue #2: pre-fix `proxy_in_use` was set from `KEYHOG_PROXY.is_some()`
/// alone - `KEYHOG_PROXY=off` (documented "disable" sentinel) ALSO set
/// the flag to true, which in turn disabled DNS pinning in
/// `resolved_client_for_url()` even though no proxy was active. Operators
/// using `KEYHOG_PROXY=off` for direct-connect verification lost DNS-
/// rebinding protection.
///
/// Issue #3: pre-fix the check ignored reqwest's standard `HTTPS_PROXY`
/// / `HTTP_PROXY` / `ALL_PROXY` env vars even though the shared client
/// honored them via reqwest defaults. A user with `HTTPS_PROXY=http://burp:8080`
/// got `proxy_in_use == false` → verifier rebuilt the pinned client
/// from scratch and dropped the env-proxy. The pinned path then connected
/// direct, bypassing the operator's interception/audit layer. Including
/// the reqwest env vars closes that gap.
pub fn proxy_is_active(explicit: Option<&str>) -> bool {
    let resolved = if let Some(p) = explicit {
        Some(p.to_string())
    } else {
        std::env::var("KEYHOG_PROXY").ok().filter(|s| !s.is_empty())
    };
    match resolved.as_deref() {
        Some("off") | Some("none") | Some("") => return false,
        Some(_) => return true,
        None => {}
    }
    for var in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        if std::env::var(var)
            .ok()
            .is_some_and(|v| !v.trim().is_empty())
        {
            return true;
        }
    }
    false
}

/// Convert a [`DedupedMatch`] into a [`VerifiedFinding`] with the given verification result.
pub(crate) fn into_finding(
    group: DedupedMatch,
    verification: VerificationResult,
    metadata: HashMap<String, String>,
) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: group.detector_id,
        detector_name: group.detector_name,
        service: group.service,
        severity: group.severity,
        credential_redacted: redact(&group.credential),
        credential_hash: group.credential_hash,
        location: group.primary_location,
        verification,
        metadata,
        additional_locations: group.additional_locations,
        confidence: group.confidence,
    }
}

/// Hidden hooks for integration tests. Not covered by semver.
#[doc(hidden)]
pub mod testing {
    pub use crate::bogon::ip_addr_is_bogon;
    pub use crate::oob::redact_interactsh_error;
    pub use crate::verify::format_sigv4_timestamps;
}
