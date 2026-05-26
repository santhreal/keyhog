//! Live credential verification: confirms whether detected secrets are actually
//! active by making HTTP requests to the service's API endpoint as specified in
//! each detector's `[detector.verify]` configuration.

#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]

/// Local HTTP compatibility shim backed by reqwest..
pub mod reqwest {
    pub use reqwest::*;
}

/// Shared in-memory verification cache.
pub mod cache;
pub mod domain_allowlist;
pub mod interpolate;
pub mod oob;
pub mod rate_limit;
mod ssrf;
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
    /// async anti-pattern — see audits/legendary-2026-04-26.
    pub(crate) inflight: Arc<DashMap<(Arc<str>, Arc<str>), Arc<Notify>>>,
    pub(crate) max_inflight_keys: usize,
    pub(crate) danger_allow_private_ips: bool,
    pub(crate) danger_allow_http: bool,
    /// Snapshot of "was the base client built with a proxy" — propagated
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
    /// reached the WebSource scanner — verification traffic and interactsh
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
/// alone — `KEYHOG_PROXY=off` (documented "disable" sentinel) ALSO set
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

#[cfg(test)]
mod proxy_is_active_tests {
    //! Contract test for issues #2 + #3. The matrix here is the only
    //! place that asserts the documented `KEYHOG_PROXY` semantics: `off`
    //! / `none` / empty disable proxying entirely; explicit URLs and
    //! the reqwest env-proxy vars enable it. Each row catches a real
    //! regression class — pre-fix every "non-empty `KEYHOG_PROXY`"
    //! disabled DNS pinning, and `HTTPS_PROXY=http://burp:8080` was
    //! invisible to the rebuild path. Test holds a serialization
    //! mutex so the env-var manipulations don't race other tests in
    //! this crate.
    use std::sync::Mutex;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn with_env<F: FnOnce()>(set: &[(&str, Option<&str>)], f: F) {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let saved: Vec<(String, Option<String>)> = set
            .iter()
            .map(|(k, _)| ((*k).into(), std::env::var(k).ok()))
            .collect();
        for (k, v) in set {
            // SAFETY: ENV_MUTEX serializes mutation; restore on drop.
            unsafe {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        for (k, v) in saved {
            unsafe {
                match v {
                    Some(v) => std::env::set_var(&k, v),
                    None => std::env::remove_var(&k),
                }
            }
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    #[test]
    fn keyhog_proxy_off_is_not_active() {
        with_env(
            &[
                ("KEYHOG_PROXY", Some("off")),
                ("HTTPS_PROXY", None),
                ("HTTP_PROXY", None),
                ("ALL_PROXY", None),
                ("https_proxy", None),
                ("http_proxy", None),
                ("all_proxy", None),
            ],
            || {
                assert!(
                    !super::proxy_is_active(None),
                    "KEYHOG_PROXY=off must NOT count as an active proxy (issue #2)",
                );
            },
        );
    }

    #[test]
    fn keyhog_proxy_none_and_empty_are_not_active() {
        for value in ["none", ""] {
            with_env(
                &[
                    ("KEYHOG_PROXY", Some(value)),
                    ("HTTPS_PROXY", None),
                    ("HTTP_PROXY", None),
                    ("ALL_PROXY", None),
                    ("https_proxy", None),
                    ("http_proxy", None),
                    ("all_proxy", None),
                ],
                || {
                    assert!(
                        !super::proxy_is_active(None),
                        "KEYHOG_PROXY={value:?} must NOT count as active",
                    );
                },
            );
        }
    }

    #[test]
    fn keyhog_proxy_url_is_active() {
        with_env(
            &[
                ("KEYHOG_PROXY", Some("http://burp:8080")),
                ("HTTPS_PROXY", None),
                ("HTTP_PROXY", None),
                ("ALL_PROXY", None),
            ],
            || {
                assert!(
                    super::proxy_is_active(None),
                    "explicit KEYHOG_PROXY URL must be active",
                );
            },
        );
    }

    #[test]
    fn explicit_off_overrides_env_proxy() {
        with_env(
            &[
                ("KEYHOG_PROXY", None),
                ("HTTPS_PROXY", Some("http://corp-burp:8080")),
            ],
            || {
                assert!(
                    !super::proxy_is_active(Some("off")),
                    "explicit Some(\"off\") must take precedence over HTTPS_PROXY",
                );
            },
        );
    }

    #[test]
    fn https_proxy_env_alone_is_active() {
        with_env(
            &[
                ("KEYHOG_PROXY", None),
                ("HTTPS_PROXY", Some("http://burp:8080")),
                ("HTTP_PROXY", None),
                ("ALL_PROXY", None),
            ],
            || {
                assert!(
                    super::proxy_is_active(None),
                    "HTTPS_PROXY env var must count as active (issue #3) — pre-fix \
                     the rebuild path dropped reqwest-managed env proxies and \
                     verifier traffic bypassed the operator's interception",
                );
            },
        );
    }

    #[test]
    fn http_proxy_and_all_proxy_env_vars_count() {
        for var in ["HTTP_PROXY", "ALL_PROXY", "http_proxy", "all_proxy"] {
            with_env(
                &[
                    ("KEYHOG_PROXY", None),
                    ("HTTPS_PROXY", None),
                    ("HTTP_PROXY", None),
                    ("ALL_PROXY", None),
                    ("https_proxy", None),
                    ("http_proxy", None),
                    ("all_proxy", None),
                    (var, Some("http://corp:8080")),
                ],
                || {
                    assert!(
                        super::proxy_is_active(None),
                        "{var} env var alone must mark proxy active",
                    );
                },
            );
        }
    }

    #[test]
    fn no_proxy_alone_is_not_active() {
        // NO_PROXY without any other proxy var means "no proxy in use at
        // all" — it's a deny-list relative to nothing. Must NOT mark
        // proxy active or rebuild-path drops DNS pinning gratuitously.
        with_env(
            &[
                ("KEYHOG_PROXY", None),
                ("HTTPS_PROXY", None),
                ("HTTP_PROXY", None),
                ("ALL_PROXY", None),
                ("https_proxy", None),
                ("http_proxy", None),
                ("all_proxy", None),
                ("NO_PROXY", Some("*.internal.corp")),
            ],
            || {
                assert!(
                    !super::proxy_is_active(None),
                    "NO_PROXY alone is not a proxy — must NOT mark active",
                );
            },
        );
    }
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
