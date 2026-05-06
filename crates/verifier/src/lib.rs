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
        }
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
