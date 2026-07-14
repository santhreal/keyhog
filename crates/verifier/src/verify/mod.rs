//! Verification execution logic.
//!
//! Verification is explicitly opt-in via the `--verify` CLI flag.
//! Security invariants for this module:
//! - Credentials are never stored permanently. They are only used in-memory for the current run.
//! - HTTPS only. TLS certificate validation stays enabled for every request.
//! - Private IPs and private DNS resolutions are blocked to reduce SSRF risk.
//! - Redirects are not followed.
//! - Response bodies are capped at 1 MB.

mod auth;
pub(crate) mod aws;
pub(crate) mod credential;
mod multi_step;
pub(crate) mod request;
pub(crate) mod response;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use futures_util::FutureExt;
use keyhog_core::{
    CredentialHash, MatchLocation, SensitiveString, Severity, VerificationResult, VerifiedFinding,
};
use reqwest::Client;
use tokio::sync::{Notify, Semaphore};
use tokio::task::{Id as TaskId, JoinError, JoinSet};

use crate::cache;
use crate::{into_finding, DedupedMatch, VerificationEngine, VerifyConfig, VerifyError};

pub(crate) use aws::{
    build_aws_probe, classify_aws_sts_failure, parse_aws_sts_success_metadata, valid_aws_format,
    validate_aws_region,
};
pub(crate) use credential::{
    rate_limit_feedback_sequence_for_test, retry_delay_bounds_for_attempt,
    retry_loop_preserves_metadata_on_exhaustion_for_test,
    retry_loop_records_rate_limit_feedback_for_test, verify_with_retry, VerificationAttempt,
};
pub(crate) use multi_step::rate_limit_service_name as multi_step_rate_limit_service_name;
pub(crate) use request::{
    apply_header_body_templates, build_request_for_step, clear_pinned_client_cache_for_test,
    missing_companion_error, pinned_client_cache_len_for_host_for_test,
    pinned_client_cache_len_for_test, pinned_client_for_test, resolved_client_for_url,
    ssrf_check_url_with_resolved_addrs_for_test, validate_header_body_templates,
    validate_template_companions, RequestBuildResult,
};
pub(crate) use response::{
    body_indicates_error, evaluate_success, execute_and_read_response, extract_metadata,
    extract_provider_evidence,
};

/// Single owner for the retryable-HTTP-status contract (rate-limit 429 plus the
/// 500..=504 server-error band). Shared by single-step verify, multi-step
/// verify, and the AWS STS classifier so the retry/cache decision can never
/// diverge between paths.
pub(crate) fn retryable_http_status(status: u16) -> bool {
    status == 429 || (500..=504).contains(&status)
}

/// Whether a detector supplied a *meaningful* success contract (any matched
/// condition, not the empty default). When true the contract is authoritative
/// and the generic `body_indicates_error` backstop must not second-guess it.
pub(crate) fn success_spec_is_explicit(spec: &keyhog_core::SuccessSpec) -> bool {
    spec.status.is_some()
        || spec.status_not.is_some()
        || spec.body_contains.is_some()
        || spec.body_not_contains.is_some()
        || spec.json_path.is_some()
}

/// Final live verdict for the single-step path. An explicit success contract is
/// authoritative: the generic `body_indicates_error` backstop runs ONLY when the
/// detector supplied no meaningful success spec, so a matched contract is never
/// flipped Live->Dead by a 200 body that merely embeds an error-named field.
pub(crate) fn resolve_live_verdict(is_live: bool, success_is_explicit: bool, body: &str) -> bool {
    is_live && (success_is_explicit || !body_indicates_error(body))
}

/// Loudly record that the inflight-dedup cap was hit and this (detector,
/// credential) is being verified WITHOUT the single-in-flight guard. Surfacing
/// (Law 10): a counter for every bypass plus a process-once warn, the silent
/// `break None` degrade otherwise hid duplicate live-API probes / rate-limit
/// bans with no operator-visible cause.
static INFLIGHT_CAP_BYPASSES: AtomicUsize = AtomicUsize::new(0);
static INFLIGHT_CAP_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

pub(crate) fn note_inflight_cap_bypass(max_inflight_keys: usize) -> usize {
    let count = INFLIGHT_CAP_BYPASSES.fetch_add(1, Ordering::Relaxed) + 1;
    if INFLIGHT_CAP_WARNED.set(()).is_ok() {
        tracing::warn!(
            max_inflight_keys,
            "verifier inflight-dedup cap reached: verifying (detector, credential) pairs \
             WITHOUT the single-in-flight guard, so concurrent duplicate probes can hit the \
             live API (rate-limit bans). Raise max_inflight_keys to restore dedup."
        );
    }
    count
}

#[derive(Clone)]
struct VerifyTaskShared {
    global_semaphore: Arc<Semaphore>,
    service_semaphores: Arc<HashMap<Arc<str>, Arc<Semaphore>>>,
    /// Fallback per-service concurrency for a group whose service is absent from
    /// `service_semaphores`. Threaded from `VerifyConfig.max_concurrent_per_service`
    /// so raising the configured cap also raises this fallback (single owner
    /// no second hardcoded default).
    max_concurrent_per_service: usize,
    client: Client,
    detectors: Arc<HashMap<Arc<str>, keyhog_core::DetectorSpec>>,
    timeout: Duration,
    cache: Arc<cache::VerificationCache>,
    inflight: Arc<DashMap<(Arc<str>, SensitiveString), Arc<Notify>>>,
    inflight_count: Arc<AtomicUsize>,
    max_inflight_keys: usize,
    danger_allow_private_ips: bool,
    danger_allow_http: bool,
    /// Mirrors `VerifyConfig.insecure_tls`. Threaded into
    /// `resolved_client_for_url` so the DNS-pinned per-request client
    /// rebuild honors the `--insecure` flag the operator set on the
    /// engine. Without this the base client accepts invalid certs but
    /// the rebuild path rejects them - the flag silently does nothing
    /// for direct (non-proxy) connections. 2026-05-26.
    insecure_tls: bool,
    allow_script_verify: bool,
    /// `true` when the engine'"'"'s base client was built with a proxy. The
    /// per-request DNS-pinned client rebuild path in
    /// `resolved_client_for_url` MUST NOT fire when a proxy is in use,
    /// or the proxy config silently gets dropped. We carry the bool
    /// rather than the proxy URL itself because no downstream code
    /// needs the URL - only the "skip the rebuild" signal.
    proxy_in_use: bool,
    oob_session: Option<Arc<crate::oob::OobSession>>,
}

struct InflightGuard {
    key: (Arc<str>, SensitiveString),
    inflight: Arc<DashMap<(Arc<str>, SensitiveString), Arc<Notify>>>,
    inflight_count: Arc<AtomicUsize>,
    notify: Arc<Notify>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        // DashMap's per-shard locking means this never blocks a tokio worker
        // for more than the time to mutate one shard - orders of magnitude
        // less than the previous global parking_lot::Mutex which was held
        // across the entire HashMap traversal in the await loop.
        self.inflight.remove(&self.key);
        self.inflight_count.fetch_sub(1, Ordering::Release);
        self.notify.notify_waiters();
    }
}

fn try_reserve_inflight_slot(inflight_count: &AtomicUsize, max_inflight_keys: usize) -> bool {
    let mut current = inflight_count.load(Ordering::Acquire);
    loop {
        if current >= max_inflight_keys {
            return false;
        }
        match inflight_count.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

async fn verify_group_task_safe(shared: VerifyTaskShared, group: DedupedMatch) -> VerifiedFinding {
    let group_for_error = group.clone();
    match std::panic::AssertUnwindSafe(verify_group_task(shared, group))
        .catch_unwind()
        .await
    {
        Ok(finding) => finding,
        Err(e) => {
            // Law 10: verifier task panic is converted into an operator-visible verification error finding
            // Law 10: scanner-thread panic => LOUD tracing::error + SCANNER_PANICKED flag (results marked incomplete + surfaced); allowed loud+recorded degrade
            let reason = if let Some(s) = e.downcast_ref::<&str>() {
                format!("verification task panicked: {s}")
            } else if let Some(s) = e.downcast_ref::<String>() {
                format!("verification task panicked: {s}")
            } else {
                "verification task panicked".to_string() // LAW10: non-str/String payload => generic loud reason; recall-safe
            };
            tracing::error!(reason);
            into_finding(
                group_for_error,
                VerificationResult::Error(reason),
                HashMap::new(),
            )
        }
    }
}

fn spawn_tracked_verify_task(
    join_set: &mut JoinSet<VerifiedFinding>,
    task_groups: &mut HashMap<TaskId, DedupedMatch>,
    shared: VerifyTaskShared,
    group: DedupedMatch,
) {
    let group_for_error = group.clone();
    let abort_handle = join_set.spawn(verify_group_task_safe(shared, group));
    task_groups.insert(abort_handle.id(), group_for_error);
}

fn finding_for_join_error(
    join_error: JoinError,
    task_groups: &mut HashMap<TaskId, DedupedMatch>,
) -> Option<VerifiedFinding> {
    let task_id = join_error.id();
    tracing::error!(
        %join_error,
        %task_id,
        "a verification task failed to join; preserving the credential group as a verification error"
    );
    match task_groups.remove(&task_id) {
        Some(group) => Some(into_finding(
            group,
            VerificationResult::Error(format!("verification task failed to join: {join_error}")),
            HashMap::new(),
        )),
        None => {
            tracing::error!(
                %task_id,
                "a verification task failed to join but had no tracked credential group"
            );
            None
        }
    }
}

#[doc(hidden)]
pub async fn tracked_join_error_preservation_for_test() -> Option<VerifiedFinding> {
    let mut join_set = JoinSet::new();
    let mut task_groups = HashMap::new();
    let group = DedupedMatch {
        detector_id: Arc::from("test-detector"),
        detector_name: Arc::from("Test Detector"),
        service: Arc::from("test-service"),
        severity: Severity::High,
        credential: SensitiveString::from("test-secret-for-join-error"),
        credential_hash: CredentialHash::ZERO,
        companions: HashMap::new(),
        primary_location: MatchLocation {
            source: Arc::from("test"),
            file_path: Some(Arc::from("fixture.txt")),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        additional_locations: Vec::new(),
        confidence: Some(0.9),
    };
    let abort_handle = join_set.spawn(async { std::future::pending::<VerifiedFinding>().await });
    task_groups.insert(abort_handle.id(), group);
    abort_handle.abort();
    match join_set.join_next_with_id().await {
        Some(Err(join_error)) => finding_for_join_error(join_error, &mut task_groups),
        _ => None,
    }
}

async fn verify_group_task(shared: VerifyTaskShared, group: DedupedMatch) -> VerifiedFinding {
    let global = shared.global_semaphore;
    let service_sem = shared
        .service_semaphores
        .get(&*group.service)
        .cloned()
        .unwrap_or_else(|| Arc::new(Semaphore::new(shared.max_concurrent_per_service))); // LAW10: absent from prebuilt map => configured max_concurrent_per_service (Tier-A knob), one owner
    let client = shared.client;
    let detector = shared.detectors.get(&*group.detector_id).cloned();
    let timeout = shared.timeout;

    let cache = shared.cache;
    let inflight = shared.inflight;
    let inflight_count = shared.inflight_count;
    let max_inflight_keys = shared.max_inflight_keys;

    let Ok(_global_permit) = global.acquire().await else {
        return into_finding(
            group,
            VerificationResult::Error("semaphore closed".into()),
            HashMap::new(),
        );
    };
    let Ok(_service_permit) = service_sem.acquire().await else {
        return into_finding(
            group,
            VerificationResult::Error("service semaphore closed".into()),
            HashMap::new(),
        );
    };

    if let Some((cached_result, cached_meta)) = cache.get(&group.credential, &group.detector_id) {
        return into_finding(group, cached_result, cached_meta);
    }

    let _inflight_guard = loop {
        // The Vacant arm always `break`s the loop, so this block only ever
        // evaluates to a notify handle (Occupied) to wait on and retry.
        let notify_to_await: Arc<Notify> = {
            // Inflight dedup via DashMap: per-shard locks instead of one
            // global parking_lot::Mutex held across HashMap operations in an
            // async context (anti-pattern that stalled the tokio runtime
            // under high concurrency - see the 2026-04-26 audit).
            let key = (group.detector_id.clone(), group.credential.clone());
            if let Some((cached_result, cached_meta)) =
                cache.get(&group.credential, &group.detector_id)
            {
                return into_finding(group, cached_result, cached_meta);
            }

            match inflight.entry(key.clone()) {
                dashmap::mapref::entry::Entry::Occupied(entry) => entry.get().clone(),
                dashmap::mapref::entry::Entry::Vacant(entry) => {
                    if !try_reserve_inflight_slot(&inflight_count, max_inflight_keys) {
                        note_inflight_cap_bypass(max_inflight_keys);
                        break None;
                    }
                    let notify = Arc::new(Notify::new());
                    entry.insert(notify.clone());
                    break Some(InflightGuard {
                        key,
                        inflight: inflight.clone(),
                        inflight_count: inflight_count.clone(),
                        notify,
                    });
                }
            }
        };

        notify_to_await.notified().await;
    };

    let (verification, metadata) = if let Some(verify_spec) = detector
        .as_ref()
        .and_then(|detector| detector.verify.as_ref())
    {
        verify_with_retry(
            &client,
            verify_spec,
            &group.credential,
            &group.companions,
            timeout,
            shared.danger_allow_private_ips,
            shared.danger_allow_http,
            shared.proxy_in_use,
            shared.insecure_tls,
            shared.allow_script_verify,
            shared.oob_session.as_ref(),
        )
        .await
    } else {
        (VerificationResult::Unverifiable, HashMap::new())
    };

    // Cache only stable verdicts. A `RateLimited` or a transient-network
    // `Error` that exhausted the retry loop must NOT be pinned for the full TTL,
    // or a single network blip would report a live credential as errored on
    // every rescan within the window. See `verification_result_is_cacheable`.
    if verification_result_is_cacheable(&verification) {
        cache.put(
            &group.credential,
            &group.detector_id,
            verification.clone(),
            metadata.clone(),
        );
    }

    into_finding(group, verification, metadata)
}

/// Whether a verification outcome is stable enough to cache across scans.
///
/// Only definitive verdicts and the deterministic local outcomes are cached.
/// `RateLimited` (always transient, a 429/503 the retry loop could not clear)
/// and `Error` (a transient timeout/reset/"max retries exceeded" that exhausted
/// retries, OR a deterministic config error) are deliberately NOT cached: the
/// transient cases must be re-verified on the next scan rather than masking a
/// live credential for the full cache TTL, and the deterministic errors are
/// cheap, network-free local recomputes whose caching saves nothing, so
/// skipping them removes any risk of pinning a misclassified blip.
///
/// This is a positive allowlist: a future `VerificationResult` variant defaults
/// to NOT cacheable (re-verify), the safe direction for a verdict cache.
pub(crate) fn verification_result_is_cacheable(result: &VerificationResult) -> bool {
    matches!(
        result,
        VerificationResult::Live
            | VerificationResult::Revoked
            | VerificationResult::Dead
            | VerificationResult::Unverifiable
            | VerificationResult::Skipped
    )
}

impl VerificationEngine {
    /// Create a verifier with shared HTTP client, cache, and concurrency controls.
    pub fn new(
        detectors: &[keyhog_core::DetectorSpec],
        config: VerifyConfig,
    ) -> Result<Self, VerifyError> {
        for detector in detectors {
            let errors = keyhog_core::json_selector::validate_detector_response_selectors(detector);
            if !errors.is_empty() {
                return Err(VerifyError::DetectorConfig(format!(
                    "detector {:?}: {}",
                    detector.id,
                    errors.join("; ")
                )));
            }
        }
        // Cert validation: ON by default, escape hatch ONLY through the
        // explicit `VerifyConfig.insecure_tls` knob (set by the `--insecure`
        // flag or `.keyhog.toml`; no env var can flip it (config mandate)).
        // Production paths never flip this. The decompression-bomb + redirect
        // posture is applied by the single `harden_verifier_client_builder`
        // owner shared with both DNS-pinned rebuild paths.
        let mut builder = crate::harden_verifier_client_builder(
            Client::builder()
                .timeout(config.timeout)
                .danger_accept_invalid_certs(config.insecure_tls),
        );
        builder = crate::apply_proxy_config(builder, config.proxy.as_deref())
            .map_err(VerifyError::ProxyConfig)?;
        let client = builder.build().map_err(VerifyError::ClientBuild)?;

        let detector_map: HashMap<Arc<str>, keyhog_core::DetectorSpec> = detectors
            .iter()
            .cloned()
            .map(|mut detector| {
                if let Some(verify) = detector.verify.as_mut() {
                    if verify.service.trim().is_empty() {
                        verify.service.clone_from(&detector.service);
                    }
                }
                (detector.id.clone().into(), detector)
            })
            .collect();

        let mut service_semaphores = HashMap::new();
        for d in detectors {
            service_semaphores
                .entry(d.service.clone().into())
                .or_insert_with(|| {
                    Arc::new(Semaphore::new(config.max_concurrent_per_service.max(1)))
                });
        }

        Ok(Self {
            client,
            detectors: Arc::new(detector_map),
            service_semaphores: Arc::new(service_semaphores),
            max_concurrent_per_service: config.max_concurrent_per_service.max(1),
            global_semaphore: Arc::new(Semaphore::new(config.max_concurrent_global.max(1))),
            timeout: config.timeout,
            cache: Arc::new(cache::VerificationCache::default_ttl()),
            inflight: Arc::new(DashMap::new()),
            inflight_count: Arc::new(AtomicUsize::new(0)),
            max_inflight_keys: config.max_inflight_keys.max(1),
            danger_allow_private_ips: config.danger_allow_private_ips,
            danger_allow_http: config.danger_allow_http,
            insecure_tls: config.insecure_tls,
            allow_script_verify: config.allow_script_verify,
            // Don't conflate "configured to set a proxy policy" with "a proxy is
            // actively routing traffic." `proxy_is_active` is true ONLY for an
            // explicit `--proxy` URL (the `off`/`none`/empty sentinels and an
            // unset proxy are inactive); no environment variable is consulted,
            // and ambient proxy-env detection is neutralized via `.no_proxy()`.
            // `proxy_in_use` gates the DNS-pinning rebuild in
            // resolved_client_for_url(): false → pin (SSRF / DNS-rebinding
            // protection on the direct connection); true → skip pinning because
            // the explicit proxy resolves DNS. Because an ambient proxy can no
            // longer exist, the prior hazard of the pinned rebuild silently
            // dropping an env-proxy (and connecting direct, past the operator's
            // interception) cannot occur.
            proxy_in_use: crate::proxy_is_active(config.proxy.as_deref()),
            oob_session: None,
        })
    }

    /// Verify a batch of deduplicated raw matches in parallel.
    pub async fn verify_all(&self, groups: Vec<DedupedMatch>) -> Vec<VerifiedFinding> {
        let max_active = self.global_semaphore.available_permits().max(1);
        let total = groups.len();
        let shared = VerifyTaskShared {
            global_semaphore: self.global_semaphore.clone(),
            service_semaphores: self.service_semaphores.clone(),
            max_concurrent_per_service: self.max_concurrent_per_service,
            client: self.client.clone(),
            detectors: self.detectors.clone(),
            timeout: self.timeout,
            cache: self.cache.clone(),
            inflight: self.inflight.clone(),
            inflight_count: self.inflight_count.clone(),
            max_inflight_keys: self.max_inflight_keys,
            danger_allow_private_ips: self.danger_allow_private_ips,
            danger_allow_http: self.danger_allow_http,
            insecure_tls: self.insecure_tls,
            allow_script_verify: self.allow_script_verify,
            proxy_in_use: self.proxy_in_use,
            oob_session: self.oob_session.clone(),
        };
        let mut pending = groups.into_iter();
        let mut join_set = JoinSet::new();
        let mut task_groups = HashMap::new();

        while join_set.len() < max_active {
            let Some(group) = pending.next() else {
                break;
            };
            spawn_tracked_verify_task(&mut join_set, &mut task_groups, shared.clone(), group);
        }

        let mut out = Vec::with_capacity(total);
        while let Some(result) = join_set.join_next_with_id().await {
            match result {
                Ok((task_id, finding)) => {
                    task_groups.remove(&task_id);
                    out.push(finding);
                }
                Err(join_error) => {
                    if let Some(finding) = finding_for_join_error(join_error, &mut task_groups) {
                        out.push(finding);
                    }
                }
            }
            if let Some(group) = pending.next() {
                spawn_tracked_verify_task(&mut join_set, &mut task_groups, shared.clone(), group);
            }
        }
        out
    }

    /// Enable out-of-band callback verification for detectors with
    /// `[detector.verify.oob]`. Registers a fresh interactsh session against
    /// the configured collector and starts the polling loop. Subsequent
    /// `verify_all` calls will mint per-finding callback URLs and combine
    /// HTTP success criteria with OOB observations per the detector's policy.
    ///
    /// Idempotent: a second call replaces the previous session (the old one
    /// is shut down). Errors here do *not* abort the engine - call sites
    /// log + continue with OOB disabled rather than failing the whole scan.
    pub async fn enable_oob(
        &mut self,
        config: crate::oob::OobConfig,
    ) -> Result<(), crate::oob::InteractshError> {
        if let Some(old) = self.oob_session.take() {
            old.shutdown().await;
        }
        let session = crate::oob::OobSession::start_with_network_policy(
            self.client.clone(),
            config,
            self.timeout,
            self.proxy_in_use,
            self.insecure_tls,
        )
        .await?;
        self.oob_session = Some(session);
        Ok(())
    }

    /// Tear down the OOB session if one is active. Idempotent. Call before
    /// dropping the engine to deregister cleanly with the collector.
    pub async fn shutdown_oob(&mut self) {
        if let Some(session) = self.oob_session.take() {
            session.shutdown().await;
        }
    }
}

impl Drop for VerificationEngine {
    fn drop(&mut self) {
        // Best-effort safety net: if the caller forgot to `shutdown_oob().await`
        // before dropping the engine, we still need to stop the background
        // poller - otherwise it keeps polling the collector indefinitely
        // even after the scan that produced it is gone, leaking a tokio
        // task and a network connection.
        //
        // We can't block on async cleanup in `Drop`, so we abort the
        // poller's join handle synchronously. The deregister POST is
        // skipped (the collector prunes inactive sessions on its own
        // retention timer), but the poller stops immediately.
        if let Some(session) = self.oob_session.take() {
            session.abort_poller_for_drop();
        }
    }
}
