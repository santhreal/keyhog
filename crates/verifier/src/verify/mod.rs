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
mod aws;
mod credential;
mod multi_step;
mod request;
mod response;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use futures_util::FutureExt;
use keyhog_core::{SensitiveString, VerificationResult, VerifiedFinding};
use reqwest::Client;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinSet;

use crate::cache;
use crate::{into_finding, DedupedMatch, VerificationEngine, VerifyConfig, VerifyError};

pub(crate) use aws::{build_aws_probe, parse_aws_sts_success_metadata};
pub(crate) use credential::{
    retry_delay_bounds_for_attempt, retry_loop_preserves_metadata_on_exhaustion_for_test,
    verify_with_retry, VerificationAttempt,
};
pub(crate) use request::{
    apply_header_body_templates, build_request_for_step, clear_pinned_client_cache_for_test,
    pinned_client_cache_len_for_host_for_test, pinned_client_cache_len_for_test,
    pinned_client_for_test, resolved_client_for_url, ssrf_check_url_with_resolved_addrs_for_test,
    RequestBuildResult,
};
pub(crate) use response::{
    body_indicates_error, evaluate_success, execute_and_read_response, extract_metadata,
};

const DEFAULT_SERVICE_CONCURRENCY: usize = 5;

#[derive(Clone)]
struct VerifyTaskShared {
    global_semaphore: Arc<Semaphore>,
    service_semaphores: Arc<HashMap<Arc<str>, Arc<Semaphore>>>,
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
            let reason = e
                .downcast_ref::<&str>()
                .map(|s| format!("verification task panicked: {s}"))
                .unwrap_or_else(|| "verification task panicked".to_string()); // LAW10: missing/non-string field => empty/placeholder; recall-safe
            tracing::error!(reason);
            into_finding(
                group_for_error,
                VerificationResult::Error(reason),
                HashMap::new(),
            )
        }
    }
}

/// Drain every task from `join_set`, and after each completion pull the next
/// task (if any) from `next` and spawn it, until the set is empty. Returns the
/// collected outputs in completion order.
///
/// A `JoinError` (the task was cancelled, or the runtime is shutting down) is
/// surfaced via `tracing::error!` and SKIPPED — the drain CONTINUES rather than
/// breaking, so one lost task never truncates the still-pending work. Callers'
/// per-task bodies catch their own panics (`verify_group_task_safe`), so in
/// normal operation the error arm is unreachable; it exists to fail
/// loud-and-complete, never silent-and-truncated, on abnormal termination. The
/// loop is generic so it is unit-testable with controllable tasks (an aborted
/// task must not drop the others) — see `drain_join_set_continues_past_cancel`.
// `pub` only so the `#[doc(hidden)] crate::testing` facade can re-export it for
// the tests/ drain-continuation gate (verifier src forbids inline test modules,
// KH-GAP-004); `mod verify` is private, so it is not otherwise reachable — same
// pattern as `format_sigv4_timestamps`.
pub async fn drain_join_set<T, F, Fut>(
    mut join_set: JoinSet<T>,
    capacity: usize,
    mut next: F,
) -> Vec<T>
where
    T: Send + 'static,
    F: FnMut() -> Option<Fut>,
    Fut: std::future::Future<Output = T> + Send + 'static,
{
    let mut out = Vec::with_capacity(capacity);
    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(value) => out.push(value),
            Err(join_error) => {
                tracing::error!(
                    %join_error,
                    "a verification task failed to join (cancelled or runtime \
                     shutting down); continuing the drain so the remaining tasks \
                     still complete"
                );
            }
        }
        if let Some(fut) = next() {
            join_set.spawn(fut);
        }
    }
    out
}

async fn verify_group_task(shared: VerifyTaskShared, group: DedupedMatch) -> VerifiedFinding {
    let global = shared.global_semaphore;
    let service_sem = shared
        .service_semaphores
        .get(&*group.service)
        .cloned()
        .unwrap_or_else(|| Arc::new(Semaphore::new(DEFAULT_SERVICE_CONCURRENCY))); // LAW10: absent config => documented default; Tier-A knob, recall-irrelevant
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
        let notify_to_await: Option<Arc<Notify>> = {
            // Inflight dedup via DashMap: per-shard locks instead of one
            // global parking_lot::Mutex held across HashMap operations in an
            // async context (anti-pattern that stalled the tokio runtime
            // under high concurrency - see legendary-2026-04-26).
            let key = (group.detector_id.clone(), group.credential.clone());
            if let Some((cached_result, cached_meta)) =
                cache.get(&group.credential, &group.detector_id)
            {
                return into_finding(group, cached_result, cached_meta);
            }

            match inflight.entry(key.clone()) {
                dashmap::mapref::entry::Entry::Occupied(entry) => Some(entry.get().clone()),
                dashmap::mapref::entry::Entry::Vacant(entry) => {
                    if !try_reserve_inflight_slot(&inflight_count, max_inflight_keys) {
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

        if let Some(notify) = notify_to_await {
            notify.notified().await;
        } else {
            break None;
        }
    };

    let (verification, metadata) =
        if let Some(verify_spec) = detector.as_ref().and_then(|det| det.verify.as_ref()) {
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

    cache.put(
        &group.credential,
        &group.detector_id,
        verification.clone(),
        metadata.clone(),
    );

    into_finding(group, verification, metadata)
}

impl VerificationEngine {
    /// Create a verifier with shared HTTP client, cache, and concurrency controls.
    pub fn new(
        detectors: &[keyhog_core::DetectorSpec],
        config: VerifyConfig,
    ) -> Result<Self, VerifyError> {
        let mut builder = Client::builder()
            .timeout(config.timeout)
            // Cert validation: ON by default, escape hatch ONLY through the
            // explicit `VerifyConfig.insecure_tls` knob (set by the `--insecure`
            // flag or `.keyhog.toml`; no env var can flip it — config mandate).
            // Production paths never flip this.
            .danger_accept_invalid_certs(config.insecure_tls)
            // Decompression-bomb defense-in-depth: the 1 MB streaming cap in
            // `read_response_body` only measures REAL wire bytes if reqwest
            // never inflates a `Content-Encoding: gzip|br|deflate` body before
            // our cap counts a byte. The crate is already compiled without the
            // `gzip`/`brotli`/`deflate` features (pinned by
            // `verifier_reqwest_has_no_auto_decompression_feature`), so today
            // these are no-ops — but calling them explicitly makes the
            // guarantee load-bearing AT THE CALL SITE: if a future Cargo.toml
            // edit turns a decompression feature on, auto-inflate stays OFF
            // here and the cap keeps measuring wire bytes. Belt-and-suspenders,
            // not a substitute for the feature pin.
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .redirect(reqwest::redirect::Policy::none());
        builder = crate::apply_proxy_config(builder, config.proxy.as_deref())
            .map_err(VerifyError::ProxyConfig)?;
        let client = builder.build().map_err(VerifyError::ClientBuild)?;

        let detector_map: HashMap<Arc<str>, keyhog_core::DetectorSpec> = detectors
            .iter()
            .cloned()
            .map(|d| (d.id.clone().into(), d))
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

        while join_set.len() < max_active {
            let Some(group) = pending.next() else {
                break;
            };
            join_set.spawn(verify_group_task_safe(shared.clone(), group));
        }

        // Drain every task, refilling from `pending` after each completion. The
        // drain is extracted into `drain_join_set` so its `JoinError` arm — only
        // reachable on task cancellation / runtime shutdown, since the per-task
        // body is panic-safe via `catch_unwind` — is unit-testable: one lost
        // task must never truncate the remaining work. The previous
        // `while let Some(Ok(_))` silently dropped every still-`pending` group on
        // the first such error.
        drain_join_set(join_set, total, move || {
            pending
                .next()
                .map(|group| verify_group_task_safe(shared.clone(), group))
        })
        .await
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
