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
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use keyhog_core::{VerificationResult, VerifiedFinding};
use reqwest::Client;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinSet;

use crate::cache;
use crate::{into_finding, DedupedMatch, VerificationEngine, VerifyConfig, VerifyError};

pub(crate) use aws::build_aws_probe;
pub use aws::format_sigv4_timestamps;
pub(crate) use credential::{verify_with_retry, VerificationAttempt};
pub(crate) use request::{
    build_request_for_step, execute_request, resolved_client_for_url, RequestBuildResult,
};
pub(crate) use response::{
    body_indicates_error, evaluate_success, extract_metadata, read_response_body,
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
    inflight: Arc<DashMap<(Arc<str>, Arc<str>), Arc<Notify>>>,
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
    key: (Arc<str>, Arc<str>),
    inflight: Arc<DashMap<(Arc<str>, Arc<str>), Arc<Notify>>>,
    notify: Arc<Notify>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        // DashMap's per-shard locking means this never blocks a tokio worker
        // for more than the time to mutate one shard - orders of magnitude
        // less than the previous global parking_lot::Mutex which was held
        // across the entire HashMap traversal in the await loop.
        self.inflight.remove(&self.key);
        self.notify.notify_waiters();
    }
}

async fn verify_group_task(shared: VerifyTaskShared, group: DedupedMatch) -> VerifiedFinding {
    let global = shared.global_semaphore;
    let service_sem = shared
        .service_semaphores
        .get(&*group.service)
        .cloned()
        .unwrap_or_else(|| Arc::new(Semaphore::new(DEFAULT_SERVICE_CONCURRENCY)));
    let client = shared.client;
    let detector = shared.detectors.get(&*group.detector_id).cloned();
    let timeout = shared.timeout;

    let cache = shared.cache;
    let inflight = shared.inflight;
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
            if inflight.len() >= max_inflight_keys {
                break None;
            }

            let key = (group.detector_id.clone(), group.credential.clone());
            if let Some((cached_result, cached_meta)) =
                cache.get(&group.credential, &group.detector_id)
            {
                return into_finding(group, cached_result, cached_meta);
            }

            match inflight.entry(key.clone()) {
                dashmap::mapref::entry::Entry::Occupied(entry) => Some(entry.get().clone()),
                dashmap::mapref::entry::Entry::Vacant(entry) => {
                    let notify = Arc::new(Notify::new());
                    entry.insert(notify.clone());
                    break Some(InflightGuard {
                        key,
                        inflight: inflight.clone(),
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

    let (verification, metadata) = if let Some(custom_verifier) =
        keyhog_core::registry::get_verifier_registry().get(&group.detector_id)
    {
        custom_verifier.verify(&group).await
    } else {
        match &detector {
            Some(det) => match &det.verify {
                Some(verify_spec) => {
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
                        shared.oob_session.as_ref(),
                    )
                    .await
                }
                None => (VerificationResult::Unverifiable, HashMap::new()),
            },
            None => (VerificationResult::Unverifiable, HashMap::new()),
        }
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
            // explicit `VerifyConfig.insecure_tls` knob (or `KEYHOG_INSECURE_TLS`
            // via CLI). Production paths never flip this.
            .danger_accept_invalid_certs(config.insecure_tls)
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
            max_inflight_keys: config.max_inflight_keys.max(1),
            danger_allow_private_ips: config.danger_allow_private_ips,
            danger_allow_http: config.danger_allow_http,
            insecure_tls: config.insecure_tls,
            // Issue #2 + #3 fix: don't conflate "configured to set a proxy
            // policy" with "a proxy is actively routing traffic."
            // `proxy_is_active` resolves the documented `KEYHOG_PROXY` sentinels
            // (`off`/`none`/empty) AND accounts for reqwest's standard
            // `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` env vars that the
            // shared client honors via reqwest defaults. proxy_in_use gates
            // DNS-pinning rebuild in resolved_client_for_url(); a wrong value
            // either:
            //   #2: disables DNS pinning when no proxy is actually active
            //       (KEYHOG_PROXY=off counted as active → rebuild skipped
            //       → DNS-rebinding protection silently removed)
            //   #3: keeps DNS pinning on a path that drops env-proxy +
            //       insecure_tls config (HTTPS_PROXY invisible to the
            //       rebuild branch → verifier connects direct → operator
            //       interception/audit bypassed)
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
            max_inflight_keys: self.max_inflight_keys,
            danger_allow_private_ips: self.danger_allow_private_ips,
            danger_allow_http: self.danger_allow_http,
            insecure_tls: self.insecure_tls,
            proxy_in_use: self.proxy_in_use,
            oob_session: self.oob_session.clone(),
        };
        let mut pending = groups.into_iter();
        let mut join_set = JoinSet::new();

        while join_set.len() < max_active {
            let Some(group) = pending.next() else {
                break;
            };
            join_set.spawn(verify_group_task(shared.clone(), group));
        }

        let mut findings = Vec::with_capacity(total);
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(finding) => findings.push(finding),
                Err(e) => tracing::error!("verification task panicked: {}", e),
            }

            if let Some(group) = pending.next() {
                join_set.spawn(verify_group_task(shared.clone(), group));
            }
        }
        findings
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
        let session = crate::oob::OobSession::start(self.client.clone(), config).await?;
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
