//! Engine-scoped OOB session: one interactsh registration shared by every
//! verification, a background polling loop, and per-finding wait notifications.
//!
//! ## Design
//!
//! - **One registration per scan.** RSA-2048 keygen + register adds ~150ms
//!   startup; doing it per finding would burn 859× that. We register once at
//!   engine boot and mint per-finding URLs from the same correlation id.
//! - **Single poller.** A background `tokio::task` polls every
//!   `poll_interval` and fans interactions out to per-id `Notify` waiters.
//!   Findings that mint a URL but never get hit just time out; the poller
//!   doesn't care.
//! - **Bounded retention.** Observations are stored in a `DashMap` keyed by
//!   unique-id. A simple `pending` set tracks ids actually being awaited;
//!   once a finding observes its callback we drop the entry, and a periodic
//!   GC pass evicts ids older than `max_observation_age` so a long scan
//!   doesn't grow unbounded.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;
use reqwest::Client;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use super::client::{Interaction, InteractionProtocol, InteractshClient};
use super::InteractshError;

/// Format an [`InteractshError`] for log output WITHOUT including the
/// underlying reqwest URL. reqwest::Error's Display embeds the full
/// request URL, and the interactsh poll URL contains the session
/// secret as a query parameter (`?secret=<session-secret>`). A naive
/// `error = %e` log therefore leaks the secret to anyone who can
/// read tracing output. Strip to error category only for transport
/// failures; pass through for other variants whose Display is safe.
/// Redact interactsh transport errors for safe logging. Exposed for contract tests.
pub fn redact_interactsh_error(e: &InteractshError) -> String {
    match e {
        InteractshError::Transport(req_err) => {
            // Build a category-only description: kind (connect/timeout/etc)
            // plus the root cause's Display if it's a non-reqwest error type.
            let kind = if req_err.is_connect() {
                "connect"
            } else if req_err.is_timeout() {
                "timeout"
            } else if req_err.is_request() {
                "request"
            } else if req_err.is_body() {
                "body"
            } else if req_err.is_decode() {
                "decode"
            } else if req_err.is_status() {
                "status"
            } else {
                "transport"
            };
            format!("interactsh transport error: kind={kind} (url redacted)")
        }
        // Every other variant's Display is hand-written and contains no URL.
        other => format!("{other}"),
    }
}

/// Runtime configuration for the OOB session. Surfaced through the CLI as
/// `--verify-oob`, `--oob-server`, `--oob-timeout`.
#[derive(Debug, Clone)]
pub struct OobConfig {
    /// Interactsh server. Default `oast.fun` (projectdiscovery's public
    /// collector). Self-host for sensitive scans.
    pub server: String,
    /// Default per-finding wait timeout when the detector spec doesn't override.
    pub default_timeout: Duration,
    /// Hard cap on per-finding wait, regardless of spec. Bounds total scan time.
    pub max_timeout: Duration,
    /// How often the poller hits the collector.
    pub poll_interval: Duration,
    /// Drop observations older than this from memory. Long-running scans
    /// won't accumulate stale events.
    pub max_observation_age: Duration,
}

impl Default for OobConfig {
    fn default() -> Self {
        Self {
            server: "oast.fun".to_string(),
            default_timeout: Duration::from_secs(30),
            max_timeout: Duration::from_secs(120),
            poll_interval: Duration::from_secs(2),
            max_observation_age: Duration::from_secs(600),
        }
    }
}

/// What the verifier sees after waiting on a minted URL.
#[derive(Debug, Clone)]
pub enum OobObservation {
    Observed {
        protocol: InteractionProtocol,
        remote_address: String,
        timestamp: String,
        raw_payload: String,
    },
    /// Timed out before any matching interaction arrived.
    NotObserved,
    /// OOB session is unavailable (register failed, poller died). The verifier
    /// degrades to HTTP-only success criteria for this finding.
    Disabled(String),
}

struct StoredInteraction {
    interaction: Interaction,
    received_at: Instant,
}

/// Engine-shared OOB session. Wrap in `Arc` and share across verify tasks.
pub struct OobSession {
    client: Arc<InteractshClient>,
    config: OobConfig,
    /// id → all observed interactions for that id.
    ///
    /// One callback URL typically triggers a DNS lookup AND an HTTP request
    /// (DNS first, then HTTP to the resolved IP) - both arrive at interactsh
    /// with the same `unique_id` but different protocols. The previous
    /// first-write-wins storage discarded the second one, which silently
    /// turned `OobProtocol::Http` detectors into FNs whenever DNS happened
    /// to arrive first. We now store every interaction; `peek_match`
    /// filters by protocol at read time.
    observations: Arc<DashMap<String, Vec<StoredInteraction>>>,
    /// id → notify handle. Populated by `wait_for` before it parks; the
    /// poller signals on match. `Mutex<HashMap>` over a `DashMap` because
    /// we need atomic insert-and-check-existing; contention is bounded
    /// (one entry per in-flight finding, ~max_concurrent_global).
    waiters: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
    poller_handle: Mutex<Option<JoinHandle<()>>>,
    shutdown: Arc<AtomicBool>,
}

impl OobSession {
    /// Boot the session: register with the collector and spawn the poller.
    /// Errors here are surface-level - caller logs and continues with OOB
    /// disabled rather than aborting the scan.
    pub async fn start(
        http: Client,
        config: OobConfig,
    ) -> Result<Arc<Self>, super::InteractshError> {
        let client = InteractshClient::register(http, &config.server).await?;
        let client = Arc::new(client);
        info!(
            target: "keyhog::oob",
            correlation_id = %client.correlation_id(),
            server = %config.server,
            "OOB verification enabled"
        );
        let session = Arc::new(Self {
            client: Arc::clone(&client),
            config: config.clone(),
            observations: Arc::new(DashMap::new()),
            waiters: Arc::new(Mutex::new(HashMap::new())),
            poller_handle: Mutex::new(None),
            shutdown: Arc::new(AtomicBool::new(false)),
        });
        let handle = spawn_poller(Arc::clone(&session));
        *session.poller_handle.lock() = Some(handle);
        Ok(session)
    }

    /// Mint a URL for a finding-in-flight. Returns the host and full URL the
    /// caller should embed in the verification probe, plus the `unique_id`
    /// to pass to `wait_for`.
    pub fn mint(&self) -> super::client::MintedUrl {
        self.client.mint_url()
    }

    /// Default per-finding wait timeout. Detector specs override this via
    /// `[detector.verify.oob].timeout_secs`; the value is also clamped to
    /// `max_timeout` inside `wait_for`.
    pub fn config_default_timeout(&self) -> Duration {
        self.config.default_timeout
    }

    /// Park until an interaction arrives for `unique_id`, or `timeout`
    /// elapses, or shutdown - whichever comes first.
    pub async fn wait_for(
        &self,
        unique_id: &str,
        accepts: OobAccept,
        timeout: Duration,
    ) -> OobObservation {
        if self.shutdown.load(Ordering::Acquire) {
            return OobObservation::Disabled("session shut down".into());
        }
        let timeout = timeout.min(self.config.max_timeout);

        // Fast path: poller may have observed it before we got here.
        if let Some(obs) = self.peek_match(unique_id, accepts) {
            return obs;
        }

        let notify = {
            let mut waiters = self.waiters.lock();
            waiters
                .entry(unique_id.to_string())
                .or_insert_with(|| Arc::new(Notify::new()))
                .clone()
        };

        // Race we're closing:
        //
        //   t0  caller peek_match  →  no match
        //   t1  poller store_and_notify  →  observation inserted
        //   t2  poller fires notify_waiters() on the (existing) Notify
        //   t3  caller calls notify.notified().await
        //
        // `notify_waiters()` does NOT store a permit and only wakes
        // already-polled `Notified` futures. A future created at t3 was
        // never polled at t2, so it never received the wake. The caller
        // would then wait up to the full `timeout` window for a callback
        // that already arrived.
        //
        // `Notified::enable()` registers the waiter at the Notify without
        // polling. Any `notify_waiters()` after `enable()` returns is
        // guaranteed to wake the future on its next poll. We enable BEFORE
        // re-peeking observations so the sequence per loop iteration is:
        //
        //   1. Build a fresh notified future, enable() it (registers waiter).
        //   2. Re-peek observations - catches anything stored before step 1.
        //   3. await the notified future - catches anything stored after
        //      step 1 (because the waiter is already registered).
        //
        // The future is recreated at the top of each iteration so that
        // post-wakeup loops (e.g. notify fired but the protocol filter
        // rejected the observation) re-arm against future stores.
        let deadline = Instant::now() + timeout;
        loop {
            // Bail early if the session is shutting down. Without this check
            // a parked wait_for would sleep the full timeout (default 30 s)
            // after the engine's Drop fired - the shutdown path wakes
            // every parked waiter, but they need to re-check shutdown to
            // exit the loop instead of falling back into the next await.
            if self.shutdown.load(Ordering::Acquire) {
                self.waiters.lock().remove(unique_id);
                return OobObservation::Disabled("session shut down".into());
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.waiters.lock().remove(unique_id);
                return OobObservation::NotObserved;
            }

            let mut notified = std::pin::pin!(notify.notified());
            notified.as_mut().enable();

            if let Some(obs) = self.peek_match(unique_id, accepts) {
                self.waiters.lock().remove(unique_id);
                return obs;
            }

            let woken = tokio::time::timeout(remaining, notified.as_mut()).await;
            if let Some(obs) = self.peek_match(unique_id, accepts) {
                self.waiters.lock().remove(unique_id);
                return obs;
            }
            if woken.is_err() {
                self.waiters.lock().remove(unique_id);
                return OobObservation::NotObserved;
            }
            // Wakeup but no matching observation (e.g. wrong protocol filter,
            // or notify_waiters fired without a corresponding store). Loop
            // with a fresh notified future to re-arm.
        }
    }

    /// Best-effort shutdown: stop poller, wake parked waiters, deregister.
    /// Idempotent.
    pub async fn shutdown(self: &Arc<Self>) {
        if self.shutdown.swap(true, Ordering::AcqRel) {
            return;
        }
        self.wake_all_waiters();
        let handle = self.poller_handle.lock().take();
        if let Some(h) = handle {
            h.abort();
            let _ = h.await;
        }
        if let Err(e) = self.client.deregister().await {
            debug!(target: "keyhog::oob", error = %e, "deregister failed (non-fatal)");
        }
    }

    /// Synchronous abort path used from `VerificationEngine::Drop` when the
    /// caller forgot to `shutdown_oob().await`. We can't await deregister
    /// from a sync context, so we just stop the poller and wake every
    /// parked `wait_for` so they observe `shutdown=true` and return
    /// `Disabled` instead of sleeping the rest of their per-finding
    /// timeout. The collector prunes inactive sessions on its own
    /// retention timer.
    ///
    /// Idempotent. Once called, subsequent `wait_for` invocations return
    /// `Disabled("session shut down")`.
    pub fn abort_poller_for_drop(&self) {
        if self.shutdown.swap(true, Ordering::AcqRel) {
            return;
        }
        self.wake_all_waiters();
        if let Some(h) = self.poller_handle.lock().take() {
            h.abort();
            // No `.await` - the JoinHandle is dropped; the abort signal is
            // delivered asynchronously by the runtime.
        }
    }

    /// Wake every parked `wait_for` once. Each wakes, sees `shutdown=true`
    /// at the top of its loop, and returns `Disabled`. Drains the waiter
    /// table so a future store_and_notify (e.g. a poll-in-flight that
    /// resolves after shutdown) doesn't try to fire on a dead waiter.
    fn wake_all_waiters(&self) {
        let drained: Vec<Arc<Notify>> = {
            let mut waiters = self.waiters.lock();
            waiters.drain().map(|(_, n)| n).collect()
        };
        for notify in drained {
            notify.notify_waiters();
        }
    }

    fn peek_match(&self, unique_id: &str, accepts: OobAccept) -> Option<OobObservation> {
        let entries = self.observations.get(unique_id)?;
        // Earliest-matching-protocol wins. The poller stores in arrival
        // order, so the first matching entry is also the first one we
        // received with that protocol.
        let stored = entries
            .iter()
            .find(|s| accepts.matches(s.interaction.protocol))?;
        Some(OobObservation::Observed {
            protocol: stored.interaction.protocol,
            remote_address: stored.interaction.remote_address.clone(),
            timestamp: stored.interaction.timestamp.clone(),
            raw_payload: stored.interaction.raw_payload.clone(),
        })
    }

    fn store_and_notify(&self, interaction: Interaction) {
        let id = interaction.unique_id.clone();
        let stored = StoredInteraction {
            interaction,
            received_at: Instant::now(),
        };
        self.observations
            .entry(id.clone())
            .or_default()
            .push(stored);
        if let Some(notify) = self.waiters.lock().get(&id) {
            notify.notify_waiters();
        }
    }

    fn gc(&self) {
        let cutoff = Instant::now()
            .checked_sub(self.config.max_observation_age)
            .unwrap_or_else(Instant::now);
        // Drop stale per-id entries (Vec inside the map) first, then evict
        // any id whose Vec is now empty.
        self.observations.retain(|_, entries| {
            entries.retain(|stored| stored.received_at >= cutoff);
            !entries.is_empty()
        });
    }

    /// Test-only constructor that bypasses both the network registration and
    /// the background poller.
    pub fn for_test(client: Arc<InteractshClient>, config: OobConfig) -> Arc<Self> {
        Arc::new(Self {
            client,
            config,
            observations: Arc::new(DashMap::new()),
            waiters: Arc::new(Mutex::new(HashMap::new())),
            poller_handle: Mutex::new(None),
            shutdown: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Test-only accessor for driving notify paths from integration tests.
    pub fn store_and_notify_for_test(&self, interaction: super::client::Interaction) {
        self.store_and_notify(interaction);
    }
}

/// Filter for which interaction protocols satisfy a wait. Mirrors `OobProtocol`
/// in the spec but lives here to keep the verifier crate's domain clean.
#[derive(Debug, Clone, Copy)]
pub enum OobAccept {
    Dns,
    Http,
    Smtp,
    Any,
}

impl OobAccept {
    pub fn matches(self, p: InteractionProtocol) -> bool {
        matches!(
            (self, p),
            (Self::Any, _)
                | (Self::Dns, InteractionProtocol::Dns)
                | (Self::Http, InteractionProtocol::Http)
                | (Self::Smtp, InteractionProtocol::Smtp)
        )
    }
}

impl From<keyhog_core::OobProtocol> for OobAccept {
    fn from(p: keyhog_core::OobProtocol) -> Self {
        match p {
            keyhog_core::OobProtocol::Dns => Self::Dns,
            keyhog_core::OobProtocol::Http => Self::Http,
            keyhog_core::OobProtocol::Smtp => Self::Smtp,
            keyhog_core::OobProtocol::Any => Self::Any,
        }
    }
}

fn spawn_poller(session: Arc<OobSession>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut consecutive_errors = 0u32;
        let mut next_gc = Instant::now() + Duration::from_secs(60);
        loop {
            if session.shutdown.load(Ordering::Acquire) {
                break;
            }
            match session.client.poll().await {
                Ok(interactions) => {
                    consecutive_errors = 0;
                    for interaction in interactions {
                        session.store_and_notify(interaction);
                    }
                }
                Err(e) => {
                    consecutive_errors += 1;
                    // Backoff progressively, but cap so we don't go silent for
                    // ages on a flaky collector.
                    let backoff_secs = (1u64 << consecutive_errors.min(5)).min(30);
                    // CREDENTIAL LEAK FIX: reqwest::Error's Display includes
                    // the request URL, which for the interactsh poll is
                    // `https://oast.fun/poll?id=<corr>&secret=<session-secret>`.
                    // Logging the raw error therefore writes the interactsh
                    // session secret to tracing - possession of that secret
                    // lets anyone poll the collector for this scan's OOB
                    // interactions. Redact to error kind only; the operator
                    // doesn't need the URL to diagnose connectivity issues.
                    // Kimi verifier-audit finding #2 (MED).
                    let redacted = redact_interactsh_error(&e);
                    warn!(
                        target: "keyhog::oob",
                        error = %redacted,
                        consecutive_errors,
                        backoff_secs,
                        "interactsh poll failed; backing off"
                    );
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    continue;
                }
            }
            if Instant::now() >= next_gc {
                session.gc();
                next_gc = Instant::now() + Duration::from_secs(60);
            }
            tokio::time::sleep(session.config.poll_interval).await;
        }
        debug!(target: "keyhog::oob", "poller exiting");
    })
}
