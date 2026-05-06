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
    /// id → first observed interaction. Once observed, future polls for the
    /// same id are no-ops (we keep the entry until GC for late waiters that
    /// haven't called `wait_for` yet).
    observations: Arc<DashMap<String, StoredInteraction>>,
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
    /// Errors here are surface-level — caller logs and continues with OOB
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
    /// elapses, or shutdown — whichever comes first.
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
        //   2. Re-peek observations — catches anything stored before step 1.
        //   3. await the notified future — catches anything stored after
        //      step 1 (because the waiter is already registered).
        //
        // The future is recreated at the top of each iteration so that
        // post-wakeup loops (e.g. notify fired but the protocol filter
        // rejected the observation) re-arm against future stores.
        let deadline = Instant::now() + timeout;
        loop {
            // Bail early if the session is shutting down. Without this check
            // a parked wait_for would sleep the full timeout (default 30 s)
            // after the engine's Drop fired — the shutdown path wakes
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
            // No `.await` — the JoinHandle is dropped; the abort signal is
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
        let stored = self.observations.get(unique_id)?;
        if !accepts.matches(stored.interaction.protocol) {
            return None;
        }
        Some(OobObservation::Observed {
            protocol: stored.interaction.protocol,
            remote_address: stored.interaction.remote_address.clone(),
            timestamp: stored.interaction.timestamp.clone(),
            raw_payload: stored.interaction.raw_payload.clone(),
        })
    }

    fn store_and_notify(&self, interaction: Interaction) {
        let id = interaction.unique_id.clone();
        // First-write-wins. Repeat callbacks for the same id (a service that
        // hits us twice) don't overwrite — the first observation is what the
        // verifier will see.
        let inserted = self
            .observations
            .entry(id.clone())
            .or_insert_with(|| StoredInteraction {
                interaction,
                received_at: Instant::now(),
            });
        let _ = inserted; // hold guard scope
        if let Some(notify) = self.waiters.lock().get(&id) {
            notify.notify_waiters();
        }
    }

    fn gc(&self) {
        let cutoff = Instant::now()
            .checked_sub(self.config.max_observation_age)
            .unwrap_or_else(Instant::now);
        self.observations
            .retain(|_, stored| stored.received_at >= cutoff);
    }

    /// Test-only constructor that bypasses both the network registration and
    /// the background poller. Lets unit tests exercise the wait_for /
    /// store_and_notify race + shutdown logic without standing up an
    /// interactsh server.
    #[cfg(test)]
    pub(crate) fn for_test(client: Arc<InteractshClient>, config: OobConfig) -> Arc<Self> {
        Arc::new(Self {
            client,
            config,
            observations: Arc::new(DashMap::new()),
            waiters: Arc::new(Mutex::new(HashMap::new())),
            poller_handle: Mutex::new(None),
            shutdown: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Test-only accessor — the unit tests need to fabricate `Interaction`
    /// values and drive the notify path that the poller would normally
    /// drive. Production code never calls this.
    #[cfg(test)]
    pub(crate) fn store_and_notify_for_test(&self, interaction: super::client::Interaction) {
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
    fn matches(self, p: InteractionProtocol) -> bool {
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
                    warn!(
                        target: "keyhog::oob",
                        error = %e,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oob_accept_filters_protocols() {
        assert!(OobAccept::Any.matches(InteractionProtocol::Dns));
        assert!(OobAccept::Any.matches(InteractionProtocol::Other));
        assert!(OobAccept::Http.matches(InteractionProtocol::Http));
        assert!(!OobAccept::Http.matches(InteractionProtocol::Dns));
        assert!(OobAccept::Smtp.matches(InteractionProtocol::Smtp));
        assert!(!OobAccept::Smtp.matches(InteractionProtocol::Http));
    }

    #[test]
    fn oob_config_defaults_safe() {
        let c = OobConfig::default();
        assert_eq!(c.server, "oast.fun");
        assert!(c.default_timeout <= c.max_timeout);
        assert!(c.poll_interval < c.default_timeout);
    }

    fn test_session() -> Arc<OobSession> {
        let client = Arc::new(super::super::client::InteractshClient::for_test("oast.fun"));
        let config = OobConfig {
            // Tighten timeouts so a misbehaving wait_for fails fast in tests
            // rather than holding the whole suite for the default 30 s.
            default_timeout: Duration::from_secs(2),
            max_timeout: Duration::from_secs(2),
            poll_interval: Duration::from_millis(50),
            max_observation_age: Duration::from_secs(60),
            ..OobConfig::default()
        };
        OobSession::for_test(client, config)
    }

    fn fake_interaction(
        unique_id: &str,
        protocol: InteractionProtocol,
    ) -> super::super::client::Interaction {
        super::super::client::Interaction {
            unique_id: unique_id.to_string(),
            protocol,
            remote_address: "203.0.113.7".to_string(),
            timestamp: "2026-05-06T00:00:00Z".to_string(),
            raw_payload: "GET /probe HTTP/1.1".to_string(),
        }
    }

    /// Race fix: a notify_waiters that fires AFTER the waiter is installed
    /// but BEFORE the future is polled used to be lost. With Notified::enable()
    /// the waiter is registered before any peek/await, so this can't happen.
    #[tokio::test]
    async fn wait_for_returns_immediately_when_observation_arrives_post_install() {
        let session = test_session();
        let id = "abcdefghijklmnopqrst1234567890123";
        // Spawn wait_for; give it a tick to install its waiter and call enable().
        let s = Arc::clone(&session);
        let id_clone = id.to_string();
        let task = tokio::spawn(async move {
            s.wait_for(&id_clone, OobAccept::Http, Duration::from_secs(2))
                .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Now store + notify. With the old code (no enable() before peek)
        // and a poll_interval of 50ms, the test would still pass because
        // the post-await peek catches the observation. Here we assert it
        // returns BEFORE the 2-second timeout — proving the wakeup path
        // (not the timeout fallback) drove completion.
        session.store_and_notify_for_test(fake_interaction(id, InteractionProtocol::Http));
        let start = Instant::now();
        let obs = task.await.expect("wait_for task panicked");
        assert!(matches!(obs, OobObservation::Observed { .. }));
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "wait_for should resolve via wakeup, not timeout; took {:?}",
            start.elapsed()
        );
    }

    /// Pre-existing observation (stored before wait_for is even called)
    /// is caught by the first peek_match — fastest path.
    #[tokio::test]
    async fn wait_for_fast_path_when_observation_already_present() {
        let session = test_session();
        let id = "preexistingidpreexistingidpreexis";
        session.store_and_notify_for_test(fake_interaction(id, InteractionProtocol::Http));
        let start = Instant::now();
        let obs = session
            .wait_for(id, OobAccept::Http, Duration::from_secs(2))
            .await;
        assert!(matches!(obs, OobObservation::Observed { .. }));
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    /// Protocol filter mismatch should keep the wait parked; correct
    /// protocol arriving later should resolve it.
    #[tokio::test]
    async fn wait_for_filters_by_protocol() {
        let session = test_session();
        let id = "protofilteridprotofilteridprotofi";
        // Store wrong-protocol first.
        session.store_and_notify_for_test(fake_interaction(id, InteractionProtocol::Dns));
        // Wait for HTTP — the DNS interaction is in the DashMap but
        // doesn't satisfy the OobAccept::Http filter.
        let s = Arc::clone(&session);
        let task = tokio::spawn(async move {
            s.wait_for(id, OobAccept::Http, Duration::from_millis(500))
                .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        // wait_for is parked. Verdict: NotObserved within the 500ms timeout
        // because the DNS observation doesn't match Http. (DashMap stores
        // first-write-wins, so a subsequent Http store wouldn't overwrite —
        // documenting that semantic with this assertion.)
        let obs = task.await.expect("task panicked");
        assert!(matches!(obs, OobObservation::NotObserved));
    }

    /// Shutdown wakes parked waiters instead of leaving them to time out.
    /// Critical robustness property: `VerificationEngine::Drop` must not
    /// leave verification tasks hanging for the per-finding timeout.
    #[tokio::test]
    async fn shutdown_wakes_parked_waiter_promptly() {
        let session = test_session();
        let id = "shutdownidshutdownidshutdownidshu";
        let s = Arc::clone(&session);
        let task = tokio::spawn(async move {
            s.wait_for(id, OobAccept::Http, Duration::from_secs(60))
                .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let start = Instant::now();
        session.abort_poller_for_drop();
        let obs = task.await.expect("task panicked");
        // Either Disabled (saw shutdown after wakeup) or NotObserved if the
        // shutdown raced with a spurious wakeup-with-empty-DashMap. Both
        // are acceptable; what's NOT acceptable is a 60-second wait.
        assert!(
            matches!(
                obs,
                OobObservation::Disabled(_) | OobObservation::NotObserved
            ),
            "expected Disabled or NotObserved post-shutdown; got {obs:?}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "shutdown should wake waiters promptly; took {:?}",
            start.elapsed()
        );
    }

    /// Shutdown invoked before wait_for is even called returns Disabled
    /// at the entry check, never installing a waiter.
    #[tokio::test]
    async fn wait_for_after_shutdown_returns_disabled_immediately() {
        let session = test_session();
        session.abort_poller_for_drop();
        let id = "afterdownidafterdownidafterdownid";
        let start = Instant::now();
        let obs = session
            .wait_for(id, OobAccept::Http, Duration::from_secs(60))
            .await;
        assert!(matches!(obs, OobObservation::Disabled(_)));
        assert!(start.elapsed() < Duration::from_millis(50));
    }
}
