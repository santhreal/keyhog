//! Per-service rate limiting for verification requests.
//!
//! `RateLimiter` enforces a minimum inter-request interval per service
//! (token-bucket-style with a 1-token bucket). Per-service entries can
//! override the default interval via [`RateLimiter::update_limit`]; the
//! default interval is hot-swappable at runtime via
//! [`RateLimiter::set_default_rps`] so the CLI's `--verify-rate` flag
//! can take effect after the global limiter has already been
//! lazily initialised by an earlier call site.
use dashmap::DashMap;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Aggregate transient-error count above which global backpressure engages,
/// injecting [`GLOBAL_BACKPRESSURE_PENALTY`] per request until successes drain
/// the counter back down. Hoisted to a single named owner (was an inline `> 50`
/// / `from_secs(1)` pair). Tier-A CLI/TOML tuning is tracked separately.
const GLOBAL_BACKPRESSURE_ERROR_THRESHOLD: usize = 50;
const GLOBAL_BACKPRESSURE_PENALTY: Duration = Duration::from_secs(1);

/// Per-service AIMD backoff (single named owners; Tier-A CLI/TOML tuning tracked
/// separately). A `429 Too Many Requests` for a service MULTIPLICATIVELY DECREASES
/// its rate (interval `*= RATE_LIMIT_BACKOFF_MULTIPLIER`, capped at
/// `RATE_LIMIT_MAX_INTERVAL`); each subsequent SUCCESSFUL round-trip
/// ADDITIVELY INCREASES the rate back (interval `-= base/RATE_LIMIT_RECOVERY_STEP_DIVISOR`,
/// floored at the configured `base_interval`). This is the classic AIMD shape:
/// back off fast when throttled, recover gently so the service is not immediately
/// re-throttled. It replaces the previous `update_limit(service, 0.5)` hard-set,
/// which pinned a service to 0.5 rps forever after a single 429 and NEVER
/// recovered even after thousands of successes (Law 7: a permanently throttled
/// verifier is a throughput bug).
const RATE_LIMIT_BACKOFF_MULTIPLIER: u32 = 2;
/// Slowest per-service pace under sustained throttling (~0.125 rps). The ceiling
/// is `max(this, base_interval)` so a service configured slower than this is
/// never sped up by the cap.
const RATE_LIMIT_MAX_INTERVAL: Duration = Duration::from_secs(8);
/// Additive-increase granularity: each success recovers `base_interval / this` of
/// the backoff, so one doubling heals in `this` successes (gentle, monotone).
const RATE_LIMIT_RECOVERY_STEP_DIVISOR: u32 = 2;

struct ServiceLimit {
    last_request: Instant,
    /// Current working inter-request interval (AIMD-adjusted: `>= base_interval`,
    /// grows on 429, shrinks back on success).
    interval: Duration,
    /// Configured target interval — the FASTEST (smallest) pace for this service
    /// and the floor AIMD recovery returns to. Set at creation / `update_limit`.
    base_interval: Duration,
}

pub struct RateLimiter {
    services: DashMap<String, Mutex<ServiceLimit>>,
    /// Default inter-request interval, in nanoseconds. Atomic so the
    /// CLI can adjust the global limiter's pace after construction
    /// without having to thread a setter through every caller.
    default_interval_nanos: AtomicU64,
    global_error_count: AtomicUsize,
}

impl RateLimiter {
    pub fn new(rps: f64) -> Self {
        Self {
            services: DashMap::new(),
            default_interval_nanos: AtomicU64::new(rps_to_nanos(rps)),
            global_error_count: AtomicUsize::new(0),
        }
    }

    /// Replace the default per-service interval. Existing per-service
    /// entries created via [`Self::update_limit`] are left at their
    /// override; only the lazily-created defaults pick up the new pace.
    /// Non-finite or non-positive `rps` falls back to 1.0 - the same
    /// guard as `new()` so a caller can't drive the limiter into a
    /// zero-interval (= infinite-rate) state by accident.
    pub fn set_default_rps(&self, rps: f64) {
        self.default_interval_nanos
            .store(rps_to_nanos(rps), Ordering::Relaxed);
    }

    /// Default interval as a `Duration`. Lock-free.
    pub fn default_interval(&self) -> Duration {
        Duration::from_nanos(self.default_interval_nanos.load(Ordering::Relaxed))
    }

    pub async fn wait(&self, service: &str) {
        let bp = if self.global_error_count.load(Ordering::Relaxed)
            > GLOBAL_BACKPRESSURE_ERROR_THRESHOLD
        {
            GLOBAL_BACKPRESSURE_PENALTY
        } else {
            Duration::ZERO
        };
        let wait_time = {
            let default = self.default_interval();
            if let Some(entry) = self.services.get(service) {
                let mut limit = entry.value().lock();
                reserve_service_slot(&mut limit, Instant::now())
            } else {
                let inserted = self.services.entry(service.to_string()).or_insert_with(|| {
                    Mutex::new(ServiceLimit {
                        last_request: initial_last_request(Instant::now(), default),
                        interval: default,
                        base_interval: default,
                    })
                });
                let mut limit = inserted.value().lock();
                reserve_service_slot(&mut limit, Instant::now())
            }
        };
        let delay = match wait_time {
            Some(wait) => wait.max(bp),
            None => bp,
        };
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    pub fn record_error(&self) {
        self.global_error_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_success(&self) {
        let _ = self // LAW10: unused-binding marker; no runtime effect, not a fallback
            .global_error_count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(1))
            });
    }

    pub(crate) fn error_count_for_test(&self) -> usize {
        self.global_error_count.load(Ordering::Relaxed)
    }

    /// Configure a service's TARGET rate (the `base_interval` AIMD recovers to).
    /// A config change resets any in-flight backoff: `interval == base_interval`.
    pub async fn update_limit(&self, service: &str, rps: f64) {
        let interval = Duration::from_nanos(rps_to_nanos(rps));
        self.services.insert(
            service.to_string(),
            Mutex::new(ServiceLimit {
                last_request: Instant::now(),
                interval,
                base_interval: interval,
            }),
        );
    }

    /// Multiplicative-decrease: a `429` for `service` slows it by
    /// [`RATE_LIMIT_BACKOFF_MULTIPLIER`], capped at
    /// `max(RATE_LIMIT_MAX_INTERVAL, base_interval)` (never faster than the
    /// configured base). If the service has no slot yet, one is created at the
    /// default pace already backed off once. Takes effect on the next
    /// [`Self::wait`]. Recovery is driven by [`Self::reward_service`] on success.
    pub fn penalize_service(&self, service: &str) {
        if let Some(entry) = self.services.get(service) {
            let mut limit = entry.value().lock();
            let ceiling = RATE_LIMIT_MAX_INTERVAL.max(limit.base_interval);
            limit.interval = limit
                .interval
                .checked_mul(RATE_LIMIT_BACKOFF_MULTIPLIER)
                .unwrap_or(ceiling)
                .min(ceiling);
        } else {
            let default = self.default_interval();
            let ceiling = RATE_LIMIT_MAX_INTERVAL.max(default);
            let interval = default
                .checked_mul(RATE_LIMIT_BACKOFF_MULTIPLIER)
                .unwrap_or(ceiling)
                .min(ceiling);
            self.services.entry(service.to_string()).or_insert_with(|| {
                Mutex::new(ServiceLimit {
                    last_request: Instant::now(),
                    interval,
                    base_interval: default,
                })
            });
        }
    }

    /// Additive-increase: a successful round-trip for `service` recovers
    /// `base_interval / RATE_LIMIT_RECOVERY_STEP_DIVISOR` of its backoff, floored
    /// at `base_interval` (never faster than configured). No-op when the service
    /// has no slot or is already at base — cheap to call on every success.
    pub fn reward_service(&self, service: &str) {
        if let Some(entry) = self.services.get(service) {
            let mut limit = entry.value().lock();
            if limit.interval > limit.base_interval {
                let step = limit.base_interval / RATE_LIMIT_RECOVERY_STEP_DIVISOR;
                limit.interval = limit.interval.saturating_sub(step).max(limit.base_interval);
            }
        }
    }

    /// Current working inter-request interval for `service`, or `None` if the
    /// service has no slot yet. Introspection of the live AIMD state (used by the
    /// recovery regression test and available for operator diagnostics).
    pub fn service_interval(&self, service: &str) -> Option<Duration> {
        self.services
            .get(service)
            .map(|entry| entry.value().lock().interval)
    }
}

/// Initial `last_request` for a freshly-created service slot: one interval in
/// the past so the very first request is admitted immediately (`next_slot =
/// last_request + interval = now`). On a host with very low uptime (a fresh
/// container, where `Instant::now()` can be *less than* `interval` from the
/// monotonic clock's origin) a plain `now - interval` underflows and PANICS.
/// `checked_sub` clamps to `now` instead: the first request then waits one
/// interval — a one-off politeness delay, never a correctness or security
/// regression, and never a panic.
pub(crate) fn initial_last_request(now: Instant, interval: Duration) -> Instant {
    now.checked_sub(interval).unwrap_or(now)
}

fn reserve_service_slot(limit: &mut ServiceLimit, now: Instant) -> Option<Duration> {
    // `last_request` is the start of the most-recent SLOT (real or
    // reserved-for-an-in-flight-waiter). The next legal slot is at
    // `last_request + interval`.
    //
    // Earlier flow used `now.duration_since(last_request)` which
    // saturates to zero when `last_request` is in the future (a
    // previous caller reserved a slot we haven't reached yet).
    // That made the second-and-onward queued caller wait `interval`
    // from THEIR arrival instead of `interval` after the previous
    // reserved slot - back-to-back arrivals therefore burst at
    // close to 1 request per slot-arrival-rate, blowing past the
    // configured per-service cap.
    //
    // Fix: always queue strictly after `last_request + interval`,
    // computed from `last_request` (not `now`), and roll
    // `last_request` forward by exactly one interval per queued
    // caller so the next arrival queues after this one's slot.
    let next_slot = limit.last_request + limit.interval;
    if now >= next_slot {
        limit.last_request = now;
        None
    } else {
        let wait = next_slot.saturating_duration_since(now);
        limit.last_request = next_slot;
        Some(wait)
    }
}

fn rps_to_nanos(rps: f64) -> u64 {
    let rate = if rps.is_finite() && rps > 0.0 {
        rps
    } else {
        1.0
    };
    let nanos = (1.0e9 / rate).round();
    if nanos.is_finite() && nanos < 1.0 {
        1
    } else if nanos.is_finite() && nanos <= u64::MAX as f64 {
        nanos as u64
    } else {
        1_000_000_000
    }
}

use std::sync::OnceLock;
pub static GLOBAL_RATE_LIMITER: OnceLock<RateLimiter> = OnceLock::new();

/// Lazily create the process-wide rate limiter at the default 5 rps.
/// Use [`set_global_default_rps`] to retune after init.
pub fn get_rate_limiter() -> &'static RateLimiter {
    GLOBAL_RATE_LIMITER.get_or_init(|| RateLimiter::new(5.0))
}

/// Convenience setter the CLI calls once at startup to apply the
/// `--verify-rate` flag. Idempotent; safe to call before or after the
/// limiter has been lazily initialised.
pub fn set_global_default_rps(rps: f64) {
    get_rate_limiter().set_default_rps(rps);
}
