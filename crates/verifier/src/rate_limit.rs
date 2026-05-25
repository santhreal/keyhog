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

struct ServiceLimit {
    last_request: Instant,
    interval: Duration,
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
    /// Non-finite or non-positive `rps` falls back to 1.0 — the same
    /// guard as `new()` so a caller can't drive the limiter into a
    /// zero-interval (= infinite-rate) state by accident.
    pub fn set_default_rps(&self, rps: f64) {
        self.default_interval_nanos
            .store(rps_to_nanos(rps), Ordering::Relaxed);
    }

    /// Default interval as a `Duration`. Lock-free.
    fn default_interval(&self) -> Duration {
        Duration::from_nanos(self.default_interval_nanos.load(Ordering::Relaxed))
    }

    pub async fn wait(&self, service: &str) {
        let bp = if self.global_error_count.load(Ordering::Relaxed) > 50 {
            Duration::from_secs(1)
        } else {
            Duration::from_millis(0)
        };
        let wait_time = {
            let default = self.default_interval();
            let entry = self.services.entry(service.to_string()).or_insert_with(|| {
                Mutex::new(ServiceLimit {
                    last_request: Instant::now() - default,
                    interval: default,
                })
            });
            let mut limit = entry.value().lock();
            let now = Instant::now();
            // `last_request` is the start of the most-recent SLOT (real or
            // reserved-for-an-in-flight-waiter). The next legal slot is at
            // `last_request + interval`.
            //
            // Earlier flow used `now.duration_since(last_request)` which
            // saturates to zero when `last_request` is in the future (a
            // previous caller reserved a slot we haven'"'"'t reached yet).
            // That made the second-and-onward queued caller wait `interval`
            // from THEIR arrival instead of `interval` after the previous
            // reserved slot — back-to-back arrivals therefore burst at
            // close to 1 request per slot-arrival-rate, blowing past the
            // configured per-service cap.
            //
            // Fix: always queue strictly after `last_request + interval`,
            // computed from `last_request` (not `now`), and roll
            // `last_request` forward by exactly one interval per queued
            // caller so the next arrival queues after this one'"'"'s slot.
            let next_slot = limit.last_request + limit.interval;
            if now >= next_slot {
                limit.last_request = now;
                None
            } else {
                let wait = next_slot.saturating_duration_since(now);
                limit.last_request = next_slot;
                Some(wait)
            }
        };
        if let Some(wait) = wait_time {
            tokio::time::sleep(wait.max(bp)).await;
        }
    }

    pub fn record_error(&self) {
        self.global_error_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_success(&self) {
        let _ = self
            .global_error_count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(1))
            });
    }

    pub async fn update_limit(&self, service: &str, rps: f64) {
        let interval = Duration::from_nanos(rps_to_nanos(rps));
        self.services.insert(
            service.to_string(),
            Mutex::new(ServiceLimit {
                last_request: Instant::now(),
                interval,
            }),
        );
    }
}

fn rps_to_nanos(rps: f64) -> u64 {
    let rate = if rps.is_finite() && rps > 0.0 {
        rps
    } else {
        1.0
    };
    let nanos = (1.0e9 / rate).round();
    if nanos.is_finite() && nanos >= 1.0 && nanos <= u64::MAX as f64 {
        nanos as u64
    } else {
        1_000_000_000 // 1s fallback for absurd inputs
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rps_to_nanos_clamps_invalid_input() {
        assert_eq!(rps_to_nanos(0.0), 1_000_000_000);
        assert_eq!(rps_to_nanos(-1.0), 1_000_000_000);
        assert_eq!(rps_to_nanos(f64::NAN), 1_000_000_000);
        assert_eq!(rps_to_nanos(f64::INFINITY), 1_000_000_000);
    }

    #[test]
    fn rps_to_nanos_typical_rates() {
        assert_eq!(rps_to_nanos(1.0), 1_000_000_000);
        assert_eq!(rps_to_nanos(5.0), 200_000_000);
        assert_eq!(rps_to_nanos(100.0), 10_000_000);
    }

    #[test]
    fn set_default_rps_updates_atomically() {
        let r = RateLimiter::new(5.0);
        assert_eq!(r.default_interval(), Duration::from_millis(200));
        r.set_default_rps(20.0);
        assert_eq!(r.default_interval(), Duration::from_millis(50));
    }

    /// Three back-to-back arrivals at 20 rps (50ms interval) must take at
    /// least ~85ms total — the first fires immediately, the second waits
    /// ~50ms, the third waits ~100ms from start. Before the
    /// `next_slot`-based fix, the third arrival used `Instant::now() -
    /// last_request` which saturated to zero (because `last_request` was
    /// in the future from the second arrival's reservation) and the
    /// third caller waited only one interval from ITS arrival instead of
    /// two — finishing in ~50ms total and bursting at ~3× the configured
    /// rate. Wall-clock timed (no `start_paused` because tokio's test-util
    /// feature isn't in our dev-deps), with generous tolerance to absorb
    /// timer jitter on busy CI runners.
    #[tokio::test]
    async fn burst_arrivals_respect_configured_interval() {
        let r = std::sync::Arc::new(RateLimiter::new(20.0)); // 50ms interval
        let start = Instant::now();

        let r1 = std::sync::Arc::clone(&r);
        let r2 = std::sync::Arc::clone(&r);
        let r3 = std::sync::Arc::clone(&r);
        let t1 = tokio::spawn(async move { r1.wait("svc").await });
        let t2 = tokio::spawn(async move { r2.wait("svc").await });
        let t3 = tokio::spawn(async move { r3.wait("svc").await });
        let _ = tokio::join!(t1, t2, t3);

        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(85),
            "three requests at 20rps must take ≥~85ms (2 intervals minus jitter); \
             took {elapsed:?}. This is the burst-rate regression — under the old \
             code, queued callers used Instant::now() instead of the reserved \
             future slot and bursted at ~3× rate (would finish in <60ms)."
        );
    }
}
