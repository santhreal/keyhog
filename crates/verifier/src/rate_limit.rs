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
            let elapsed = now.duration_since(limit.last_request);
            if elapsed < limit.interval {
                let wait = limit.interval - elapsed;
                limit.last_request = now + wait;
                Some(wait)
            } else {
                limit.last_request = now;
                None
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
    let rate = if rps.is_finite() && rps > 0.0 { rps } else { 1.0 };
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
}
