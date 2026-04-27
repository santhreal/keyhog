//! Per-service rate limiting for verification requests.
//!
//! Sharded via DashMap: every service occupies a different shard so concurrent
//! `wait()` calls for distinct services never serialize on a global mutex.
//! Calls for the same service still serialize through the per-entry update
//! step, but that is the desired behavior for a rate limiter — see
//! audits/legendary-2026-04-26 for the global-mutex contention finding.

use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;

/// Per-service leaky-bucket state. Locked individually so cross-service
/// independence is preserved.
struct ServiceLimit {
    last_request: Instant,
    interval: Duration,
}

/// Sharded leaky-bucket rate limiter per service name.
pub struct RateLimiter {
    services: DashMap<String, Mutex<ServiceLimit>>,
    default_interval: Duration,
}

impl RateLimiter {
    pub fn new(default_requests_per_second: f64) -> Self {
        // Reject zero/negative/non-finite rates at construction time —
        // 1.0 / 0.0 = +inf which would overflow Duration::from_secs_f64.
        let rate = if default_requests_per_second.is_finite() && default_requests_per_second > 0.0 {
            default_requests_per_second
        } else {
            1.0
        };
        let interval = Duration::from_secs_f64(1.0 / rate);
        Self {
            services: DashMap::new(),
            default_interval: interval,
        }
    }

    /// Block (async) until the next call to `service` is allowed.
    pub async fn wait(&self, service: &str) {
        let entry = self.services.entry(service.to_string()).or_insert_with(|| {
            Mutex::new(ServiceLimit {
                last_request: Instant::now() - self.default_interval,
                interval: self.default_interval,
            })
        });

        // Compute the sleep duration under the per-service mutex (cheap),
        // RELEASE the lock before sleeping to avoid holding it across an
        // await point.
        let wait_time = {
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
            tokio::time::sleep(wait).await;
        }
    }

    /// Update the rate limit for a specific service (e.g. on 429 with
    /// `Retry-After`).
    pub async fn update_limit(&self, service: &str, requests_per_second: f64) {
        let interval = if requests_per_second.is_finite() && requests_per_second > 0.0 {
            Duration::from_secs_f64(1.0 / requests_per_second)
        } else {
            self.default_interval
        };
        self.services.insert(
            service.to_string(),
            Mutex::new(ServiceLimit {
                last_request: Instant::now(),
                interval,
            }),
        );
    }
}

use std::sync::OnceLock;

pub static GLOBAL_RATE_LIMITER: OnceLock<RateLimiter> = OnceLock::new();

pub fn get_rate_limiter() -> &'static RateLimiter {
    GLOBAL_RATE_LIMITER.get_or_init(|| RateLimiter::new(5.0)) // 5 req/sec default
}
