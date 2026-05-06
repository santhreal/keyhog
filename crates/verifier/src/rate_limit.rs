//! Per-service rate limiting for verification requests.
use dashmap::DashMap;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
struct ServiceLimit {
    last_request: Instant,
    interval: Duration,
}
pub struct RateLimiter {
    services: DashMap<String, Mutex<ServiceLimit>>,
    default_interval: Duration,
    global_error_count: AtomicUsize,
}
impl RateLimiter {
    pub fn new(rps: f64) -> Self {
        let rate = if rps.is_finite() && rps > 0.0 {
            rps
        } else {
            1.0
        };
        let interval = Duration::from_secs_f64(1.0 / rate);
        Self {
            services: DashMap::new(),
            default_interval: interval,
            global_error_count: AtomicUsize::new(0),
        }
    }
    pub async fn wait(&self, service: &str) {
        let bp = if self.global_error_count.load(Ordering::Relaxed) > 50 {
            Duration::from_secs(1)
        } else {
            Duration::from_millis(0)
        };
        let wait_time = {
            let entry = self.services.entry(service.to_string()).or_insert_with(|| {
                Mutex::new(ServiceLimit {
                    last_request: Instant::now() - self.default_interval,
                    interval: self.default_interval,
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
        let interval = if rps.is_finite() && rps > 0.0 {
            Duration::from_secs_f64(1.0 / rps)
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
    GLOBAL_RATE_LIMITER.get_or_init(|| RateLimiter::new(5.0))
}
