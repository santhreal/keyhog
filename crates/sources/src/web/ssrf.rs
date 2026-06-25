use keyhog_core::SourceError;
use std::net::SocketAddr;
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::Duration;
use std::time::Instant;

const DNS_SCREEN_WORKERS: usize = 4;
const DNS_SCREEN_QUEUE_CAP: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_resolution_timeout_is_operator_visible() {
        let (_sender, receiver) = mpsc::sync_channel(1);
        let err = receive_dns_result("example.com", Duration::from_millis(1), receiver)
            .expect_err("slow DNS resolution must time out");

        let message = err.to_string();
        assert!(
            message.contains("DNS resolution timed out") && message.contains("example.com"),
            "timeout error must be visible and name the screened host, got {message}"
        );
    }

    #[test]
    fn remaining_fetch_timeout_deducts_dns_screening_elapsed_time() {
        let started = Instant::now();
        std::thread::sleep(Duration::from_millis(2));
        let remaining = remaining_fetch_timeout(
            "https://example.com/app.js",
            Duration::from_secs(1),
            started,
        )
        .expect("remaining timeout");
        assert!(
            remaining < Duration::from_secs(1),
            "remaining request timeout must be smaller than the full configured timeout"
        );
    }
}

pub(crate) fn redact_url(url: &str) -> std::borrow::Cow<'_, str> {
    crate::url_redaction::redact_url(url)
}

pub(crate) fn is_disallowed_web_host(url: &str) -> bool {
    keyhog_verifier::ssrf::is_private_url(url)
}

pub(crate) fn is_autoroute_loopback_calibration_url(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    if parsed.scheme() != "http" {
        return false;
    }
    parsed
        .host_str()
        .and_then(|host| host.parse::<std::net::IpAddr>().ok()) // LAW10: non-IP hosts fail closed as non-calibration URLs; the normal SSRF block remains active
        .is_some_and(|ip| ip.is_loopback())
}

/// SSRF IP-classification for the WebSource fetch surface.
///
/// This delegates to the fleet-canonical classifier
/// `keyhog_verifier::ssrf::is_private_ip_addr`, which is the single
/// source of truth for "is this address one an SSRF guard must
/// refuse?". That predicate composes the fast reserved-range bitwise
/// checks (`is_private_ip_addr_fast` — loopback, RFC 1918, link-local,
/// multicast, 0.0.0.0/8, 100.64.0.0/10 CGN, 240.0.0.0/4 Class E, ...)
/// on top of `bogon::ip_addr_is_bogon` (CGN, 192.0.0.0/24 IETF
/// protocol assignment, 198.18.0.0/15 benchmark, IPv6 unique-local /
/// link-local / Teredo / ORCHIDv2 / documentation / 6to4-wrapped
/// bogons, ...) — exactly the "layer additional checks on top of
/// `ip_addr_is_bogon`, do not fork it" contract the bogon module docs
/// mandate (`crates/verifier/src/bogon.rs`).
///
/// Previously WebSource shipped a hand-rolled copy (`is_loopback ||
/// is_private || is_link_local || is_multicast || is_broadcast ||
/// is_unspecified`) that was a strict subset of the canonical and
/// silently let CGN, benchmark, IETF, Class E, and 0.0.0.0/8 (minus
/// the single 0.0.0.0) addresses through — an SSRF pivot into
/// internal/provider space. The fork is gone; both the direct
/// `resolve_and_screen` path and the redirect-revalidation path now
/// resolve to this one predicate.
pub(crate) fn is_disallowed_ip(ip: std::net::IpAddr) -> bool {
    keyhog_verifier::ssrf::is_private_ip_addr(&ip)
}

pub(crate) fn build_web_client(
    cfg: &crate::http::HttpClientConfig,
    url: &str,
    proxy_in_use: bool,
    allow_autoroute_loopback_calibration_url: bool,
) -> Result<reqwest::blocking::Client, SourceError> {
    let fetch_started = Instant::now();
    let total_timeout = cfg.effective_timeout();
    let parsed =
        reqwest::Url::parse(url).map_err(|e| SourceError::Other(format!("invalid URL: {e}")))?;
    if is_disallowed_web_host(url) && !allow_autoroute_loopback_calibration_url {
        let safe_url = redact_url(url);
        return Err(super::web_unreadable_error(format!(
            "refusing to fetch {safe_url}: host resolves to a private / \
             loopback / link-local / metadata-service address - \
             WebSource only fetches public URLs"
        )));
    }

    let mut pinned_addrs = None;
    if !allow_autoroute_loopback_calibration_url {
        if let Some(host) = parsed.host_str() {
            let port = parsed.port_or_known_default().unwrap_or(443); // LAW10: 443 is the correct https default port, not a swallowed error
            let host = host.to_string();
            let addrs = resolve_and_screen(&host, port, total_timeout)?;
            if !proxy_in_use {
                pinned_addrs = Some((host, addrs));
            }
        }
    }

    let remaining_timeout = remaining_fetch_timeout(url, total_timeout, fetch_started)?;
    let mut request_cfg = cfg.clone();
    request_cfg.timeout = Some(remaining_timeout);
    let mut builder = crate::http::blocking_client_builder(&request_cfg)
        .map_err(SourceError::Other)?
        .redirect(reqwest::redirect::Policy::none());
    if let Some((host, addrs)) = pinned_addrs.as_ref() {
        builder = builder.resolve_to_addrs(host, addrs);
    }

    builder
        .build()
        .map_err(|e| SourceError::Other(format!("failed to build HTTP client: {e}")))
}

pub(crate) fn resolve_and_screen(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<Vec<std::net::SocketAddr>, SourceError> {
    let addrs = resolve_socket_addrs_with_timeout(host, port, timeout)?;
    if addrs.is_empty() {
        return Err(super::web_unreadable_error(format!(
            "refusing to fetch {}: DNS returned no addresses",
            redact_url(host)
        )));
    }
    if addrs.iter().any(|a| is_disallowed_ip(a.ip())) {
        return Err(super::web_unreadable_error(format!(
            "refusing to fetch {}: host resolves to a private / loopback / \
             link-local / metadata-service address - WebSource only fetches \
             public URLs",
            redact_url(host)
        )));
    }
    Ok(addrs)
}

fn remaining_fetch_timeout(
    url: &str,
    total_timeout: Duration,
    started: Instant,
) -> Result<Duration, SourceError> {
    total_timeout
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| {
            super::web_unreadable_error(format!(
                "failed to fetch {}: DNS screening consumed the configured {:.3}s timeout before the HTTP request could start",
                redact_url(url),
                total_timeout.as_secs_f64()
            ))
        })
}

fn resolve_socket_addrs_with_timeout(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<Vec<std::net::SocketAddr>, SourceError> {
    let pool = dns_resolver_pool()?;
    let (reply, receiver) = mpsc::sync_channel(1);
    pool.sender
        .try_send(DnsJob {
            host: host.to_string(),
            port,
            reply,
        })
        .map_err(|error| match error {
            mpsc::TrySendError::Full(_) => super::web_unreadable_error(format!(
                "refusing to fetch {}: DNS screening queue is full",
                redact_url(host)
            )),
            mpsc::TrySendError::Disconnected(_) => super::web_unreadable_error(format!(
                "refusing to fetch {}: DNS screening workers are unavailable",
                redact_url(host)
            )),
        })?;
    receive_dns_result(host, timeout, receiver)
}

fn receive_dns_result(
    host: &str,
    timeout: Duration,
    receiver: mpsc::Receiver<std::io::Result<Vec<SocketAddr>>>,
) -> Result<Vec<SocketAddr>, SourceError> {
    let host_for_error = host.to_string();
    match receiver.recv_timeout(timeout) {
        Ok(Ok(addrs)) => Ok(addrs),
        Ok(Err(error)) => Err(super::web_unreadable_error(format!(
            "refusing to fetch {}: DNS resolution failed: {error}",
            redact_url(&host_for_error)
        ))),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            Err(super::web_unreadable_error(format!(
                "refusing to fetch {}: DNS resolution timed out after {:.3}s",
                redact_url(&host_for_error),
                timeout.as_secs_f64()
            )))
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err(super::web_unreadable_error(format!(
                "refusing to fetch {}: DNS resolution worker exited before returning addresses",
                redact_url(&host_for_error)
            )))
        }
    }
}

struct DnsJob {
    host: String,
    port: u16,
    reply: mpsc::SyncSender<std::io::Result<Vec<SocketAddr>>>,
}

struct DnsResolverPool {
    sender: mpsc::SyncSender<DnsJob>,
}

fn dns_resolver_pool() -> Result<&'static DnsResolverPool, SourceError> {
    static DNS_RESOLVER_POOL: OnceLock<Result<DnsResolverPool, String>> = OnceLock::new();
    match DNS_RESOLVER_POOL.get_or_init(DnsResolverPool::start) {
        Ok(pool) => Ok(pool),
        Err(error) => Err(super::web_unreadable_error(format!(
            "WebSource DNS screening unavailable: {error}"
        ))),
    }
}

impl DnsResolverPool {
    fn start() -> Result<Self, String> {
        let (sender, receiver) = mpsc::sync_channel(DNS_SCREEN_QUEUE_CAP);
        let receiver = Arc::new(Mutex::new(receiver));
        for worker_index in 0..DNS_SCREEN_WORKERS {
            let receiver = Arc::clone(&receiver);
            std::thread::Builder::new()
                .name(format!("keyhog-web-dns-screen-{worker_index}"))
                .spawn(move || dns_worker_loop(receiver))
                .map_err(|error| format!("failed to start DNS worker {worker_index}: {error}"))?;
        }
        Ok(Self { sender })
    }
}

fn dns_worker_loop(receiver: Arc<Mutex<mpsc::Receiver<DnsJob>>>) {
    use std::net::ToSocketAddrs;

    loop {
        let job = match receiver.lock() {
            Ok(receiver) => receiver.recv(),
            Err(_poisoned) => return,
        };
        let Ok(job) = job else {
            return;
        };
        let result = (job.host.as_str(), job.port)
            .to_socket_addrs()
            .map(|iter| iter.collect());
        let _ignored = job.reply.send(result);
    }
}
