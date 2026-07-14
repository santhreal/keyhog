use super::*;
use std::sync::{Arc, Condvar, Mutex};

struct WorkerRelease(Arc<(Mutex<bool>, Condvar)>);

impl WorkerRelease {
    fn new() -> Self {
        Self(Arc::new((Mutex::new(false), Condvar::new())))
    }

    fn signal(&self) {
        let (lock, ready) = &*self.0;
        let mut released = match lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *released = true;
        ready.notify_all();
    }
}

impl Drop for WorkerRelease {
    fn drop(&mut self) {
        self.signal();
    }
}

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
fn resolve_with_abandon_returns_numeric_addr_exactly() {
    let addrs = resolve_with_abandon("127.0.0.1".to_string(), 8080, Duration::from_secs(5))
        .expect("loopback literal must resolve");
    assert_eq!(addrs, vec!["127.0.0.1:8080".parse::<SocketAddr>().unwrap()]);
}

#[test]
fn resolve_with_abandon_times_out_and_frees_the_worker() {
    // A 1ns budget cannot be met by any real getaddrinfo, so the worker
    // abandons the helper and returns TimedOut instead of blocking forever.
    let err = resolve_with_abandon("example.com".to_string(), 443, Duration::from_nanos(1))
        .expect_err("sub-nanosecond budget must abandon the resolve");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(
        err.to_string(),
        "getaddrinfo exceeded the DNS screening budget"
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

#[test]
fn dns_queue_runs_all_workers_concurrently() {
    let (sender, receiver) = bounded(DNS_SCREEN_QUEUE_CAP);
    let (started_tx, started_rx) = mpsc::sync_channel(DNS_SCREEN_WORKERS);
    let release = WorkerRelease::new();
    let mut workers = Vec::new();

    for _ in 0..DNS_SCREEN_WORKERS {
        let receiver = receiver.clone();
        let started_tx = started_tx.clone();
        let release = Arc::clone(&release.0);
        workers.push(std::thread::spawn(move || {
            dns_worker_loop(receiver, move |host, port, _budget| {
                let _ignored = started_tx.send(host);
                let (lock, ready) = &*release;
                let mut released = lock
                    .lock()
                    .map_err(|_| std::io::Error::other("test release mutex was poisoned"))?;
                while !*released {
                    released = ready
                        .wait(released)
                        .map_err(|_| std::io::Error::other("test release mutex was poisoned"))?;
                }
                Ok(vec![SocketAddr::from(([192, 0, 2, 1], port))])
            });
        }));
    }
    drop(started_tx);

    let mut replies = Vec::new();
    for index in 0..DNS_SCREEN_WORKERS {
        let (reply, receiver) = mpsc::sync_channel(1);
        replies.push(receiver);
        sender
            .try_send(DnsJob {
                host: format!("worker-{index}.example"),
                port: 443,
                budget: Duration::from_secs(1),
                reply,
            })
            .expect("test DNS job must enter the bounded queue");
    }

    let mut started = Vec::new();
    let start_deadline = Instant::now() + Duration::from_secs(5);
    for _ in 0..DNS_SCREEN_WORKERS {
        let remaining = start_deadline.saturating_duration_since(Instant::now());
        started.push(
            started_rx
                .recv_timeout(remaining)
                .expect("every DNS worker must start before release"),
        );
    }

    release.signal();
    for receiver in replies {
        let result = receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("every concurrent worker must return its result")
            .expect("test resolver must succeed");
        assert_eq!(result, vec![SocketAddr::from(([192, 0, 2, 1], 443))]);
    }
    drop(sender);
    for worker in workers {
        worker.join().expect("test DNS worker must exit cleanly");
    }

    assert_eq!(
        started.len(),
        DNS_SCREEN_WORKERS,
        "all DNS workers must begin before any one is released"
    );
}
