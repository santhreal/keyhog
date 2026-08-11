//! Unit tests for daemon client timeouts (KH-1459).

#[cfg(test)]
use super::{
    request_timeout, DAEMON_HEALTH_TIMEOUT, DAEMON_REQUEST_TIMEOUT, DAEMON_SCAN_TEXT_TIMEOUT,
    DAEMON_SHUTDOWN_TIMEOUT,
};
#[cfg(test)]
use crate::daemon::protocol::Request;

#[cfg(test)]
#[test]
fn health_and_hello_use_short_timeout() {
    assert_eq!(request_timeout(&Request::Health), DAEMON_HEALTH_TIMEOUT);
    assert_eq!(request_timeout(&Request::Hello), DAEMON_HEALTH_TIMEOUT);
    assert_eq!(DAEMON_HEALTH_TIMEOUT.as_secs(), 5);
}

#[cfg(test)]
#[test]
fn shutdown_timeout_exceeds_the_bounded_server_drain() {
    assert_eq!(request_timeout(&Request::Shutdown), DAEMON_SHUTDOWN_TIMEOUT);
    assert_eq!(DAEMON_SHUTDOWN_TIMEOUT.as_secs(), 45);
}

#[cfg(test)]
#[test]
fn scan_text_uses_mid_timeout() {
    let req = Request::ScanText {
        path: None,
        text: "x".into(),
        dogfood: false,
        profile: false,
    };
    assert_eq!(request_timeout(&req), DAEMON_SCAN_TEXT_TIMEOUT);
    assert_eq!(DAEMON_SCAN_TEXT_TIMEOUT.as_secs(), 60);
}

#[cfg(test)]
#[test]
fn scan_path_uses_full_file_timeout() {
    let req = Request::ScanPath {
        path: "/tmp/a".into(),
        working_dir: None,
        dogfood: false,
        profile: false,
    };
    assert_eq!(request_timeout(&req), DAEMON_REQUEST_TIMEOUT);
    assert_eq!(DAEMON_REQUEST_TIMEOUT.as_secs(), 300);
}

#[cfg(test)]
#[test]
fn mass_filesystem_acquisition_uses_workload_timeout() {
    let request = Request::MassFilesystemBegin {
        root: "/workspace".into(),
        max_file_size: 1024,
        ignore_paths: Vec::new(),
        respect_default_excludes: true,
        reader_threads: None,
        incremental_cache: Some("/cache/keyhog/merkle.idx".into()),
    };
    assert_eq!(request_timeout(&request), DAEMON_REQUEST_TIMEOUT);
}
