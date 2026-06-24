//! Regression: the daemon must NOT resolve a relative scan path against its own
//! working directory. The client (subcommands/scan.rs) sends `working_dir=None`
//! only when its own `std::env::current_dir()` failed; the daemon's cwd is
//! unrelated to the client's intended target, so an unanchored relative path
//! must fail closed with an actionable error instead of silently scanning the
//! wrong tree (LAW10: no silent fallback).

use keyhog::daemon::server::resolve_scan_target;
use std::path::PathBuf;

#[cfg(windows)]
fn absolute_path(path: &str) -> String {
    format!(r"C:\{path}")
}

#[cfg(not(windows))]
fn absolute_path(path: &str) -> String {
    format!("/{}", path.replace('\\', "/"))
}

#[test]
fn absolute_path_passes_through_unchanged() {
    let hosts = absolute_path(r"etc\hosts");
    let app_log = absolute_path(r"var\log\app.log");
    let home = absolute_path(r"home\u");
    assert_eq!(
        resolve_scan_target(&hosts, None).expect("absolute path resolves"),
        PathBuf::from(&hosts)
    );
    // working_dir is irrelevant once the path is already absolute.
    assert_eq!(
        resolve_scan_target(&app_log, Some(&home)).expect("absolute path resolves"),
        PathBuf::from(&app_log)
    );
}

#[test]
fn relative_path_is_anchored_to_the_client_working_dir() {
    let project = absolute_path(r"home\u\proj");
    assert_eq!(
        resolve_scan_target("sub/file.txt", Some(&project))
            .expect("relative path resolves under the client working_dir"),
        PathBuf::from(project).join("sub/file.txt")
    );
}

#[test]
fn relative_working_dir_fails_closed_instead_of_using_daemon_cwd() {
    let err = resolve_scan_target("sub/file.txt", Some("relative-client-cwd"))
        .expect_err("relative working_dir would resolve against daemon cwd");
    assert!(
        err.contains("working_dir")
            && err.contains("not absolute")
            && err.contains("absolute working_dir"),
        "error must reject the relative working_dir explicitly, got: {err}"
    );
}

#[cfg(windows)]
#[test]
fn drive_relative_scan_path_fails_closed_after_join() {
    let err = resolve_scan_target(r"C:relative\file.txt", Some(r"C:\home\u\proj"))
        .expect_err("Windows drive-relative paths must not survive as relative daemon targets");
    assert!(
        err.contains("resolved target") && err.contains("not absolute"),
        "error must reject the drive-relative resolved target explicitly, got: {err}"
    );
}

#[test]
fn unanchored_relative_path_fails_closed_instead_of_using_daemon_cwd() {
    let err = resolve_scan_target("rel.txt", None).expect_err(
        "a relative path with no working_dir must fail closed, not fall back to daemon cwd",
    );
    assert!(
        err.contains("cannot resolve relative path") && err.contains("absolute path"),
        "error must be actionable and tell the client to resend an absolute path, got: {err}"
    );
}
