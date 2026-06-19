//! Installer/update lifecycle under a HOSTILE GitHub: malformed JSON, 500s,
//! empty release lists, asset-less releases, missing pinned tags. Drives the
//! REAL binary's release-resolution path (`keyhog update --check`) against an
//! httpmock server via the hidden `--release-api-base` test seam, with zero network.
//!
//! `--check` is used exclusively: it resolves + compares versions but NEVER
//! downloads or self-replaces, so the test binary is never overwritten. The
//! download/verify/rollback primitives are covered by
//! `installer_recoverability` at the library level.
//!
//! Bar: a broken or hostile release endpoint must produce a clean, documented
//! error - never a panic, never a hang, never a nonsense exit code. "The
//! installer broke under stress" is the exact failure this suite forbids.

use std::process::Command;

use httpmock::prelude::*;

use crate::reliability::harness::binary;

/// A releases-list body whose newest tag is `tag`, carrying an asset for every
/// supported platform so `select_asset` resolves regardless of test host.
fn releases_body(tag: &str) -> String {
    format!(
        r#"[{{"tag_name":"{tag}","assets":[
            {{"name":"keyhog-linux-x86_64","browser_download_url":"http://example.invalid/lin"}},
            {{"name":"keyhog-macos-aarch64","browser_download_url":"http://example.invalid/mac-arm"}},
            {{"name":"keyhog-macos-x86_64","browser_download_url":"http://example.invalid/mac-x86"}},
            {{"name":"keyhog-windows-x86_64.exe","browser_download_url":"http://example.invalid/win"}}
        ]}}]"#
    )
}

fn run_update(base: &str, extra: &[&str]) -> (Option<i32>, String, String) {
    let mut args: Vec<&str> = vec!["update", "--release-api-base", base];
    args.extend_from_slice(extra);
    let out = Command::new(binary())
        .args(&args)
        .output()
        .expect("spawn keyhog update");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Assert the invocation degraded gracefully: real exit code (not a signal),
/// no panic/backtrace, no ANSI leak on the pipe, and an exit code update is
/// allowed to return (0 up-to-date, 10 available, 2 user error, 3 system).
fn assert_graceful(code: Option<i32>, stdout: &str, stderr: &str, what: &str) {
    assert!(code.is_some(), "{what}: update crashed (killed by signal)");
    let hay = format!("{stdout}{stderr}");
    for needle in [
        "panicked at",
        "RUST_BACKTRACE",
        "Result::unwrap()",
        "Option::unwrap()",
    ] {
        assert!(
            !hay.contains(needle),
            "{what}: panic marker {needle:?}:\n{hay}"
        );
    }
    assert!(
        !stdout.as_bytes().contains(&0x1b) && !stderr.as_bytes().contains(&0x1b),
        "{what}: ANSI escape leaked to a pipe"
    );
    let c = code.unwrap();
    assert!(
        [0, 2, 3, 10].contains(&c),
        "{what}: undocumented exit {c} (update may return 0/10/2/3)\n{hay}"
    );
}

fn releases_mock(server: &MockServer, status: u16, body: &str) {
    server.mock(|when, then| {
        when.method(GET)
            .path("/repos/santhsecurity/keyhog/releases");
        then.status(status)
            .header("content-type", "application/json")
            .body(body);
    });
}

#[test]
fn newer_release_reports_update_available() {
    let server = MockServer::start();
    releases_mock(&server, 200, &releases_body("v99.0.0"));
    let (code, out, err) = run_update(&server.base_url(), &["--check"]);
    assert_graceful(code, &out, &err, "newer release");
    assert_eq!(
        code,
        Some(10),
        "a strictly newer release must exit 10 (update available)"
    );
    assert!(
        out.to_lowercase().contains("update available") || out.contains("v99.0.0"),
        "--check did not announce the available update:\n{out}"
    );
}

#[test]
fn current_or_older_release_reports_up_to_date() {
    let server = MockServer::start();
    releases_mock(&server, 200, &releases_body("v0.0.1"));
    let (code, out, err) = run_update(&server.base_url(), &["--check"]);
    assert_graceful(code, &out, &err, "older release");
    assert_eq!(
        code,
        Some(0),
        "an older latest must mean 'already current' (exit 0)"
    );
    assert!(
        out.to_lowercase().contains("latest") || out.to_lowercase().contains("up"),
        "did not report up-to-date:\n{out}"
    );
}

#[test]
fn malformed_json_fails_gracefully() {
    let server = MockServer::start();
    releases_mock(&server, 200, "{ this is not valid json at all ][");
    let (code, out, err) = run_update(&server.base_url(), &["--check"]);
    assert_graceful(code, &out, &err, "malformed JSON");
    assert_ne!(
        code,
        Some(10),
        "malformed JSON must not be read as 'update available'"
    );
    assert_ne!(
        code,
        Some(0),
        "malformed JSON must not be read as 'up to date'"
    );
}

#[test]
fn truncated_json_fails_gracefully() {
    let server = MockServer::start();
    releases_mock(&server, 200, "[{\"tag_name\":\"v9.9.9\",\"assets\":[");
    let (code, out, err) = run_update(&server.base_url(), &["--check"]);
    assert_graceful(code, &out, &err, "truncated JSON");
}

#[test]
fn html_error_page_instead_of_json_fails_gracefully() {
    let server = MockServer::start();
    releases_mock(
        &server,
        200,
        "<!DOCTYPE html><html><body>502 Bad Gateway</body></html>",
    );
    let (code, out, err) = run_update(&server.base_url(), &["--check"]);
    assert_graceful(code, &out, &err, "HTML body");
}

#[test]
fn server_500_fails_gracefully() {
    let server = MockServer::start();
    releases_mock(&server, 500, "internal server error");
    let (code, out, err) = run_update(&server.base_url(), &["--check"]);
    assert_graceful(code, &out, &err, "HTTP 500");
    assert_ne!(code, Some(0), "an HTTP 500 must not be treated as success");
    assert_ne!(
        code,
        Some(10),
        "an HTTP 500 must not be treated as 'update available'"
    );
}

#[test]
fn rate_limit_403_fails_gracefully() {
    let server = MockServer::start();
    releases_mock(&server, 403, r#"{"message":"API rate limit exceeded"}"#);
    let (code, out, err) = run_update(&server.base_url(), &["--check"]);
    assert_graceful(code, &out, &err, "HTTP 403 rate limit");
}

#[test]
fn empty_release_list_fails_gracefully_with_guidance() {
    let server = MockServer::start();
    releases_mock(&server, 200, "[]");
    let (code, out, err) = run_update(&server.base_url(), &["--check"]);
    assert_graceful(code, &out, &err, "empty release list");
    assert_ne!(code, Some(10));
    assert_ne!(code, Some(0), "no releases must not be 'up to date'");
}

#[test]
fn release_with_no_assets_fails_gracefully() {
    let server = MockServer::start();
    releases_mock(&server, 200, r#"[{"tag_name":"v99.0.0","assets":[]}]"#);
    let (code, out, err) = run_update(&server.base_url(), &["--check"]);
    assert_graceful(code, &out, &err, "asset-less release");
}

#[test]
fn pinned_missing_tag_404_fails_gracefully() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET)
            .path("/repos/santhsecurity/keyhog/releases/tags/v1.2.3");
        then.status(404).body(r#"{"message":"Not Found"}"#);
    });
    let (code, out, err) = run_update(&server.base_url(), &["--check", "--version", "v1.2.3"]);
    assert_graceful(code, &out, &err, "pinned missing tag");
    assert_ne!(code, Some(10), "a 404 tag must not be 'update available'");
}

#[test]
fn garbage_tag_name_in_release_does_not_crash() {
    // A release whose tag_name is unparseable as semver: is_newer fails safe
    // (not newer), so --check must say up-to-date or error, never panic.
    let server = MockServer::start();
    releases_mock(
        &server,
        200,
        r#"[{"tag_name":"not-a-version-🙃","assets":[{"name":"keyhog-linux-x86_64","browser_download_url":"http://example.invalid/x"}]}]"#,
    );
    let (code, out, err) = run_update(&server.base_url(), &["--check"]);
    assert_graceful(code, &out, &err, "garbage tag");
    assert_ne!(
        code,
        Some(10),
        "an unparseable tag must not be 'update available' (fail-safe)"
    );
}
