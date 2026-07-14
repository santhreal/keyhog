//! Offline release lifecycle coverage through the library-only endpoint seam.
//!
//! Production `update` and `repair` have no endpoint override. These tests
//! inject an HTTP server directly into release resolution and the shared
//! signature, checksum, download, and atomic install path.

use std::process::Command;

use httpmock::prelude::*;
use keyhog::testing::{CliTestApi as _, ResolvedRelease, API};

use crate::reliability::harness::binary;

const FIXTURE_DATA: &[u8] = b"keyhog-signature-test-v1\n";
const FIXTURE_SIG: &str = "untrusted comment: signature from rsign secret key\n\
RUTPnJ/p6xVJ3REkJ9dhxwKQpEisq7Y2A4uIZlUzPRM0zDjWidV3sIXjHB8d558++9M0KpCpz6T8efYlVFl/RZhrKIznrUZSGww=\n\
trusted comment: timestamp:1780025193\tfile:/tmp/claude-1000/tmp.JTQWgRt5FO/fixture.bin\tprehashed\n\
L/wvGiwIhpaBlkEUaQ364Q8ph9ksqIxJyIMy1RQbs/QS4+q8biUaJGt+0weV4E0IV/pPHywDFtZhvUD03un2CA==\n";
const FIXTURE_SHA256: &str = "79792c6a6ce7cccb7d14cadf57006754b70a3e90a944cdaaf111ae97f03fbee8";

fn release_value(tag: &str, base: &str) -> serde_json::Value {
    let mut assets = Vec::new();
    for binary in [
        "keyhog-linux-x86_64",
        "keyhog-macos-aarch64",
        "keyhog-macos-x86_64",
        "keyhog-windows-x86_64.exe",
    ] {
        for suffix in [
            "",
            ".sha256",
            ".minisig",
            ".gpu-literals.tar.gz",
            ".gpu-literals.tar.gz.sha256",
            ".gpu-literals.tar.gz.minisig",
        ] {
            let name = format!("{binary}{suffix}");
            assets.push(serde_json::json!({
                "name": name,
                "browser_download_url": format!("{base}/download/{binary}{suffix}"),
            }));
        }
    }
    for suffix in ["", ".sha256", ".minisig"] {
        assets.push(serde_json::json!({
            "name": format!("fixture.bin{suffix}"),
            "browser_download_url": format!("{base}/download/fixture.bin{suffix}"),
        }));
    }
    serde_json::json!({
        "tag_name": tag,
        "draft": false,
        "prerelease": false,
        "assets": assets,
    })
}

fn releases_body(tag: &str, base: &str) -> String {
    serde_json::json!([release_value(tag, base)]).to_string()
}

fn releases_mock(server: &MockServer, status: u16, body: &str) {
    server.mock(|when, then| {
        when.method(GET).path("/repos/santhreal/keyhog/releases");
        then.status(status)
            .header("content-type", "application/json")
            .body(body);
    });
}

async fn resolve(base: &str, version: Option<&str>) -> anyhow::Result<ResolvedRelease> {
    let client = API.http_client()?;
    API.resolve_release_at(&client, version, base).await
}

fn private_install_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("installer target directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("make installer target private");
    }
    directory
}

#[test]
fn shipped_update_and_repair_reject_release_api_base() {
    for command in ["update", "repair"] {
        let output = Command::new(binary())
            .args([command, "--release-api-base", "http://127.0.0.1:9"])
            .output()
            .unwrap_or_else(|error| panic!("run keyhog {command}: {error}"));
        assert_eq!(
            output.status.code(),
            Some(2),
            "{command} must reject the removed flag"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("unexpected argument") && stderr.contains("--release-api-base"),
            "{command} must reject the test-only flag before any network access: {stderr}"
        );
    }
}

#[tokio::test]
async fn newer_release_resolves_through_library_injection() {
    let server = MockServer::start();
    releases_mock(&server, 200, &releases_body("v99.0.0", &server.base_url()));
    let release = resolve(&server.base_url(), None)
        .await
        .expect("resolve release");
    assert_eq!(release.tag_name, "v99.0.0");
    assert!(release.asset_name.starts_with("keyhog-"));
}

#[tokio::test]
async fn empty_injected_base_does_not_fall_back_to_github() {
    let error = resolve(" / ", None).await.unwrap_err();
    assert!(format!("{error:#}").contains("injected release API base is empty"));
}

#[tokio::test]
async fn assetless_release_is_not_installable() {
    let server = MockServer::start();
    releases_mock(
        &server,
        200,
        r#"[{"tag_name":"v99.0.0","draft":false,"prerelease":false,"assets":[]}]"#,
    );
    let error = resolve(&server.base_url(), None).await.unwrap_err();
    assert!(format!("{error:#}").contains("complete signed asset bundle"));
}

#[tokio::test]
async fn incomplete_newer_release_is_skipped_for_complete_stable_bundle() {
    let server = MockServer::start();
    let body = serde_json::json!([
        {
            "tag_name": "v100.0.0",
            "assets": [{"name": "keyhog-linux-x86_64", "browser_download_url": "http://example.invalid/partial"}]
        },
        release_value("v99.0.0", &server.base_url())
    ]);
    releases_mock(&server, 200, &body.to_string());
    let release = resolve(&server.base_url(), None)
        .await
        .expect("resolve complete release");
    assert_eq!(release.tag_name, "v99.0.0");
}

#[tokio::test]
async fn prerelease_is_not_selected_as_implicit_latest() {
    let server = MockServer::start();
    let mut prerelease = release_value("v100.0.0-rc.1", &server.base_url());
    prerelease["prerelease"] = serde_json::Value::Bool(true);
    let body = serde_json::json!([prerelease, release_value("v99.0.0", &server.base_url())]);
    releases_mock(&server, 200, &body.to_string());
    let release = resolve(&server.base_url(), None)
        .await
        .expect("resolve stable release");
    assert_eq!(release.tag_name, "v99.0.0");
}

#[tokio::test]
async fn hostile_release_metadata_fails_closed() {
    for (name, status, body) in [
        (
            "malformed JSON",
            200,
            "{ this is not valid json at all ][".to_string(),
        ),
        (
            "truncated JSON",
            200,
            "[{\"tag_name\":\"v9.9.9\",\"assets\":[".to_string(),
        ),
        (
            "HTML body",
            200,
            "<!DOCTYPE html><html>502</html>".to_string(),
        ),
        ("server error", 500, "internal server error".to_string()),
        (
            "rate limit",
            403,
            r#"{"message":"API rate limit exceeded"}"#.to_string(),
        ),
        ("empty list", 200, "[]".to_string()),
        ("oversized metadata", 200, "x".repeat(8 * 1024 * 1024 + 1)),
    ] {
        let server = MockServer::start();
        releases_mock(&server, status, &body);
        let error = resolve(&server.base_url(), None).await.unwrap_err();
        let message = format!("{error:#}");
        assert!(!message.is_empty(), "{name} must return a contextual error");
        if name == "oversized metadata" {
            assert!(message.contains("download limit"), "{message}");
        }
    }
}

#[tokio::test]
async fn pinned_missing_tag_fails_closed() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET)
            .path("/repos/santhreal/keyhog/releases/tags/v1.2.3");
        then.status(404).body(r#"{"message":"Not Found"}"#);
    });
    let error = resolve(&server.base_url(), Some("v1.2.3"))
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("HTTP status"));
}

#[tokio::test]
async fn signed_payload_runs_shared_download_and_atomic_install_path() {
    let server = MockServer::start();
    let tag = "v99.0.0";
    let release = release_value(tag, &server.base_url()).to_string();
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/repos/santhreal/keyhog/releases/tags/{tag}"));
        then.status(200)
            .header("content-type", "application/json")
            .body(release);
    });
    server.mock(|when, then| {
        when.method(GET).path("/download/fixture.bin");
        then.status(200).body(FIXTURE_DATA);
    });
    server.mock(|when, then| {
        when.method(GET).path("/download/fixture.bin.minisig");
        then.status(200).body(FIXTURE_SIG);
    });
    server.mock(|when, then| {
        when.method(GET).path("/download/fixture.bin.sha256");
        then.status(200)
            .body(format!("{FIXTURE_SHA256}  fixture.bin\n"));
    });

    let directory = private_install_directory();
    let target = directory.path().join("keyhog-fixture");
    std::fs::write(&target, b"working-old-binary").expect("write old target");
    let client = API.http_client().expect("build release client");
    API.install_verified_release_payload_at(
        &client,
        Some(tag),
        &server.base_url(),
        "fixture.bin",
        &target,
    )
    .await
    .expect("verify and install signed payload");
    assert_eq!(
        std::fs::read(&target).expect("read installed target"),
        FIXTURE_DATA
    );
}

#[tokio::test]
async fn invalid_signature_preserves_existing_install() {
    let server = MockServer::start();
    let tag = "v99.0.0";
    let release = release_value(tag, &server.base_url()).to_string();
    server.mock(|when, then| {
        when.method(GET)
            .path(format!("/repos/santhreal/keyhog/releases/tags/{tag}"));
        then.status(200).body(release);
    });
    server.mock(|when, then| {
        when.method(GET).path("/download/fixture.bin");
        then.status(200).body(b"tampered payload");
    });
    server.mock(|when, then| {
        when.method(GET).path("/download/fixture.bin.minisig");
        then.status(200).body(FIXTURE_SIG);
    });

    let directory = private_install_directory();
    let target = directory.path().join("keyhog-fixture");
    std::fs::write(&target, b"working-old-binary").expect("write old target");
    let client = API.http_client().expect("build release client");
    let error = API
        .install_verified_release_payload_at(
            &client,
            Some(tag),
            &server.base_url(),
            "fixture.bin",
            &target,
        )
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("signature verification"));
    assert_eq!(
        std::fs::read(&target).expect("read preserved target"),
        b"working-old-binary"
    );
}
