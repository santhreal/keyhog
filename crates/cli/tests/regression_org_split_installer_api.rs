//! Regression: the file-responsibility split of `installer.rs` into a NETWORK +
//! TRUST half (`installer/release.rs`: release resolution, asset selection,
//! semver, signature verify, scan self-test) and a LOCAL-INSTALL half
//! (`installer.rs`: self-replace, backup/rollback, reaping) must NOT change the
//! internal installer API.
//!
//! Every symbol the `update`/`repair`/`doctor`/`uninstall` subcommands call
//! stays reachable through the parent module for production code, while tests
//! use `keyhog::testing::API` so installer plumbing does not bloat the
//! supported public API. These pin EXACT values for the pure functions so a
//! moved helper that drifted its logic is caught, plus a compile-time
//! reachability check over the full call list the subcommands depend on.

use keyhog::testing::{API, CliTestApi as _};

// ── release (network/trust) half: pure functions keep exact behavior ────────

#[test]
fn release_semver_and_version_compare_unchanged_after_split() {
    assert_eq!(API.parse_semver("v1.2.3"), Some((1, 2, 3)));
    assert_eq!(API.parse_semver("0.5.37"), Some((0, 5, 37)));
    assert_eq!(API.parse_semver("v2.0.0-rc1"), Some((2, 0, 0)));
    assert_eq!(API.parse_semver("not-a-version"), None);

    assert!(API.is_newer("0.5.0", "0.5.1"));
    assert!(API.is_newer("0.5.37", "0.6.0"));
    assert!(!API.is_newer("0.6.0", "0.5.99"));
    assert!(!API.is_newer("garbage", "0.6.0"));
}

#[test]
fn release_asset_naming_unchanged_after_split() {
    assert_eq!(
        API.asset_name("linux", "x86_64", false).as_deref(),
        Some("keyhog-linux-x86_64")
    );
    assert_eq!(
        API.asset_name("linux", "x86_64", true).as_deref(),
        Some("keyhog-linux-x86_64-cuda")
    );
    assert_eq!(
        API.asset_name("macos", "aarch64", false).as_deref(),
        Some("keyhog-macos-aarch64")
    );
    assert_eq!(
        API.asset_name("windows", "x86_64", false).as_deref(),
        Some("keyhog-windows-x86_64.exe")
    );
    assert_eq!(API.asset_name("plan9", "riscv", false), None);
}

#[test]
fn release_executable_magic_check_unchanged_after_split() {
    // The native magic guard is the cheap "did we download an HTML 404?" gate.
    let elf = [0x7Fu8, b'E', b'L', b'F', 0, 0, 0, 0];
    let macho = [0xFEu8, 0xED, 0xFA, 0xCF, 0, 0, 0, 0];
    let pe = [b'M', b'Z', 0x90, 0x00];
    let html = b"<!DOCTYPE html>";
    assert!(API.looks_like_native_executable_for_os(&elf, "linux"));
    assert!(API.looks_like_native_executable_for_os(&macho, "macos"));
    assert!(API.looks_like_native_executable_for_os(&pe, "windows"));
    assert!(!API.looks_like_native_executable_for_os(html, "linux"));
    assert!(!API.looks_like_native_executable_for_os(html, "macos"));
    assert!(!API.looks_like_native_executable_for_os(html, "windows"));
    assert!(!API.looks_like_native_executable(&[0x7F, b'E']));
}

#[test]
fn release_signature_verify_rejects_garbage_after_split() {
    // verify_release_signature moved to `release.rs`; a malformed signature
    // must still be a hard error (fail-closed trust gate).
    let err = API
        .verify_release_signature(b"data", "not-a-minisig")
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("malformed") || msg.contains("signature"),
        "malformed signature must be rejected with a signature error, got: {msg}"
    );
}

#[test]
fn release_public_constants_and_self_test_reachable_after_split() {
    assert_eq!(API.release_repo(), "santhsecurity/keyhog");
    assert!(API.release_public_key().starts_with("RWT"));
    // release_api_base default is always the real GitHub API. The offline
    // lifecycle tests use an explicit hidden argv seam; ambient env must not
    // redirect production update metadata.
    let base = API.release_api_base();
    assert_eq!(base, "https://api.github.com");
    // The scan-engine self-test plants a synthetic secret and round-trips it
    // through compile->scan->extract; it must still find the planted token.
    assert!(
        API.scan_engine_self_test().expect("self-test must run"),
        "scan_engine_self_test must detect its own planted secret after the split"
    );
}

#[test]
fn release_api_base_ignores_ambient_env_after_split() {
    std::env::set_var("KEYHOG_RELEASE_API_BASE", "http://attacker.invalid");
    assert_eq!(
        API.release_api_base(),
        "https://api.github.com",
        "ambient KEYHOG_RELEASE_API_BASE must not redirect production update metadata"
    );
    assert_eq!(
        API.release_api_base_with_override("http://127.0.0.1:1234/"),
        "http://127.0.0.1:1234",
        "offline tests must use the explicit argv/test seam instead"
    );
    std::env::remove_var("KEYHOG_RELEASE_API_BASE");
}

// ── local-install half: surface reachable + reaping behavior unchanged ──────

#[test]
fn local_install_reap_clears_orphans_keeps_unrelated_after_split() {
    // reap_stale_binaries stays in `installer.rs`. Confirm it still removes the
    // PID-scoped orphan artifacts and never touches the live binary or
    // unrelated siblings.
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("keyhog");
    std::fs::write(&exe, b"WORKING-BINARY").unwrap();

    let orphan_stash = dir.path().join(".keyhog.keyhog-old-4294967295");
    let orphan_backup = dir.path().join(".keyhog.keyhog-bak-4294967294");
    let orphan_tmp = dir.path().join(".keyhog-update-4294967293.tmp");
    let unrelated = dir.path().join("config.json");
    for p in [&orphan_stash, &orphan_backup, &orphan_tmp, &unrelated] {
        std::fs::write(p, b"x").unwrap();
    }

    API.reap_stale_binaries(&exe);

    assert!(!orphan_stash.exists(), "rename-away stash must be reaped");
    assert!(!orphan_backup.exists(), "rollback backup must be reaped");
    assert!(!orphan_tmp.exists(), "staging tmp must be reaped");
    assert!(
        unrelated.exists(),
        "unrelated sibling must be left untouched"
    );
    assert!(exe.exists(), "the live binary must never be reaped");
}

#[test]
fn local_install_rollback_restores_on_failed_verify_after_split() {
    // install_with_rollback stays in `installer.rs`. A new binary that fails
    // its injected health check must be rolled back to the prior working one.
    #[cfg(unix)]
    {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("keyhog");
        std::fs::write(&exe, b"GOOD").unwrap();

        // verify always fails -> rollback path -> original bytes restored.
        let err = API
            .install_with_rollback(&exe, b"BAD-NEW-BINARY", |_| false)
            .expect_err("a failing health check must error");
        assert!(
            err.to_string().contains("health check"),
            "rollback error must name the failed health check, got: {err}"
        );
        assert_eq!(
            std::fs::read(&exe).unwrap(),
            b"GOOD",
            "the prior working binary must be restored byte-for-byte on rollback"
        );
    }
}

/// Compile-time reachability: every installer symbol the subcommands call must
/// still resolve through the hidden test facade after the split. If any symbol
/// moved without wiring this fails to COMPILE.
#[test]
fn full_installer_call_surface_reachable_after_split() {
    let _release_api_base = || API.release_api_base();
    let _http_client = || API.http_client();
    let _parse_semver = |tag: &str| API.parse_semver(tag);
    let _is_newer = |current: &str, latest: &str| API.is_newer(current, latest);
    let _asset_name = |os: &str, arch: &str, cuda: bool| API.asset_name(os, arch, cuda);
    let _select_release_asset_name =
        |tag: &str, names: &[&str], cuda: bool| API.select_release_asset_name(tag, names, cuda);
    let _release_api_base_with_override = |base: &str| API.release_api_base_with_override(base);
    let _looks_like_native_executable = |bytes: &[u8]| API.looks_like_native_executable(bytes);
    let _verify_release_signature =
        |bytes: &[u8], signature: &str| API.verify_release_signature(bytes, signature);
    let _scan_engine_self_test = || API.scan_engine_self_test();
    let _current_binary = || API.current_binary();
    let _reap_stale_binaries = |exe: &std::path::Path| API.reap_stale_binaries(exe);
    let _backup_path = |exe: &std::path::Path| API.backup_path(exe);
    let _verify_via_doctor = |exe: &std::path::Path| API.verify_via_doctor(exe);
    let _verify_candidate_release =
        |exe: &std::path::Path, tag: &str, current: &str, allow: bool| {
            API.verify_candidate_release(exe, tag, current, allow)
        };
    #[cfg(unix)]
    {
        let _install_with_rollback_checked =
            |exe: &std::path::Path,
             bytes: &[u8],
             verify: fn(&std::path::Path) -> anyhow::Result<()>| {
                API.install_with_rollback_checked(exe, bytes, verify)
            };
    }
}
