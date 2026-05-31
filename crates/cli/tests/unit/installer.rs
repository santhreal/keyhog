use keyhog::installer::{
    asset_name, download_verified_asset, http_client, is_newer, looks_like_native_executable,
    parse_semver, reap_stale_binaries, replace_running_binary, scan_engine_self_test,
    verify_release_signature, Asset,
};

#[test]
fn asset_name_matches_release_convention() {
    assert_eq!(
        asset_name("linux", "x86_64", false).as_deref(),
        Some("keyhog-linux-x86_64")
    );
    assert_eq!(
        asset_name("linux", "x86_64", true).as_deref(),
        Some("keyhog-linux-x86_64-cuda")
    );
    assert_eq!(
        asset_name("macos", "aarch64", false).as_deref(),
        Some("keyhog-macos-aarch64")
    );
    assert_eq!(
        asset_name("macos", "x86_64", false).as_deref(),
        Some("keyhog-macos-x86_64")
    );
    // macOS has no CUDA build - cuda flag is ignored, no `-cuda` suffix.
    assert_eq!(
        asset_name("macos", "aarch64", true).as_deref(),
        Some("keyhog-macos-aarch64")
    );
    // Windows x86_64: release.yml uploads keyhog-windows-x86_64.exe, so
    // `update`/`repair` must resolve it (previously returned None, which
    // left both commands dead on Windows). CUDA has no Windows asset, so
    // the flag is ignored - no `-cuda` suffix.
    assert_eq!(
        asset_name("windows", "x86_64", false).as_deref(),
        Some("keyhog-windows-x86_64.exe")
    );
    assert_eq!(
        asset_name("windows", "x86_64", true).as_deref(),
        Some("keyhog-windows-x86_64.exe")
    );
    // Unsupported (os, arch) pairs still yield None.
    assert_eq!(asset_name("windows", "aarch64", false), None);
    assert_eq!(asset_name("linux", "riscv64", false), None);
}

#[test]
fn semver_parsing_handles_v_prefix_and_suffix() {
    assert_eq!(parse_semver("v0.5.36"), Some((0, 5, 36)));
    assert_eq!(parse_semver("0.5.36"), Some((0, 5, 36)));
    assert_eq!(parse_semver("v1.2.3-rc1"), Some((1, 2, 3)));
    assert_eq!(parse_semver("garbage"), None);
    assert_eq!(parse_semver("v1.2"), None);
}

#[test]
fn is_newer_compares_correctly() {
    assert!(is_newer("0.5.35", "v0.5.36"));
    assert!(is_newer("0.5.35", "0.6.0"));
    assert!(is_newer("0.5.35", "1.0.0"));
    assert!(!is_newer("0.5.36", "v0.5.36"));
    assert!(!is_newer("0.5.36", "v0.5.35"));
    assert!(!is_newer("0.5.35", "garbage"));
}

#[test]
fn rejects_non_executable_download() {
    assert!(!looks_like_native_executable(
        b"<!DOCTYPE html><html>Not Found"
    ));
    assert!(!looks_like_native_executable(b""));
    #[cfg(target_os = "linux")]
    assert!(looks_like_native_executable(&[
        0x7F, b'E', b'L', b'F', 2, 1, 1, 0
    ]));
}

#[test]
fn self_test_detects_planted_secret() {
    // The doctor/repair self-test must actually fire end-to-end.
    assert!(scan_engine_self_test().expect("self-test runs"));
}

// A real minisign signature of FIXTURE_DATA, produced by the keyhog release
// secret key whose public half is embedded as installer::RELEASE_PUBLIC_KEY.
// This proves the embedded key verifies a genuine release signature and that
// any tampering (wrong data, mangled signature) is rejected.
const FIXTURE_DATA: &[u8] = b"keyhog-signature-test-v1\n";
const FIXTURE_SIG: &str = "untrusted comment: signature from rsign secret key\n\
RUTPnJ/p6xVJ3REkJ9dhxwKQpEisq7Y2A4uIZlUzPRM0zDjWidV3sIXjHB8d558++9M0KpCpz6T8efYlVFl/RZhrKIznrUZSGww=\n\
trusted comment: timestamp:1780025193\tfile:/tmp/claude-1000/tmp.JTQWgRt5FO/fixture.bin\tprehashed\n\
L/wvGiwIhpaBlkEUaQ364Q8ph9ksqIxJyIMy1RQbs/QS4+q8biUaJGt+0weV4E0IV/pPHywDFtZhvUD03un2CA==\n";

#[test]
fn release_signature_verifies_against_embedded_key() {
    verify_release_signature(FIXTURE_DATA, FIXTURE_SIG)
        .expect("a genuine signature must verify against the embedded public key");
}

#[test]
fn release_signature_rejects_tampered_payload() {
    // Same signature, different bytes: the update must be refused.
    assert!(
        verify_release_signature(b"tampered binary contents", FIXTURE_SIG).is_err(),
        "a signature must not verify against payload it didn't sign"
    );
}

#[test]
fn release_signature_rejects_malformed_signature() {
    assert!(verify_release_signature(FIXTURE_DATA, "not a minisig file").is_err());
    assert!(verify_release_signature(FIXTURE_DATA, "").is_err());
}

// ── Moved from src/installer.rs (#[cfg(test)] mod rename_away_tests) per the
//    no_inline_tests_in_src gate. Cross-platform rename-away self-replace that
//    backs `keyhog update`/`repair` on Windows; same std::fs::rename semantics
//    on every OS, so the Linux host exercises the exact Windows code path.

#[test]
fn replace_success_installs_new_and_returns_stash() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("keyhog");
    std::fs::write(&exe, b"OLD-WORKING-BINARY").unwrap();

    let stash = replace_running_binary(&exe, b"NEW-GOOD-BINARY", |_| true)
        .expect("replace should succeed when verify passes");

    assert_eq!(std::fs::read(&exe).unwrap(), b"NEW-GOOD-BINARY");
    let stash = stash.expect("a prior binary existed, so a stash is returned");
    // The caller reaps the stash; until then it holds the old bytes.
    assert_eq!(std::fs::read(&stash).unwrap(), b"OLD-WORKING-BINARY");
    reap_stale_binaries(&exe);
    assert!(!stash.exists(), "reap must remove the stash");
}

#[test]
fn replace_failure_rolls_back_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("keyhog");
    // Arbitrary bytes incl. NULs/high bytes: rollback must be exact.
    let original: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    std::fs::write(&exe, &original).unwrap();

    let err = replace_running_binary(&exe, b"NEW-BROKEN-BINARY", |_| false)
        .expect_err("replace must fail when verify rejects the new binary");
    assert!(format!("{err}").contains("rolled back"));
    assert_eq!(
        std::fs::read(&exe).unwrap(),
        original,
        "rollback must restore the original binary byte-for-byte"
    );
    // No stash left orphaned beside the exe after a rollback.
    reap_stale_binaries(&exe);
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains("keyhog-old"))
        .collect();
    assert!(leftovers.is_empty(), "rollback must not leave a stash");
}

#[test]
fn fresh_install_failure_removes_broken_binary() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("keyhog");
    // No prior binary: a failed verify must not leave a broken executable.
    let err = replace_running_binary(&exe, b"BROKEN", |_| false)
        .expect_err("fresh install must fail when verify rejects it");
    assert!(format!("{err}").contains("no prior binary"));
    assert!(!exe.exists(), "broken fresh install must be removed");
}

#[test]
fn reap_only_touches_this_binarys_stashes() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("keyhog");
    std::fs::write(&exe, b"bin").unwrap();
    let mine = dir.path().join(".keyhog.keyhog-old-99999");
    let other = dir.path().join("unrelated.txt");
    std::fs::write(&mine, b"old").unwrap();
    std::fs::write(&other, b"keep").unwrap();

    reap_stale_binaries(&exe);
    assert!(!mine.exists(), "matching stash must be reaped");
    assert!(other.exists(), "unrelated files must be left alone");
    assert!(exe.exists(), "the live binary must never be reaped");
}

// Supply-chain: a missing `.minisig` must FAIL CLOSED. A forged 404 on the
// signature URL (active MITM / compromised CDN serving a tampered binary)
// otherwise bypassed the entire minisign gate. Linux-gated because the served
// asset must pass `looks_like_native_executable` (ELF magic) to reach the
// signature-fetch branch; the CI test/integration jobs run on linux.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn unsigned_release_download_fails_closed() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    let mut elf = vec![0x7F, b'E', b'L', b'F'];
    elf.extend_from_slice(&[0u8; 64]);
    let asset_path = "/download/keyhog-linux-x86_64";
    let body = elf.clone();
    server.mock(|when, then| {
        when.method(GET).path(asset_path);
        then.status(200).body(body);
    });
    server.mock(|when, then| {
        when.method(GET).path(format!("{asset_path}.minisig"));
        then.status(404).body("Not Found");
    });
    let asset = Asset {
        name: "keyhog-linux-x86_64".to_string(),
        browser_download_url: format!("{}{}", server.base_url(), asset_path),
    };
    let res = download_verified_asset(&http_client().unwrap(), &asset).await;
    assert!(
        res.is_err(),
        "a missing .minisig must fail closed (refuse), not install on HTTPS-only trust"
    );
    let msg = format!("{:#}", res.unwrap_err());
    assert!(
        msg.contains(".minisig") || msg.to_lowercase().contains("signature"),
        "error must name the missing signature as the reason: {msg}"
    );
}
