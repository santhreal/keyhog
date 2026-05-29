use keyhog::installer::{
    asset_name, is_newer, looks_like_native_executable, parse_semver, scan_engine_self_test,
    verify_release_signature,
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
    assert_eq!(asset_name("windows", "x86_64", false), None);
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
