use keyhog::installer::{
    asset_name, is_newer, looks_like_native_executable, parse_semver, scan_engine_self_test,
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
