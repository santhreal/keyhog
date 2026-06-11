//! Contract: `keyhog --version` exits 0 and prints semver.

use std::process::Command;

#[test]
fn version_flag_exits_zero_and_prints_semver() {
    let bin = env!("CARGO_BIN_EXE_keyhog");
    let out = Command::new(bin)
        .arg("--version")
        .output()
        .expect("spawn keyhog");

    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("KeyHog v"),
        "version output must include KeyHog v prefix: {stdout}"
    );
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "version must match crate semver"
    );
}

/// MC-06: build provenance must be surfaced in `--version`. `build.rs` stamps the
/// git commit and the embedded-detector-set digest, but for a long while nothing
/// READ them (a Law-11 stamped-but-dead gap) — so `tuned==benched==shipped` was
/// unverifiable and a stale binary reported the same version string as HEAD.
/// This pins the surfacing: the commit line and the detector-set line must be
/// present, and the printed digest + count must match the values the linked
/// `keyhog_core` was built with (so an embed-time drift is caught here).
#[test]
fn version_flag_surfaces_commit_and_detector_provenance() {
    let bin = env!("CARGO_BIN_EXE_keyhog");
    let out = Command::new(bin)
        .arg("--version")
        .output()
        .expect("spawn keyhog");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        stdout.contains("Commit:"),
        "version must surface the build commit (MC-06): {stdout}"
    );
    assert!(
        stdout.contains(keyhog_core::git_hash()),
        "version commit line must print keyhog_core::git_hash() ({}): {stdout}",
        keyhog_core::git_hash()
    );

    assert!(
        stdout.contains("Detector Set:"),
        "version must surface the embedded detector set (MC-06): {stdout}"
    );
    assert!(
        stdout.contains(keyhog_core::detector_digest()),
        "version must print the embedded detector digest ({}): {stdout}",
        keyhog_core::detector_digest()
    );
    assert!(
        stdout.contains(&keyhog_core::embedded_detector_count().to_string()),
        "version must print the embedded detector count ({}): {stdout}",
        keyhog_core::embedded_detector_count()
    );
}
