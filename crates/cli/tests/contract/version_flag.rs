//! Contract: `keyhog --version` exits 0 and prints semver.

use std::process::Command;

#[test]
fn version_flag_exits_zero_and_prints_semver() {
    let bin = env!("CARGO_BIN_EXE_keyhog");
    let out = Command::new(bin)
        .arg("--version")
        .output()
        .expect("spawn keyhog");

    assert_eq!(out.status.code(), Some(0), "stderr={}", String::from_utf8_lossy(&out.stderr));

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
