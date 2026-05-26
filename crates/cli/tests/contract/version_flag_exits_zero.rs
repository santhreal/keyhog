//! Contract: `keyhog --version` exits 0 and prints the crate semver.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn version_flag_exits_zero_with_semver() {
    let output = Command::new(binary())
        .arg("--version")
        .output()
        .expect("spawn keyhog --version");

    assert!(
        output.status.success(),
        "keyhog --version must exit 0, got {:?}",
        output.status.code()
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let version = env!("CARGO_PKG_VERSION");
    assert!(
        stdout.contains(version),
        "stdout must contain semver {version}, got: {stdout}"
    );
}
