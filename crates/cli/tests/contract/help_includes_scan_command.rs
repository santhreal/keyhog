//! Contract: top-level `--help` surfaces the primary `scan` subcommand.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn help_includes_scan_command() {
    let output = Command::new(binary())
        .arg("--help")
        .output()
        .expect("spawn keyhog --help");

    assert!(
        output.status.success(),
        "keyhog --help must exit 0, got {:?}",
        output.status.code()
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scan"),
        "help output must mention the scan subcommand, got: {stdout}"
    );
}
