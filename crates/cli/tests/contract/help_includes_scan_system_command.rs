//! Contract: top-level `--help` surfaces the `scan-system` subcommand.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn help_includes_scan_system_command() {
    let output = Command::new(binary()).arg("--help").output().expect("spawn");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("scan-system"), "help must mention scan-system; got: {stdout}");
}
