//! Contract: top-level `--help` surfaces the `detectors` subcommand.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn help_includes_detectors_command() {
    let output = Command::new(binary()).arg("--help").output().expect("spawn");
    assert!(output.status.success(), "exit {:?}", output.status.code());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("detectors"), "help must mention detectors; got: {stdout}");
}
