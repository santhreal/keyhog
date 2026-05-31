//! R5-T contract: backend --help documents --json.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn r5t_backend_help_documents_json_flag() {
    let output = Command::new(binary())
        .args(["backend", "--help"])
        .output()
        .expect("spawn backend --help");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--json"),
        "backend help must document --json; got: {stdout}"
    );
}
