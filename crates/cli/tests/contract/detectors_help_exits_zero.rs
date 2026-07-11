//! Contract: `keyhog detectors --help` exits 0.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn detectors_help_exits_zero() {
    let output = Command::new(binary())
        .args(["detectors", "--help"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--format"),
        "detectors help must document canonical --format; got: {stdout}"
    );
    assert!(
        !stdout.contains("--json"),
        "detectors help must not advertise the compatibility spelling: {stdout}"
    );
    assert!(
        !stdout.contains("[VERB]") && !stdout.contains("detectors list"),
        "detectors help must not advertise the redundant list verb: {stdout}"
    );

    let retired_json = Command::new(binary())
        .args(["detectors", "--json"])
        .output()
        .expect("spawn retired json spelling");
    assert_eq!(retired_json.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&retired_json.stderr);
    assert!(
        stderr.contains("unexpected argument '--json'"),
        "retired detector JSON flag must be rejected visibly; got: {stderr}"
    );

    let retired_list = Command::new(binary())
        .args(["detectors", "list"])
        .output()
        .expect("spawn retired list spelling");
    assert_eq!(retired_list.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&retired_list.stderr);
    assert!(
        stderr.contains("unexpected argument 'list'"),
        "retired duplicate list verb must be rejected visibly; got: {stderr}"
    );
}
