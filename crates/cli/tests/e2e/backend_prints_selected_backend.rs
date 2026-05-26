//! E2E: `backend` subcommand names a selected backend.

use crate::e2e::support::run;

#[test]
fn backend_prints_selected_backend() {
    let output = run(&["backend"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
    assert!(
        stdout.contains("cpu") || stdout.contains("gpu") || stdout.contains("simd") || stdout.contains("mega"),
        "backend must name a backend; got: {stdout}"
    );
}
