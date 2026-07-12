//! E2E: `explain aws-access-key` prints detector metadata.

use crate::e2e::support::run;

#[test]
fn explain_aws_access_key() {
    let output = run(&["explain", "aws-access-key"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
    // Law 6: pin the EXACT detector id (no loose `|| "aws"` fallback that a bare
    // "aws" anywhere would satisfy) AND the concrete severity value the renderer
    // prints (`Severity: {Critical}` → lowercased "critical").
    assert!(
        stdout.contains("aws-access-key"),
        "explain must name the exact detector id aws-access-key; got: {stdout}"
    );
    assert!(
        stdout.contains("critical"),
        "explain must report the aws-access-key severity (critical); got: {stdout}"
    );
}
