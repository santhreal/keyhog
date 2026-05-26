//! E2E: `explain aws-access-key` prints detector metadata.

use crate::e2e::support::run;

#[test]
fn explain_aws_access_key() {
    let output = run(&["explain", "aws-access-key"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
    assert!(stdout.contains("aws-access-key") || stdout.contains("aws"), "explain must describe aws-access-key; got: {stdout}");
}
