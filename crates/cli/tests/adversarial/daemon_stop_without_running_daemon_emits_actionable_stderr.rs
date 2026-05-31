//! Adversarial: daemon stop with no server must fail with actionable stderr.

use crate::support::binary;
use std::process::Command;

#[test]
fn daemon_stop_without_running_daemon_emits_actionable_stderr() {
    let output = Command::new(binary())
        .args(["daemon", "stop"])
        .output()
        .expect("spawn daemon stop");
    assert_eq!(
        output.status.code(),
        Some(2),
        "daemon stop with no server must exit 2; stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("daemon") || stderr.contains("no daemon"),
        "stderr must mention daemon state; got: {stderr}"
    );
}
