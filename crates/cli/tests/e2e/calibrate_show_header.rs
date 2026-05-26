//! E2E: `calibrate --show` prints calibration header.

use crate::e2e::support::run;

#[test]
fn calibrate_show_header() {
    let output = run(&["calibrate", "--show"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("calibration"),
        "calibrate --show must print header; got: {stdout}"
    );
}
