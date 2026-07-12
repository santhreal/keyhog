//! Contract: `--format junit` emits valid JUnit XML with testsuites/testcase structure.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_format_junit_testcase_structure() {
    let (_dir, path) = write_temp_file("secret.env", "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "simd",
            "--format",
            "junit",
            "--no-suppress-test-fixtures",
        ])
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify XML declaration
    assert!(
        stdout.starts_with("<?xml version"),
        "junit must start with XML declaration; got: {:.80}",
        stdout
    );

    // Verify root testsuites element
    assert!(
        stdout.contains("<testsuites>"),
        "junit must have root <testsuites> element"
    );
    assert!(
        stdout.contains("</testsuites>"),
        "junit must have closing </testsuites> tag"
    );

    // Verify testsuite with keyhog name and attributes
    assert!(
        stdout.contains("<testsuite name=\"keyhog\""),
        "junit must have <testsuite name=\"keyhog\""
    );
    assert!(
        stdout.contains("tests="),
        "junit testsuite must include 'tests' attribute"
    );
    assert!(
        stdout.contains("failures="),
        "junit testsuite must include 'failures' attribute"
    );

    // Verify testcase element
    assert!(
        stdout.contains("<testcase"),
        "junit must contain <testcase> elements"
    );
    assert!(
        stdout.contains("classname=\"keyhog.findings\""),
        "junit testcase must use classname=\"keyhog.findings\""
    );

    // Verify failure element (findings are reported as failures in junit)
    assert!(
        stdout.contains("<failure"),
        "junit must report findings as <failure> elements"
    );
    assert!(
        stdout.contains("</failure>"),
        "junit must close <failure> elements"
    );

    // Verify test count matches finding count (at least 1)
    let tests_attr = stdout
        .split("tests=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .and_then(|s| s.parse::<usize>().ok());
    assert_eq!(
        tests_attr,
        Some(1),
        "junit testsuite tests count must be 1 for the planted secret"
    );
}
