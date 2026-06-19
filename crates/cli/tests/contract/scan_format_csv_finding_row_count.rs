//! Contract: `--format csv` data rows match finding count exactly.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_format_csv_finding_row_count() {
    // Plant exactly one AWS key to guarantee one finding
    let (_dir, path) = write_temp_file("secret.env", "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "simd",
            "--format",
            "csv",
            "--no-suppress-test-fixtures",
        ])
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(
        output.status.code(),
        Some(1),
        "scan with finding must exit 1"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines.len() >= 2,
        "csv must have header + at least one data row"
    );

    // Line 0 is the header; line 1+ are findings. Verify there is exactly one data row.
    // (A well-formed finding will have 15 comma-separated fields per the CSV header.)
    let data_lines: Vec<&str> = lines
        .iter()
        .skip(1)
        .filter(|l| !l.is_empty())
        .copied()
        .collect();
    assert_eq!(
        data_lines.len(),
        1,
        "exactly one finding was planted; csv must emit exactly one data row, got {}",
        data_lines.len()
    );

    // Verify the data row has the expected field count (15 fields means 14 commas)
    let field_count = data_lines[0].matches(',').count() + 1;
    assert_eq!(
        field_count, 15,
        "csv data row must have exactly 15 fields, got {field_count}"
    );
}
