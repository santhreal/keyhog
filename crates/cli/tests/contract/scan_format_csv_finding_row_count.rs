//! Contract: `--format csv` data rows match finding count exactly.

use crate::support::{binary, write_temp_file};
use std::process::Command;

fn parse_csv_row(row: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = row.chars().peekable();
    while let Some(ch) = chars.next() {
        if quoted {
            match ch {
                '"' if chars.peek() == Some(&'"') => {
                    field.push('"');
                    chars.next();
                }
                '"' => quoted = false,
                _ => field.push(ch),
            }
        } else {
            match ch {
                '"' if field.is_empty() => quoted = true,
                ',' => fields.push(std::mem::take(&mut field)),
                _ => field.push(ch),
            }
        }
    }
    fields.push(field);
    fields
}

#[test]
fn scan_format_csv_finding_row_count() {
    // Plant exactly one AWS key to guarantee one finding
    let (_dir, path) = write_temp_file("secret.env", "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
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
    let lines: Vec<&str> = stdout
        .lines()
        .filter(|line| !line.starts_with("# keyhog.scan.metadata="))
        .collect();
    assert!(
        lines.len() >= 2,
        "csv must have header + at least one data row"
    );

    // Line 0 is the header; line 1+ are findings. Verify there is exactly one data row.
    // Parse the RFC-4180 row rather than counting commas inside JSON columns.
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

    // Verify the data row has the expected field count.
    let fields = parse_csv_row(data_lines[0]);
    let field_count = fields.len();
    assert_eq!(
        field_count, 20,
        "csv data row must have exactly 20 fields, got {field_count}"
    );
    let metadata: serde_json::Value =
        serde_json::from_str(&fields[18]).expect("metadata JSON must parse");
    assert!(metadata["account_id"].is_string());
    assert_eq!(fields[19], "[]");
}
