//! Contract: `--format csv` emits documented header fields.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_format_csv_header_fields() {
    let (_dir, path) = write_temp_file("clean.txt", "no secrets here\n");
    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--format", "csv"])
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(
        output.status.code(),
        Some(0),
        "clean scan with csv format must exit 0"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let header = stdout
        .lines()
        .next()
        .expect("csv must have at least a header");

    // Verify exact field names as documented in CsvReporter::new()
    let expected_fields = [
        "detector_id",
        "detector_name",
        "service",
        "severity",
        "credential_redacted",
        "credential_hash",
        "source",
        "file_path",
        "line",
        "offset",
        "commit",
        "author",
        "date",
        "verification",
        "confidence",
    ];

    for field in &expected_fields {
        assert!(
            header.contains(field),
            "csv header must contain field '{field}'; got: {header}"
        );
    }

    // Verify field order by checking the exact header line
    assert_eq!(
        header.trim(),
        "detector_id,detector_name,service,severity,credential_redacted,credential_hash,source,file_path,line,offset,commit,author,date,verification,confidence",
        "csv header must be exactly the documented field list in order"
    );
}
