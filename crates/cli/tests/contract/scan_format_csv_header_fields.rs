//! Contract: `--format csv` emits documented header fields.

use crate::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_format_csv_header_fields() {
    let (_dir, path) = write_temp_file("clean.txt", "no secrets here\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "simd",
            "--format",
            "csv",
        ])
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
        .find(|line| !line.starts_with("# keyhog.scan.metadata="))
        .expect("csv must have at least a header");

    // Verify exact field names as documented in CsvReporter::new()
    let expected_fields = [
        "detector_id",
        "detector_name",
        "service",
        "severity",
        "credential_redacted",
        "credential_hash",
        "companions_redacted",
        "source",
        "file_path",
        "line",
        "offset",
        "commit",
        "author",
        "date",
        "verification",
        "confidence",
        "entropy",
        "remediation",
        "metadata",
        "additional_locations",
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
        "detector_id,detector_name,service,severity,credential_redacted,credential_hash,companions_redacted,source,file_path,line,offset,commit,author,date,verification,confidence,entropy,remediation,metadata,additional_locations",
        "csv header must be exactly the documented field list in order"
    );
}
