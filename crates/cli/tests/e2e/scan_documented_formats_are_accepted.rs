//! E2E doc-to-binary output-format contract.
//!
//! The docs are a user-facing contract. This test extracts the documented
//! `scan --format` values from `docs/src/output-formats.md` and drives the real
//! binary with each value so a doc-only format cannot pass as a product feature.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn every_output_format_documented_in_user_docs_is_accepted_by_scan() {
    let doc = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/src/output-formats.md"
    ));
    let intro = doc
        .split("Pick the one")
        .next()
        .expect("output-formats.md intro paragraph");
    let documented: Vec<&str> = intro
        .split('`')
        .skip(1)
        .step_by(2)
        .filter(|value| *value != "--format")
        .collect();
    assert_eq!(
        documented,
        vec![
            "text",
            "json",
            "json-envelope",
            "jsonl",
            "jsonl-envelope",
            "sarif",
            "csv",
            "github-annotations",
            "gitlab-sast",
            "html",
            "junit"
        ],
        "docs/src/output-formats.md must enumerate the canonical eleven scan formats"
    );

    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("clean.txt");
    std::fs::write(&path, b"clean prose, no secrets here\n").expect("write clean fixture");

    for format in documented {
        let output = Command::new(binary())
            .arg("scan")
            .arg("--daemon=off")
            .arg("--backend")
            .arg("simd")
            .arg("--format")
            .arg(format)
            .arg(&path)
            .output()
            .unwrap_or_else(|error| panic!("spawn keyhog scan --format {format}: {error}"));

        assert_eq!(
            output.status.code(),
            Some(0),
            "documented scan format `{format}` must be accepted by the binary on a clean file; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
