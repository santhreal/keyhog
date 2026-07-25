//! Real-process contracts for `keyhog bloom-diagnostic`.
//!
//! These fixtures are deliberately tiny and synthetic: the command must expose
//! exact corpus accounting and actionable failures without depending on the
//! benchmark checkout or on source-level assertions.

use crate::e2e::support::binary;
use serde_json::{json, Value};
use std::process::{Command, Output};
use tempfile::TempDir;

const SCHEMA: &str = "keyhog-bloom-corpus-v1";
const PLANTED_AWS: &str = "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"";

fn run_diagnostic(fixture: &std::path::Path, corpus_root: &std::path::Path) -> Output {
    Command::new(binary())
        .arg("bloom-diagnostic")
        .args(["--fixture", fixture.to_str().expect("UTF-8 fixture path")])
        .args([
            "--corpus-root",
            corpus_root.to_str().expect("UTF-8 corpus-root path"),
        ])
        .output()
        .expect("spawn keyhog bloom-diagnostic")
}

fn write_fixture(dir: &TempDir, fixture: Value) -> std::path::PathBuf {
    let path = dir.path().join("fixture.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&fixture).expect("serialize Bloom fixture"),
    )
    .expect("write Bloom fixture");
    path
}

/// Positive and 64-byte boundary contract: a 63-byte miss is ineligible, a
/// 64-byte miss is rejected, and a 64-byte planted AWS line is admitted. The
/// operator receipt must therefore report exactly 3/2/2/1 inputs for
/// total/eligible/admitted/rejected and one identical finding on both paths.
#[test]
fn bloom_diagnostic_reports_exact_boundary_and_parity_receipt() {
    let corpus = TempDir::new().expect("Bloom corpus root");
    let below_threshold = "~".repeat(63);
    let at_threshold = "~".repeat(64);
    let planted = format!("{PLANTED_AWS:<64}");
    assert_eq!(below_threshold.len(), 63);
    assert_eq!(at_threshold.len(), 64);
    assert_eq!(planted.len(), 64);
    std::fs::write(corpus.path().join("below.txt"), below_threshold)
        .expect("write below-threshold input");
    std::fs::write(corpus.path().join("threshold.txt"), at_threshold)
        .expect("write threshold input");
    std::fs::write(corpus.path().join("secret.txt"), planted).expect("write planted input");

    let fixture = write_fixture(
        &corpus,
        json!({
            "schema_version": SCHEMA,
            "corpus_name": "cli-e2e-boundary",
            "corpus_revision": "revision-1",
            "declared_input_count": 3,
            "unavailable_inputs": [],
            "inputs": [
                {"id": "below", "path": "below.txt", "labels": ["F"], "line_start": 1, "line_end": 1},
                {"id": "threshold", "path": "threshold.txt", "labels": ["X"], "line_start": 1, "line_end": 1},
                {"id": "secret", "path": "secret.txt", "labels": ["F"], "line_start": 1, "line_end": 1}
            ]
        }),
    );

    let output = run_diagnostic(&fixture, corpus.path());
    assert_eq!(
        output.status.code(),
        Some(0),
        "valid diagnostic must exit 0; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stderr, b"", "successful diagnostics are stdout-only");
    let receipt: Value = serde_json::from_slice(&output.stdout).expect("Bloom evidence JSON");

    for (field, expected) in [
        ("schema_version", json!("bloom-evidence-v1")),
        ("corpus_name", json!("cli-e2e-boundary")),
        ("corpus_revision", json!("revision-1")),
        ("declared_input_count", json!(3)),
        ("unavailable_input_count", json!(0)),
        ("unavailable_reason_counts", json!({})),
        ("input_count", json!(3)),
        ("eligible_input_count", json!(2)),
        ("admitted_input_count", json!(2)),
        ("rejected_input_count", json!(1)),
        ("rejection_basis_points", json!(3_333)),
        ("total_slots", json!(65_536)),
        ("saturation_threshold_slots", json!(39_322)),
        ("state", json!("healthy")),
        ("enabled_finding_count", json!(1)),
        ("bypass_finding_count", json!(1)),
        ("findings_identical", json!(true)),
    ] {
        assert_eq!(receipt[field], expected, "exact receipt field {field}");
    }
    assert_eq!(
        receipt["enabled_findings_sha256"], receipt["bypass_findings_sha256"],
        "the two operator-visible parity digests must agree"
    );
}

/// Negative contract: a fixture from another schema generation is rejected
/// before corpus access, with exit 2, empty stdout, and the exact remediation
/// detail naming both the received and supported schema versions.
#[test]
fn bloom_diagnostic_rejects_unsupported_fixture_schema_exactly() {
    let corpus = TempDir::new().expect("Bloom corpus root");
    let fixture = write_fixture(
        &corpus,
        json!({
            "schema_version": "keyhog-bloom-corpus-v0",
            "corpus_name": "obsolete",
            "corpus_revision": "revision-0",
            "declared_input_count": 1,
            "unavailable_inputs": [],
            "inputs": [
                {"id": "unused", "path": "unused.txt", "labels": ["F"], "line_start": 1, "line_end": 1}
            ]
        }),
    );

    let output = run_diagnostic(&fixture, corpus.path());
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, b"");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "error: unsupported Bloom corpus fixture schema \"keyhog-bloom-corpus-v0\"; expected keyhog-bloom-corpus-v1\n"
    );
}

/// Boundary/error contract: fixture paths must stay relative to the declared
/// corpus root. A parent traversal is rejected before any file is opened, with
/// the exact offending path visible to the operator and no data on stdout.
#[test]
fn bloom_diagnostic_rejects_parent_traversal_exactly() {
    let corpus = TempDir::new().expect("Bloom corpus root");
    let fixture = write_fixture(
        &corpus,
        json!({
            "schema_version": SCHEMA,
            "corpus_name": "unsafe-path",
            "corpus_revision": "revision-1",
            "declared_input_count": 1,
            "unavailable_inputs": [],
            "inputs": [
                {"id": "escape", "path": "../outside.txt", "labels": ["X"], "line_start": 1, "line_end": 1}
            ]
        }),
    );

    let output = run_diagnostic(&fixture, corpus.path());
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, b"");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "error: Bloom corpus fixture input is not a safe relative path: ../outside.txt\n"
    );
}
