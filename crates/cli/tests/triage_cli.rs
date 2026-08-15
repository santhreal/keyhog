#![cfg(unix)]

use keyhog_core::triage::{
    TriageDisposition, TriageEnvelope, TriageReason, TriageRecord, TriageScope,
    MAX_TRIAGE_INPUT_BYTES, TRIAGE_ENVELOPE_VERSION,
};
use keyhog_core::{EvidenceReasonCode, FindingProvenance, SemanticSourceRole};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::LazyLock;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

fn digest(value: &str) -> String {
    format!("blake3:{}", blake3::hash(value.as_bytes()).to_hex())
}

fn detector_id() -> &'static str {
    keyhog_core::embedded_detector_specs()
        .iter()
        .find(|detector| !detector.patterns.is_empty())
        .expect("embedded corpus has a regex detector")
        .id
        .as_str()
}

fn active_detector_digest() -> &'static str {
    static DIGEST: LazyLock<String> = LazyLock::new(|| {
        let scanner = keyhog_scanner::CompiledScanner::compile_with_gpu_policy(
            keyhog_core::load_embedded_detectors_or_fail().expect("load embedded detectors"),
            keyhog_scanner::GpuInitPolicy::ForceDisabled,
        )
        .expect("compile embedded scanner");
        format!("{:016x}", scanner.runtime_status().detector_digest)
    });
    DIGEST.as_str()
}

fn record(scope: TriageScope, finding: &str) -> TriageRecord {
    let detector_id = detector_id();
    TriageRecord {
        finding_hash: digest(finding),
        detector_id: detector_id.to_owned(),
        provenance: FindingProvenance::pattern(
            u64::from_str_radix(active_detector_digest(), 16).expect("active detector digest"),
            0,
            SemanticSourceRole::StandaloneToken,
            EvidenceReasonCode::UnsupportedContext,
        ),
        context_digest: digest("private-context-never-emit"),
        disposition: TriageDisposition::Dismissed,
        reason: TriageReason::FalsePositive,
        scope,
    }
}

fn write_envelope(path: &Path, records: Vec<TriageRecord>) {
    let envelope = TriageEnvelope {
        version: TRIAGE_ENVELOPE_VERSION,
        detector_digest: active_detector_digest().to_owned(),
        records,
    };
    std::fs::write(
        path,
        serde_json::to_vec(&envelope).expect("serialize envelope"),
    )
    .expect("write envelope");
}

fn run(input: &Path, suppressions: &Path, feedback: &Path) -> Output {
    Command::new(binary())
        .args(["triage", "--input"])
        .arg(input)
        .arg("--suppressions")
        .arg(suppressions)
        .arg("--pattern-feedback")
        .arg(feedback)
        .output()
        .expect("run keyhog triage")
}

#[test]
fn triage_help_pins_the_three_required_destinations() {
    let output = Command::new(binary())
        .args(["triage", "--help"])
        .output()
        .expect("run triage help");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("utf-8 help");
    for flag in ["--input", "--suppressions", "--pattern-feedback"] {
        assert!(stdout.contains(flag), "missing help flag {flag}");
    }
}

#[test]
fn triage_emitted_bytes_are_redacted_and_scopes_stay_separate() {
    let temp = TempDir::new().expect("tempdir");
    let raw_credential = "credential-PLAINTEXT-never-emit";
    let raw_context = "private-context-never-emit";
    let raw_path = "repository/private/path-never-emit.env";
    let raw_repository = "private-repository-location";
    let input = temp.path().join("redacted-input.json");
    let suppressions = temp.path().join("runtime.json");
    let feedback = temp.path().join("feedback.json");
    write_envelope(
        &input,
        vec![
            record(TriageScope::Exact, raw_credential),
            record(
                TriageScope::Path {
                    path_hash: digest(raw_path),
                },
                "path-finding",
            ),
            record(
                TriageScope::Repository {
                    repository_hash: digest(raw_repository),
                },
                "repository-finding",
            ),
            record(TriageScope::PatternFeedbackOnly, "training-only-finding"),
            {
                let mut confirmed = record(TriageScope::Exact, "confirmed-finding");
                confirmed.disposition = TriageDisposition::Confirmed;
                confirmed.reason = TriageReason::ConfirmedSecret;
                confirmed
            },
        ],
    );

    let output = run(&input, &suppressions, &feedback);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let runtime_bytes = std::fs::read(&suppressions).expect("runtime output");
    let feedback_bytes = std::fs::read(&feedback).expect("feedback output");
    let mut every_emitted_byte = Vec::new();
    every_emitted_byte.extend_from_slice(&output.stdout);
    every_emitted_byte.extend_from_slice(&output.stderr);
    every_emitted_byte.extend_from_slice(&runtime_bytes);
    every_emitted_byte.extend_from_slice(&feedback_bytes);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&suppressions)
            .expect("runtime metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(&feedback)
            .expect("feedback metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let emitted = String::from_utf8(every_emitted_byte).expect("utf-8 emitted bytes");
    for plaintext in [
        raw_credential,
        raw_context,
        raw_path,
        raw_repository,
        temp.path().to_str().expect("temporary path"),
    ] {
        assert!(
            !emitted.contains(plaintext),
            "emitted bytes retained supplied plaintext {plaintext:?}"
        );
    }

    let runtime = keyhog_core::triage::RuntimeSuppressions::from_json(
        &runtime_bytes,
        active_detector_digest(),
    )
    .expect("runtime contract");
    assert_eq!(runtime.suppressions.len(), 3);
    let expected_provenance = record(TriageScope::Exact, "identity-only").provenance;
    assert!(
        runtime
            .suppressions
            .iter()
            .all(|record| record.provenance == expected_provenance),
        "runtime output changed scanner provenance"
    );
    let pattern =
        keyhog_core::triage::PatternFeedback::from_json(&feedback_bytes, active_detector_digest())
            .expect("feedback contract");
    assert_eq!(pattern.feedback.len(), 5);
    assert!(
        pattern
            .feedback
            .iter()
            .all(|record| record.provenance == expected_provenance),
        "training output changed scanner provenance"
    );
    assert!(
        keyhog_core::triage::RuntimeSuppressions::from_json(
            &feedback_bytes,
            active_detector_digest(),
        )
        .is_err(),
        "pattern feedback became parseable runtime suppression"
    );
}

#[test]
fn triage_symlinks_parent_traversal_and_oversized_input_fail_without_outputs() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("tempdir");
    let real_input = temp.path().join("real.json");
    write_envelope(&real_input, vec![record(TriageScope::Exact, "finding")]);
    let linked_input = temp.path().join("linked.json");
    symlink(&real_input, &linked_input).expect("input symlink");
    let runtime = temp.path().join("runtime.json");
    let feedback = temp.path().join("feedback.json");
    let linked = run(&linked_input, &runtime, &feedback);
    assert!(!linked.status.success());
    assert!(!runtime.exists() && !feedback.exists());

    let oversized = temp.path().join("oversized.json");
    std::fs::write(&oversized, vec![b'x'; MAX_TRIAGE_INPUT_BYTES + 1]).expect("oversized input");
    let runtime = temp.path().join("runtime-oversized.json");
    let feedback = temp.path().join("feedback-oversized.json");
    let too_large = run(&oversized, &runtime, &feedback);
    assert!(!too_large.status.success());
    assert!(!runtime.exists() && !feedback.exists());

    let traversal = temp.path().join("missing").join("..").join("escaped.json");
    let escaped = temp.path().join("escaped.json");
    let feedback = temp.path().join("feedback-traversal.json");
    let rejected = run(&real_input, &traversal, &feedback);
    assert!(!rejected.status.success());
    assert!(!escaped.exists() && !feedback.exists());

    let linked_output = temp.path().join("linked-output.json");
    let target = temp.path().join("target.json");
    std::fs::write(&target, b"unchanged").expect("output target");
    symlink(&target, &linked_output).expect("output symlink");
    let feedback = temp.path().join("feedback-linked.json");
    let rejected = run(&real_input, &linked_output, &feedback);
    assert!(!rejected.status.success());
    assert_eq!(std::fs::read(&target).expect("target bytes"), b"unchanged");
    assert!(!feedback.exists());
}

#[test]
fn triage_malformed_secret_bearing_input_is_rejected_without_echo_or_artifacts() {
    let temp = TempDir::new().expect("tempdir");
    let supplied_secret = "malicious-credential-never-echo";
    let input = temp.path().join("malicious.json");
    let runtime = temp.path().join("runtime-malicious.json");
    let feedback = temp.path().join("feedback-malicious.json");
    let envelope = TriageEnvelope {
        version: TRIAGE_ENVELOPE_VERSION,
        detector_digest: active_detector_digest().to_owned(),
        records: vec![record(TriageScope::Exact, "finding")],
    };
    let mut value = serde_json::to_value(envelope).expect("serialize envelope");
    value["records"][0]["raw_context"] = serde_json::Value::String(supplied_secret.to_owned());
    std::fs::write(
        &input,
        serde_json::to_vec(&value).expect("serialize mutation"),
    )
    .expect("write malicious input");

    let output = run(&input, &runtime, &feedback);
    assert!(!output.status.success());
    assert!(!runtime.exists() && !feedback.exists());
    let mut emitted = output.stdout;
    emitted.extend_from_slice(&output.stderr);
    assert!(
        !String::from_utf8(emitted)
            .expect("utf-8 process output")
            .contains(supplied_secret),
        "error output echoed rejected credential or context bytes"
    );
}
