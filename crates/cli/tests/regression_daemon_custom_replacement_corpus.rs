//! Production-path regression coverage for daemon replacement-corpus identity.

#![cfg(unix)]

use serde_json::Value;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const CUSTOM_TOKEN: &str = "demo_secret_ABCD1234";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

fn write_detector(directory: &Path, id: &str) {
    std::fs::create_dir_all(directory).expect("create detector directory");
    let toml = r#"
[detector]
id = "__DETECTOR_ID__"
name = "Daemon custom fixture"
service = "fixture"
severity = "high"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
match_confidence = { literal_prefix_weight = 0.35, context_anchor_weight = 0.20, entropy_weight = 0.20, high_entropy_partial_weight = 0.12, moderate_entropy_threshold = 3.0, moderate_entropy_weight = 0.05, low_entropy_penalty_floor = 2.0, low_entropy_min_match_length = 10, low_entropy_penalty_multiplier = 0.60, keyword_nearby_weight = 0.10, sensitive_file_weight = 0.10, companion_weight = 0.05, very_high_entropy_margin = 1.3, named_anchor_floor = 0.55, assignment_context_multiplier = 1.0, string_literal_context_multiplier = 0.9, unknown_context_multiplier = 0.8, documentation_context_multiplier = 0.3, comment_context_multiplier = 0.4, test_context_multiplier = 0.3, encrypted_context_multiplier = 0.05, soft_context_suppression_threshold = 0.5, encrypted_context_suppression_threshold = 0.8, post_match = { placeholder_multiplier = 0.05, minimum_byte_diversity = 0.1, low_diversity_multiplier = 0.1, maximum_repeat_ratio = 0.8, degenerate_run_min_length = 10, degenerate_repeat_multiplier = 0.1, fixture_path_multiplier = 0.5, ml_context_reapply_below = 0.95 } }
keywords = ["demo_secret_"]

[[detector.patterns]]
regex = "demo_secret_[A-Z0-9]{8}"
"#
    .replace("__DETECTOR_ID__", id);
    std::fs::write(directory.join("custom.toml"), toml).expect("write custom detector");
}

struct RunningDaemon {
    child: Child,
    socket: PathBuf,
}

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        let _ = Command::new(binary())
            .args(["daemon", "stop", "--socket"])
            .arg(&self.socket)
            .output();
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

fn start_daemon(root: &Path, detectors: &Path) -> RunningDaemon {
    let socket = root.join("custom.sock");
    let child = Command::new(binary())
        .current_dir(root)
        .args(["daemon", "start", "--socket"])
        .arg(&socket)
        .args(["--detectors"])
        .arg(detectors)
        .args(["--backend", "cpu"])
        .env("HOME", root)
        .env("XDG_DATA_HOME", root.join("xdg-data"))
        .env("XDG_CACHE_HOME", root.join("xdg-cache"))
        .env_remove("KEYHOG_BACKEND")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("start custom-corpus daemon");

    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if socket.exists() && UnixStream::connect(&socket).is_ok() {
            return RunningDaemon { child, socket };
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("custom-corpus daemon did not become ready within 30 seconds");
}

fn start_default_daemon(root: &Path) -> RunningDaemon {
    let socket = root.join("default.sock");
    let child = Command::new(binary())
        .current_dir(root)
        .args(["daemon", "start", "--socket"])
        .arg(&socket)
        .args(["--backend", "cpu"])
        .env("HOME", root)
        .env("XDG_DATA_HOME", root.join("xdg-data"))
        .env("XDG_CACHE_HOME", root.join("xdg-cache"))
        .env_remove("KEYHOG_BACKEND")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("start default-corpus daemon");

    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if socket.exists() && UnixStream::connect(&socket).is_ok() {
            return RunningDaemon { child, socket };
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("default-corpus daemon did not become ready within 30 seconds");
}

fn scan_default(root: &Path, socket: &Path, fixture: &Path) -> Output {
    Command::new(binary())
        .current_dir(root)
        .args(["scan", "--daemon=on", "--daemon-socket"])
        .arg(socket)
        .args(["--format", "json-envelope"])
        .arg(fixture)
        .env("HOME", root)
        .env("XDG_DATA_HOME", root.join("xdg-data"))
        .env("XDG_CACHE_HOME", root.join("xdg-cache"))
        .env_remove("KEYHOG_BACKEND")
        .output()
        .expect("run default daemon scan")
}

fn scan(root: &Path, socket: &Path, fixture: &Path, detectors: &Path, overlay: bool) -> Output {
    let mut command = Command::new(binary());
    command
        .current_dir(root)
        .args(["scan", "--daemon=on", "--daemon-socket"])
        .arg(socket)
        .args(["--detectors"])
        .arg(detectors);
    if overlay {
        command.args(["--detectors-mode", "overlay"]);
    }
    command
        .args(["--format", "json-envelope"])
        .arg(fixture)
        .env("HOME", root)
        .env("XDG_DATA_HOME", root.join("xdg-data"))
        .env("XDG_CACHE_HOME", root.join("xdg-cache"))
        .env_remove("KEYHOG_BACKEND")
        .output()
        .expect("run daemon scan")
}

/// Regression: v8 warm-identity validation previously hard-coded the embedded
/// detector digest, so a daemon deliberately compiled with a replacement
/// `--detectors` corpus rejected the matching production scan client. This
/// lifecycle proves an exact match and its report provenance, while a different
/// replacement, overlay composition, and client-only disable policy fail closed.
#[test]
fn custom_replacement_corpus_requires_exact_daemon_identity() {
    let root = TempDir::new().expect("tempdir");
    let matching = root.path().join("matching-detectors");
    let mismatched = root.path().join("mismatched-detectors");
    write_detector(&matching, "daemon-custom-match");
    write_detector(&mismatched, "daemon-custom-other");
    let fixture = root.path().join("planted.txt");
    std::fs::write(&fixture, format!("custom = \"{CUSTOM_TOKEN}\"\n"))
        .expect("write planted custom secret");

    let daemon = start_daemon(root.path(), &matching);

    let matched = scan(root.path(), &daemon.socket, &fixture, &matching, false);
    assert_eq!(
        matched.status.code(),
        Some(1),
        "matching replacement corpus must reach the daemon and find the custom token; stderr={}",
        String::from_utf8_lossy(&matched.stderr)
    );
    let report: Value = serde_json::from_slice(&matched.stdout).unwrap_or_else(|error| {
        panic!(
            "matching daemon scan must emit a JSON envelope: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&matched.stdout),
            String::from_utf8_lossy(&matched.stderr)
        )
    });
    let findings = report["findings"]
        .as_array()
        .unwrap_or_else(|| panic!("daemon report must contain findings: {report:?}"));
    assert_eq!(
        findings.len(),
        1,
        "matching daemon scan must emit exactly the custom finding: {report:?}"
    );
    assert_eq!(
        findings[0]["detector_id"].as_str(),
        Some("daemon-custom-match"),
        "the finding must come from the daemon's replacement corpus: {report:?}"
    );
    let loaded = keyhog_core::load_detector_corpus(&matching).expect("reload expected corpus");
    let expected_digest = keyhog_core::hex_encode(
        keyhog_core::compute_detector_corpus_digest_for_schema(
            &loaded.specs,
            loaded.schema_version,
        )
        .expect("compute expected replacement corpus digest"),
    );
    let effective = &report["metadata"]["resolved_scan"]["effective"];
    assert_eq!(report["metadata"]["detector_count"], 1);
    assert_eq!(effective["detector_corpus_mode"], "replace");
    assert_eq!(
        effective["detector_corpus_source"],
        matching.display().to_string()
    );
    assert_eq!(effective["detector_corpus_embedded_count"], "0");
    assert_eq!(effective["detector_corpus_custom_count"], "1");
    assert_eq!(effective["detector_corpus_digest"], expected_digest);

    let wrong = scan(root.path(), &daemon.socket, &fixture, &mismatched, false);
    assert_eq!(
        wrong.status.code(),
        Some(2),
        "stderr={}",
        String::from_utf8_lossy(&wrong.stderr)
    );
    let wrong_stderr = String::from_utf8_lossy(&wrong.stderr);
    assert!(
        wrong_stderr.contains("daemon identity mismatch")
            && wrong_stderr.contains("detector rules daemon=")
            && wrong_stderr.contains("--daemon=off"),
        "mismatched replacement identity must fail closed with remediation; stderr={wrong_stderr}"
    );
    assert!(
        wrong.stdout.is_empty(),
        "an identity mismatch must fail before emitting scan results"
    );

    let overlay = scan(root.path(), &daemon.socket, &fixture, &matching, true);
    assert_eq!(
        overlay.status.code(),
        Some(2),
        "stderr={}",
        String::from_utf8_lossy(&overlay.stderr)
    );
    let overlay_stderr = String::from_utf8_lossy(&overlay.stderr);
    assert!(
        overlay_stderr.contains("--detectors-mode=overlay")
            && overlay_stderr.contains("precompiled scanner")
            && overlay_stderr.contains("--daemon=off"),
        "overlay must remain rejected with actionable remediation; stderr={overlay_stderr}"
    );
    assert!(
        overlay.stdout.is_empty(),
        "a rejected overlay must not emit scan results"
    );

    std::fs::write(
        root.path().join(".keyhog.toml"),
        "[detector.daemon-custom-match]\nenabled = false\n",
    )
    .expect("write client-only detector policy");
    let disabled = scan(root.path(), &daemon.socket, &fixture, &matching, false);
    assert_eq!(
        disabled.status.code(),
        Some(2),
        "client-only detector policy must not be bypassed by the daemon; stderr={}",
        String::from_utf8_lossy(&disabled.stderr)
    );
    let disabled_stderr = String::from_utf8_lossy(&disabled.stderr);
    assert!(
        disabled_stderr.contains("--daemon=on cannot be honored")
            && disabled_stderr.contains("config policy")
            && disabled_stderr.contains("--daemon=off"),
        "client-only detector policy must fail closed with in-process remediation; stderr={disabled_stderr}"
    );
    assert!(
        disabled.stdout.is_empty(),
        "a rejected client-only detector policy must not emit scan results"
    );
}

/// WHY: a checkout-local `detectors/` directory must not silently replace the
/// build-bound default corpus, or the static handshake identity could attest to
/// different rules than the daemon actually compiled.
#[test]
fn default_daemon_ignores_unrequested_checkout_detector_directory() {
    let root = TempDir::new().expect("tempdir");
    let local_detectors = root.path().join("detectors");
    write_detector(&local_detectors, "daemon-custom-shadow");
    let fixture = root.path().join("planted.txt");
    std::fs::write(&fixture, format!("custom = \"{CUSTOM_TOKEN}\"\n"))
        .expect("write planted custom secret");

    let daemon = start_default_daemon(root.path());
    let output = scan_default(root.path(), &daemon.socket, &fixture);
    assert!(
        matches!(output.status.code(), Some(0 | 1 | 10)),
        "default daemon scan must complete; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "default daemon scan must emit a JSON envelope: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let findings = report["findings"]
        .as_array()
        .unwrap_or_else(|| panic!("daemon report must contain findings: {report:?}"));
    assert!(
        findings
            .iter()
            .all(|finding| finding["detector_id"] != "daemon-custom-shadow"),
        "an unrequested checkout detector must never enter the default daemon: {report:?}"
    );
    assert_eq!(
        report["metadata"]["detector_count"].as_u64(),
        Some(keyhog_core::embedded_detector_count() as u64),
        "default daemon must report the build-bound embedded corpus"
    );
}
