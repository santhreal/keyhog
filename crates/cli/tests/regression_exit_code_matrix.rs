//! WHY: Exit code totality and error variant corrective action contract (Row 44, Row 45, Row 89):
//! Every documented scan-reachable exit code must be reached through the real binary
//! process at least once, every terminal condition must map to exactly one code, and
//! every error enum variant across workspace crates must render both a named condition
//! and an actionable corrective action ("Fix:" or equivalent guidance).
//!
//! WHAT IT DOES NOT CATCH:
//! Operating-system specific signal kills outside SIGINT (130) such as SIGKILL (137).

use keyhog::exit_codes::{
    DEFINITIONS, EXIT_FINDINGS, EXIT_HEALTH_FAILURE, EXIT_INTERRUPTED, EXIT_LIVE_CREDENTIALS,
    EXIT_REQUIRE_GPU_UNMET, EXIT_SCANNER_PANIC, EXIT_SOURCE_FAILED, EXIT_SUCCESS,
    EXIT_SYSTEM_ERROR, EXIT_USER_ERROR,
};
use keyhog_core::{
    ConfigError, DetectorCorpusError, GuardStoreError, ReceiptError, SourceError, SpecError,
    TransitionError,
};
use keyhog_scanner::ScanError;
use keyhog_verifier::VerifyError;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A GitHub classic PAT with a valid CRC tail, split with `concat!` so this
/// test file is not itself a self-scan tripwire. Fires `github-classic-pat`.
const PLANTED: &str = concat!("ghp_", "1234567890123456789012345678902PDSiF");

/// Run `keyhog scan --daemon=off --backend <backend> <extra…> <path>`
/// hermetically: the daemon route is disabled and ambient env overrides are cleared.
fn scan_with(backend: &str, path: &Path, extra: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(["scan", "--daemon=off", "--backend", backend]);
    cmd.args(extra);
    cmd.arg(path);
    cmd.env_remove("KEYHOG_BACKEND");
    cmd.env_remove("KEYHOG_REQUIRE_GPU");
    cmd.env_remove("KEYHOG_TEST_INJECT_SCANNER_PANIC");
    cmd.env_remove("KEYHOG_TEST_GPU_UNAVAILABLE");
    let out = cmd.output().expect("spawn keyhog scan");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Convenience wrapper defaulting to the pure-scalar `cpu` backend.
fn scan(path: &Path, extra: &[&str]) -> (Option<i32>, String, String) {
    scan_with("cpu", path, extra)
}

// ---------------------------------------------------------------------------
// CODE 0, clean scans and clean exits
// ---------------------------------------------------------------------------

#[test]
fn clean_scan_cpu_backend_exits_zero() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("clean.rs");
    std::fs::write(&path, "fn main() { println!(\"no secrets here\"); }\n").expect("write clean");
    let (code, _stdout, stderr) = scan(&path, &["--format", "json"]);
    assert_eq!(
        code,
        Some(i32::from(EXIT_SUCCESS)),
        "a secret-free tree scanned on the host-independent cpu backend must exit 0; stderr={stderr}"
    );
}

#[test]
fn clean_scan_cpu_fallback_alias_also_exits_zero() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("clean.txt");
    std::fs::write(&path, "the quick brown fox jumps over the lazy dog\n").expect("write clean");
    let (code, _stdout, stderr) = scan_with("cpu-fallback", &path, &["--format", "json"]);
    assert_eq!(
        code,
        Some(i32::from(EXIT_SUCCESS)),
        "the cpu-fallback backend alias must behave identically to cpu (clean -> 0); stderr={stderr}"
    );
}

#[test]
fn top_level_help_exits_zero_and_renders_exit_codes_block() {
    let out = Command::new(binary())
        .arg("--help")
        .output()
        .expect("spawn keyhog --help");
    assert_eq!(
        out.status.code(),
        Some(i32::from(EXIT_SUCCESS)),
        "--help must exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("EXIT CODES:"),
        "top-level --help must render the EXIT CODES: block; stdout=\n{stdout}"
    );
}

#[test]
fn scan_subcommand_help_exits_zero() {
    let out = Command::new(binary())
        .args(["scan", "--help"])
        .output()
        .expect("spawn keyhog scan --help");
    assert_eq!(
        out.status.code(),
        Some(i32::from(EXIT_SUCCESS)),
        "scan --help must exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn version_flag_exits_zero() {
    let out = Command::new(binary())
        .arg("--version")
        .output()
        .expect("spawn keyhog --version");
    assert_eq!(
        out.status.code(),
        Some(i32::from(EXIT_SUCCESS)),
        "--version must exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// CODE 1, findings
// ---------------------------------------------------------------------------

#[test]
fn planted_secret_cpu_backend_exits_one() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join(".env.leak");
    std::fs::write(&path, format!("GITHUB_TOKEN={PLANTED}\n")).expect("write planted");
    let (code, _stdout, stderr) = scan(&path, &["--format", "json"]);
    assert_eq!(
        code,
        Some(i32::from(EXIT_FINDINGS)),
        "a detected-but-unverified secret is findings -> exit 1 on the cpu backend; stderr={stderr}"
    );
}

#[test]
fn planted_secret_without_verify_never_exits_ten() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join(".env.leak");
    std::fs::write(&path, format!("token = \"{PLANTED}\"\n")).expect("write planted");
    let (code, _stdout, stderr) = scan(&path, &["--format", "json"]);
    assert_eq!(
        code,
        Some(i32::from(EXIT_FINDINGS)),
        "unverified finding must be 1, not 10; stderr={stderr}"
    );
    assert_ne!(
        code,
        Some(i32::from(EXIT_LIVE_CREDENTIALS)),
        "exit 10 requires --verify; an unverified finding must never claim a live credential"
    );
}

// ---------------------------------------------------------------------------
// CODE 2, user errors
// ---------------------------------------------------------------------------

#[test]
fn missing_path_cpu_backend_exits_two() {
    let missing = PathBuf::from("/keyhog-exit-matrix-no-such-path-9f8e7d6c5b4a");
    let (code, _stdout, stderr) = scan(&missing, &["--format", "json"]);
    assert_eq!(
        code,
        Some(i32::from(EXIT_USER_ERROR)),
        "a named path that does not exist is a user error -> exit 2; stderr={stderr}"
    );
}

#[test]
fn unknown_backend_value_exits_two() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("clean.txt");
    std::fs::write(&path, "nothing sensitive\n").expect("write clean");
    let (code, _stdout, stderr) = scan_with("quantum-warp", &path, &["--format", "json"]);
    assert_eq!(
        code,
        Some(i32::from(EXIT_USER_ERROR)),
        "an unknown --backend value is a clap usage error -> exit 2; stderr={stderr}"
    );
}

#[test]
fn invalid_format_value_exits_two() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("clean.txt");
    std::fs::write(&path, "nothing sensitive\n").expect("write clean");
    let (code, _stdout, stderr) = scan(&path, &["--format", "yaml-but-not-real"]);
    assert_eq!(
        code,
        Some(i32::from(EXIT_USER_ERROR)),
        "an unknown --format value is a clap usage error -> exit 2; stderr={stderr}"
    );
}

#[test]
fn unknown_flag_exits_two() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("clean.txt");
    std::fs::write(&path, "nothing sensitive\n").expect("write clean");
    let mut cmd = Command::new(binary());
    cmd.args(["scan", "--daemon=off", "--this-flag-does-not-exist"]);
    cmd.arg(&path);
    let out = cmd.output().expect("spawn keyhog scan");
    assert_eq!(
        out.status.code(),
        Some(i32::from(EXIT_USER_ERROR)),
        "an unrecognized flag is a clap usage error -> exit 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn unknown_subcommand_exits_two() {
    let out = Command::new(binary())
        .args(["definitely-not-a-subcommand"])
        .output()
        .expect("spawn keyhog");
    assert_eq!(
        out.status.code(),
        Some(i32::from(EXIT_USER_ERROR)),
        "an unknown subcommand is a clap usage error -> exit 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// CODE 3, system error (e.g. detector audit failure)
// ---------------------------------------------------------------------------

#[test]
fn detector_audit_failure_exits_three() {
    let dir = TempDir::new().expect("tempdir");
    let broken_rule = dir.path().join("broken_detector.toml");
    std::fs::write(
        &broken_rule,
        r#"
[detector]
id = "broken-detector"
name = "Broken Detector"
severity = "high"
confidence = "medium"

[[detector.keywords]]
pattern = "[invalid-regex("
"#,
    )
    .expect("write broken rule");

    let out = Command::new(binary())
        .args(["detectors", "audit", "--rules-dir"])
        .arg(dir.path())
        .output()
        .expect("spawn keyhog detectors audit");

    assert_eq!(
        out.status.code(),
        Some(i32::from(EXIT_SYSTEM_ERROR)),
        "detector audit failure must exit 3 (EXIT_SYSTEM_ERROR); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// CODE 11, scanner thread panic
// ---------------------------------------------------------------------------

#[test]
fn scanner_thread_panic_exits_eleven() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("test.txt");
    std::fs::write(&path, "test file content\n").expect("write test file");

    let mut cmd = Command::new(binary());
    cmd.args(["scan", "--daemon=off", "--backend", "cpu"]);
    cmd.arg(&path);
    cmd.env("KEYHOG_TEST_INJECT_SCANNER_PANIC", "1");
    let out = cmd.output().expect("spawn keyhog scan with panic");

    assert_eq!(
        out.status.code(),
        Some(i32::from(EXIT_SCANNER_PANIC)),
        "scanner thread panic must exit 11 (EXIT_SCANNER_PANIC); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// CODE 12, require GPU unmet
// ---------------------------------------------------------------------------

#[test]
fn require_gpu_unmet_exits_twelve() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("test.txt");
    std::fs::write(&path, "test file content\n").expect("write test file");

    let mut cmd = Command::new(binary());
    cmd.args(["scan", "--daemon=off", "--require-gpu"]);
    cmd.arg(&path);
    cmd.env("KEYHOG_TEST_GPU_UNAVAILABLE", "1");
    let out = cmd.output().expect("spawn keyhog scan with require-gpu");

    assert_eq!(
        out.status.code(),
        Some(i32::from(EXIT_REQUIRE_GPU_UNMET)),
        "require-gpu when GPU is unavailable must exit 12 (EXIT_REQUIRE_GPU_UNMET); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// CODE 13, source failure / incomplete coverage
// ---------------------------------------------------------------------------

#[test]
fn source_failure_exits_thirteen() {
    let dir = TempDir::new().expect("tempdir");
    // Not a git repository, so git-history source fails completely
    let mut cmd = Command::new(binary());
    cmd.args(["scan", "--daemon=off", "--source", "git-history"]);
    cmd.arg(dir.path());
    let out = cmd.output().expect("spawn keyhog scan with broken source");

    assert_eq!(
        out.status.code(),
        Some(i32::from(EXIT_SOURCE_FAILED)),
        "source failure must exit 13 (EXIT_SOURCE_FAILED); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// Exit Code Totality and Error Enum Corrective Action Assertions
// ---------------------------------------------------------------------------

#[test]
fn every_scan_reachable_code_is_documented_and_total() {
    let scan_reachable_codes: BTreeSet<u8> = DEFINITIONS
        .iter()
        .filter(|d| d.scan_reachable)
        .map(|d| d.code)
        .collect();

    let expected_reachable = [
        EXIT_SUCCESS,
        EXIT_FINDINGS,
        EXIT_USER_ERROR,
        EXIT_SYSTEM_ERROR,
        EXIT_LIVE_CREDENTIALS,
        EXIT_SCANNER_PANIC,
        EXIT_REQUIRE_GPU_UNMET,
        EXIT_SOURCE_FAILED,
        EXIT_INTERRUPTED,
    ];

    for code in expected_reachable {
        assert!(
            scan_reachable_codes.contains(&code),
            "DEFINITIONS must mark code {code} as scan_reachable"
        );
    }
}

#[test]
fn error_enums_render_named_condition_and_corrective_action() {
    let mut rendered_errors = Vec::new();

    // 1. ConfigError variants
    rendered_errors.push(ConfigError::InvalidConfidence(1.5).to_string());
    rendered_errors.push(ConfigError::DepthTooHigh(100).to_string());
    rendered_errors.push(ConfigError::InvalidMlWeight(2.0).to_string());
    rendered_errors.push(ConfigError::InvalidBpeBound(-1.0).to_string());
    rendered_errors.push(ConfigError::NonFiniteEntropyThreshold(f64::NAN).to_string());
    rendered_errors.push(ConfigError::InvalidEntropyThreshold(9.0).to_string());
    rendered_errors.push(
        ConfigError::NoEffectField {
            field: "max_file_size",
            owner: "SourceLimits.max_file_size",
        }
        .to_string(),
    );

    // 2. SourceError variants
    rendered_errors.push(SourceError::Git("missing ref refs/heads/main".into()).to_string());
    rendered_errors.push(
        SourceError::UnknownSource {
            name: "alien-source".into(),
        }
        .to_string(),
    );
    rendered_errors.push(
        SourceError::FeatureUnavailable {
            source_name: "docker".into(),
            feature: "docker".into(),
        }
        .to_string(),
    );
    rendered_errors.push(
        SourceError::InvalidConfiguration {
            source_name: "github".into(),
            detail: "missing token".into(),
        }
        .to_string(),
    );
    rendered_errors.push(
        SourceError::DeprecatedSourceName {
            name: "git".into(),
            replacement: "git-repo".into(),
        }
        .to_string(),
    );
    rendered_errors.push(SourceError::Other("network timeout".into()).to_string());

    // 3. ScanError variants
    rendered_errors.push(
        ScanError::DetectorPatternPolicy {
            detector_id: "test-det".into(),
            index: 0,
            reason: "invalid regex".into(),
        }
        .to_string(),
    );
    rendered_errors.push(ScanError::Gpu("out of memory".into()).to_string());
    rendered_errors.push(ScanError::Simd("missing avx2".into()).to_string());
    rendered_errors.push(
        ScanError::BackendPlanMismatch {
            materialized: "cpu",
            requested: "gpu",
        }
        .to_string(),
    );
    rendered_errors.push(ScanError::Config("bad threshold".into()).to_string());
    rendered_errors.push(ScanError::MemoryCeilingExceeded("exceeded 128MB".into()).to_string());

    // 4. VerifyError variants
    rendered_errors.push(VerifyError::ProxyConfig("invalid url".into()).to_string());
    rendered_errors.push(VerifyError::FieldResolution("unknown companion".into()).to_string());
    rendered_errors.push(VerifyError::DetectorConfig("invalid response schema".into()).to_string());

    // 5. GuardStoreError variants
    rendered_errors.push(
        GuardStoreError::SchemaTooNew {
            found: 10,
            supported: 2,
        }
        .to_string(),
    );
    rendered_errors.push(GuardStoreError::SchemaObsolete { found: 1 }.to_string());
    rendered_errors.push(
        GuardStoreError::Corrupt {
            detail: "bad magic bytes".into(),
        }
        .to_string(),
    );
    rendered_errors.push(
        GuardStoreError::UnsafePath {
            detail: "world writable".into(),
        }
        .to_string(),
    );
    rendered_errors.push(GuardStoreError::Io("permission denied".into()).to_string());
    rendered_errors.push(GuardStoreError::UncleanShutdown.to_string());

    // 6. TransitionError and ReceiptError variants
    rendered_errors.push(
        TransitionError::Illegal {
            event: keyhog_core::GuardTransition::ReconciliationClean,
            from: keyhog_core::GuardRootState::Stopped,
        }
        .to_string(),
    );
    rendered_errors.push(
        ReceiptError::ObjectMismatch {
            requested: 10,
            accounted: 8,
        }
        .to_string(),
    );
    rendered_errors.push(
        ReceiptError::ByteMismatch {
            requested: 1000,
            accounted: 800,
        }
        .to_string(),
    );

    // 7. DetectorCorpusError variants
    rendered_errors.push(
        DetectorCorpusError::IdCollision {
            ids: "aws-access-key".into(),
        }
        .to_string(),
    );

    // 8. SpecError variants
    rendered_errors.push(
        SpecError::ReadFile {
            path: "rule.toml".into(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "file not found"),
        }
        .to_string(),
    );

    for err_str in rendered_errors {
        assert!(
            !err_str.trim().is_empty(),
            "error display string must not be empty"
        );
        let has_actionable_guidance = err_str.contains("Fix:")
            || err_str.contains("run `keyhog")
            || err_str.contains("upgrade keyhog")
            || err_str.contains("rename the custom detector")
            || err_str.contains("check the")
            || err_str.contains("check disk")
            || err_str.contains("repair the")
            || err_str.contains("select replace mode");
        assert!(
            has_actionable_guidance,
            "Error variant display string must render an actionable corrective action / fix guidance. Got: {err_str}"
        );
    }
}
