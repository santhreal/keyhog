//! E2E regression: `.keyhog.toml` config-file LOAD + PRECEDENCE through the real
//! binary. This is the operator-path counterpart to the in-crate `core`
//! `config_precedence` unit tests: every assertion drives the shipped `keyhog`
//! executable (`env!("CARGO_BIN_EXE_keyhog")`) and asserts a CONCRETE effect
//! (exact exit code, exact stdout bytes, exact operator-visible error text),
//! never merely that output is non-empty.
//!
//! HOST-INDEPENDENCE: every scan pins `--backend cpu`: the scalar path that is
//! always present on every host, so no assertion depends on an accelerator
//! (Hyperscan / SIMD / GPU) being available. The config-load contract is
//! identical on the scalar path, and the fixture (a canary AWS access-key id)
//! fires there deterministically.
//!
//! Contract exercised (see `crates/cli/src/config/*.rs`):
//!   * a `.keyhog.toml` setting genuinely changes scan behavior (positive load);
//!   * a CLI flag and `--no-config` each OVERRIDE the on-disk value (precedence);
//!   * an explicit `--config PATH` outside the scan tree is loaded;
//!   * a malformed / invalid config FAILS CLOSED with exit 2 and a message that
//!     names the offending key AND the fix (never a silent degrade).

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A planted AWS access-key id (`aws-access-key` detector). Split with `concat!`
/// so the literal token never appears verbatim in this source and trips the
/// repo's own dogfood self-scan.
const PLANTED: &str = concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\n");

/// The un-redacted credential, reconstructed the same split way. Only used as an
/// expected-value string for the `show_secrets` assertion.
const FULL_SECRET: &str = concat!("AKIA", "QYLPMN5HFIQR7XYA");

/// Config disabling every detector that can report the planted key, so a load
/// that takes effect suppresses the finding entirely (exit 0). `aws-access-key`
/// is the structural detector; `entropy-api-key` is the entropy twin that also
/// reports the same token.
const DISABLE_PLANTED: &str =
    "[detector.aws-access-key]\nenabled = false\n[detector.entropy-api-key]\nenabled = false\n";

/// Create a temp scan dir containing the planted fixture, and (optionally) a
/// `.keyhog.toml` with `config`. Returns the owned `TempDir` (keep it alive for
/// the duration of the scan) and its path.
fn make_scan_dir(config: Option<&str>) -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("planted.txt"), PLANTED).expect("write fixture");
    if let Some(cfg) = config {
        std::fs::write(dir.path().join(".keyhog.toml"), cfg).expect("write config");
    }
    dir
}

/// Run `keyhog scan --daemon=off --backend cpu <extra...> <dir>` and return
/// (exit code, stdout, stderr). `--backend cpu` keeps the run host-independent.
fn scan(dir: &std::path::Path, extra: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(binary())
        .arg("scan")
        .arg("--daemon=off")
        .arg("--backend")
        .arg("cpu")
        .args(extra)
        .arg(dir)
        .output()
        .expect("spawn keyhog scan");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn copy_detector(corpus: &std::path::Path, filename: &str) {
    std::fs::create_dir_all(corpus).expect("create detector corpus");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../detectors")
        .join(filename);
    std::fs::copy(&source, corpus.join(filename)).unwrap_or_else(|error| {
        panic!(
            "copy detector {} into test corpus: {error}",
            source.display()
        )
    });
}

fn scan_from_cwd(
    dir: &std::path::Path,
    cwd: &std::path::Path,
    extra: &[&str],
) -> (Option<i32>, String, String) {
    let output = Command::new(binary())
        .current_dir(cwd)
        .arg("scan")
        .arg("--daemon=off")
        .arg("--backend")
        .arg("cpu")
        .args(extra)
        .arg(dir)
        .output()
        .expect("spawn keyhog scan from caller cwd");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

// ---------------------------------------------------------------------------
// POSITIVE: a config-file setting takes effect on the default (config-enabled)
// path.
// ---------------------------------------------------------------------------

#[test]
fn config_disabling_detectors_suppresses_the_planted_key() {
    // Baseline sanity FIRST: with NO config, the planted key fires on the cpu
    // path (exit 1). If this ever regresses, the suppression assertion below
    // would be vacuous, so prove the fixture is live.
    let bare = make_scan_dir(None);
    let (code, stdout, stderr) = scan(bare.path(), &["--format", "json"]);
    assert_eq!(
        code,
        Some(1),
        "no-config baseline: the planted aws-access-key must fire (exit 1) on the \
         scalar cpu path.\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert!(
        stdout.contains("\"detector_id\":\"aws-access-key\""),
        "baseline stdout must carry the aws-access-key finding.\n--- stdout ---\n{stdout}"
    );

    // Now with the disabling `.keyhog.toml` the SAME scan is clean: the config
    // was loaded and honored.
    let dir = make_scan_dir(Some(DISABLE_PLANTED));
    let (code, stdout, stderr) = scan(dir.path(), &["--format", "json"]);
    assert_eq!(
        code,
        Some(0),
        "a `.keyhog.toml` disabling both reporting detectors must be loaded and \
         honored (planted key suppressed → exit 0).\n--- stdout ---\n{stdout}\n\
         --- stderr ---\n{stderr}"
    );
    assert_eq!(
        stdout.trim(),
        "[]",
        "with the detectors disabled the JSON findings array must be exactly empty.\n\
         --- stdout ---\n{stdout}"
    );
}

#[test]
fn retired_flat_scan_key_fails_closed() {
    for (config, key, canonical) in [
        ("format = \"json\"\n", "format", "format"),
        (
            "exclude_paths = [\"planted.txt\"]\n",
            "exclude_paths",
            "exclude",
        ),
    ] {
        let dir = make_scan_dir(Some(config));
        let (code, _stdout, stderr) = scan(dir.path(), &[]);
        assert_eq!(code, Some(2), "retired flat scan keys must fail closed");
        assert!(
            stderr.contains(&format!("unknown field `{key}`"))
                && stderr.contains(&format!("move top-level `{key}` to `[scan].{canonical}`")),
            "the parse error must identify the retired key and canonical table; stderr={stderr}"
        );
    }
}

#[test]
fn config_scan_section_format_json_is_honored() {
    // The `[scan]` nested table is the README-canonical surface and must be
    // the canonical output-format owner.
    let dir = make_scan_dir(Some("[scan]\nformat = \"json\"\n"));
    let (code, stdout, _stderr) = scan(dir.path(), &[]);
    assert_eq!(code, Some(1), "planted key fires; only rendering changed");
    assert_eq!(
        stdout.as_bytes().first().copied(),
        Some(b'['),
        "`[scan].format = \"json\"` must render a JSON array (leading '[').\n\
         --- stdout ---\n{stdout}"
    );
    assert!(
        stdout.contains("\"detector_id\":\"aws-access-key\""),
        "nested-[scan] JSON body must contain the finding.\n--- stdout ---\n{stdout}"
    );
}

#[test]
fn config_scan_section_format_json_envelope_is_honored() {
    let dir = make_scan_dir(Some("[scan]\nformat = \"json-envelope\"\n"));
    let (code, stdout, stderr) = scan(dir.path(), &[]);
    assert_eq!(
        code,
        Some(1),
        "the envelope format must preserve the finding exit code; stdout={stdout} stderr={stderr}"
    );
    let report: serde_json::Value =
        serde_json::from_str(&stdout).expect("[scan].format=json-envelope must emit a JSON object");
    assert_eq!(report["schema_version"]["major"], 1);
    assert!(report["findings"].is_array());
    assert_eq!(report["findings"][0]["detector_id"], "aws-access-key");
}

#[test]
fn config_show_secrets_reveals_full_credential() {
    // Default: credential is redacted to "AK...YA". `show_secrets = true` in the
    // config must reveal the full token in the JSON.
    let redacted = make_scan_dir(Some("[scan]\nformat = \"json\"\n"));
    let (_c, stdout_default, _e) = scan(redacted.path(), &[]);
    assert!(
        stdout_default.contains("\"credential_redacted\":\"AK...YA\""),
        "negative twin: without show_secrets the credential must be redacted to \
         \"AK...YA\".\n--- stdout ---\n{stdout_default}"
    );
    assert!(
        !stdout_default.contains(FULL_SECRET),
        "negative twin: the full secret must NOT leak by default.\n--- stdout ---\n{stdout_default}"
    );

    let dir = make_scan_dir(Some("show_secrets = true\n[scan]\nformat = \"json\"\n"));
    let (code, stdout, _stderr) = scan(dir.path(), &[]);
    assert_eq!(
        code,
        Some(1),
        "finding still reported when secrets are shown"
    );
    let expected = format!("\"credential_redacted\":\"{FULL_SECRET}\"");
    assert!(
        stdout.contains(&expected),
        "config `show_secrets = true` must emit the un-redacted credential.\n\
         --- stdout ---\n{stdout}"
    );
}

#[test]
fn config_scan_exclude_suppresses_the_planted_file() {
    // `[scan].exclude` drops the planted file from the walk, so the
    // scan is clean.
    let dir = make_scan_dir(Some("[scan]\nexclude = [\"planted.txt\"]\n"));
    let (code, stdout, stderr) = scan(dir.path(), &["--format", "json"]);
    assert_eq!(
        code,
        Some(0),
        "config `[scan].exclude` must exclude the only fixture file → exit 0.\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert_eq!(
        stdout.trim(),
        "[]",
        "excluded scan must produce an empty JSON findings array.\n--- stdout ---\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// PRECEDENCE: CLI flag and `--no-config` override the config file.
// ---------------------------------------------------------------------------

#[test]
fn cli_format_flag_overrides_config_format() {
    // Config asks for JSON; the explicit `--format text` CLI flag wins (CLI is
    // the highest-precedence layer), so the output is the text report, NOT JSON.
    let dir = make_scan_dir(Some("[scan]\nformat = \"json\"\n"));
    let (code, stdout, _stderr) = scan(dir.path(), &["--format", "text"]);
    assert_eq!(code, Some(1), "planted key still fires");
    assert_ne!(
        stdout.as_bytes().first().copied(),
        Some(b'['),
        "`--format text` must override config `[scan].format = \"json\"`: output must NOT \
         be a JSON array.\n--- stdout ---\n{stdout}"
    );
    assert!(
        stdout.contains("AWS Access Key"),
        "the CLI-selected text report must render the human-readable detector name.\n\
         --- stdout ---\n{stdout}"
    );
}

#[test]
fn no_config_flag_ignores_disabling_config() {
    // The `.keyhog.toml` disables the reporting detectors, but `--no-config`
    // skips discovery entirely, so the planted key still fires.
    let dir = make_scan_dir(Some(DISABLE_PLANTED));
    let (code, stdout, stderr) = scan(dir.path(), &["--no-config", "--format", "json"]);
    assert_eq!(
        code,
        Some(1),
        "`--no-config` must ignore the on-disk disabling `.keyhog.toml`: the \
         planted key must still fire (exit 1).\n--- stdout ---\n{stdout}\n\
         --- stderr ---\n{stderr}"
    );
    assert!(
        stdout.contains("\"detector_id\":\"aws-access-key\""),
        "hermetic scan must report the aws-access-key finding the config tried to \
         suppress.\n--- stdout ---\n{stdout}"
    );
}

#[test]
fn multi_root_scan_refuses_ambiguous_repository_configs() {
    let first = make_scan_dir(Some("[scan]\nformat = \"json\"\n"));
    let second = make_scan_dir(Some("[scan]\nformat = \"text\"\n"));
    let output = Command::new(binary())
        .args(["scan", "--daemon=off", "--backend", "cpu"])
        .arg(first.path())
        .arg(second.path())
        .output()
        .expect("spawn multi-root keyhog scan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "one scan must not silently apply the first root's policy to a differently configured root; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("scan roots resolve different repository configuration identities")
            && stderr.contains("pass one explicit --config PATH"),
        "the operator must see the conflicting policy identities and an explicit resolution; stderr={stderr}"
    );
}

#[test]
fn no_config_flag_ignores_config_format() {
    // Config asks for JSON, but `--no-config` skips the file, so the output is
    // the compiled-default text report (leading char is not '[').
    let dir = make_scan_dir(Some("format = \"json\"\n"));
    let (code, stdout, _stderr) = scan(dir.path(), &["--no-config"]);
    assert_eq!(
        code,
        Some(1),
        "planted key fires on the hermetic default path"
    );
    assert_ne!(
        stdout.as_bytes().first().copied(),
        Some(b'['),
        "`--no-config` must ignore config `format = \"json\"`: output stays the \
         default text report.\n--- stdout ---\n{stdout}"
    );
    assert!(
        stdout.contains("secret found"),
        "the default text report must render the results summary.\n--- stdout ---\n{stdout}"
    );
}

#[test]
fn explicit_config_path_outside_scan_dir_is_loaded() {
    // `--config PATH` loads a config that does NOT live on the walk-up path from
    // the scan root, proving explicit-path load (not just `.keyhog.toml`
    // discovery). The disabling config suppresses the finding → exit 0.
    let scan_dir = make_scan_dir(None);
    let cfg_dir = TempDir::new().expect("cfg tempdir");
    let cfg_path = cfg_dir.path().join("explicit-keyhog.toml");
    std::fs::write(&cfg_path, DISABLE_PLANTED).expect("write explicit config");

    let output = Command::new(binary())
        .arg("scan")
        .arg("--daemon=off")
        .arg("--backend")
        .arg("cpu")
        .arg("--format")
        .arg("json")
        .arg("--config")
        .arg(&cfg_path)
        .arg(scan_dir.path())
        .output()
        .expect("spawn keyhog scan");

    assert_eq!(
        output.status.code(),
        Some(0),
        "an explicit `--config PATH` outside the scan tree must be loaded and \
         honored (finding suppressed → exit 0).\n--- stderr ---\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "[]",
        "explicit-config disable must yield an empty JSON findings array."
    );
}

#[test]
fn config_relative_detector_corpus_is_independent_of_caller_cwd() {
    let case = TempDir::new().expect("case tempdir");
    let scan_root = case.path().join("scan-root");
    let corpus = case.path().join("corpus");
    std::fs::create_dir(&scan_root).expect("create scan root");
    std::fs::write(scan_root.join("planted.txt"), PLANTED).expect("write fixture");
    copy_detector(&corpus, "aws-access-key.toml");
    std::fs::write(
        scan_root.join(".keyhog.toml"),
        "detectors = \"../corpus\"\n[scan]\nformat = \"json\"\n",
    )
    .expect("write repository config");

    let first_cwd = TempDir::new().expect("first caller cwd");
    let second_cwd = TempDir::new().expect("second caller cwd");
    let first = scan_from_cwd(&scan_root, first_cwd.path(), &[]);
    let second = scan_from_cwd(&scan_root, second_cwd.path(), &[]);

    for (code, stdout, stderr) in [&first, &second] {
        assert_eq!(
            *code,
            Some(1),
            "the config-owned AWS corpus must load from either caller cwd; stdout={stdout} stderr={stderr}"
        );
        assert!(
            stdout.contains("\"detector_id\":\"aws-access-key\""),
            "the selected corpus must report the planted AWS key; stdout={stdout}"
        );
    }
    assert_eq!(
        first.1, second.1,
        "changing caller cwd must not change findings from a config-relative corpus"
    );
}

#[test]
fn explicit_cli_detector_corpus_overrides_config_relative_corpus() {
    let case = TempDir::new().expect("case tempdir");
    let scan_root = case.path().join("scan-root");
    let config_corpus = case.path().join("config-corpus");
    let cli_corpus = case.path().join("cli-corpus");
    std::fs::create_dir(&scan_root).expect("create scan root");
    std::fs::write(scan_root.join("planted.txt"), PLANTED).expect("write fixture");
    copy_detector(&config_corpus, "aws-access-key.toml");
    copy_detector(&cli_corpus, "stripe-secret-key.toml");
    std::fs::write(
        scan_root.join(".keyhog.toml"),
        "detectors = \"../config-corpus\"\n[scan]\nformat = \"json\"\n",
    )
    .expect("write repository config");

    let (baseline_code, baseline_stdout, baseline_stderr) =
        scan_from_cwd(&scan_root, case.path(), &["--no-entropy"]);
    assert_eq!(
        baseline_code,
        Some(1),
        "the config-owned AWS corpus must report the planted key before the CLI override; stdout={baseline_stdout} stderr={baseline_stderr}"
    );
    assert!(
        baseline_stdout.contains("\"detector_id\":\"aws-access-key\""),
        "the precedence baseline must prove the config corpus is active; stdout={baseline_stdout}"
    );

    let cli_corpus_arg = cli_corpus.to_string_lossy().into_owned();
    let (code, stdout, stderr) = scan_from_cwd(
        &scan_root,
        case.path(),
        &["--no-entropy", "--detectors", &cli_corpus_arg],
    );
    assert_eq!(
        code,
        Some(0),
        "the CLI-selected Stripe corpus must replace the config-owned AWS corpus; stdout={stdout} stderr={stderr}"
    );
    assert_eq!(
        stdout.trim(),
        "[]",
        "the Stripe-only CLI corpus must not report the planted AWS key"
    );
}

// ---------------------------------------------------------------------------
// FAIL-CLOSED: malformed / invalid config fails loudly with exit 2 + a helpful,
// key-naming message. Never a silent degrade.
// ---------------------------------------------------------------------------

#[test]
fn malformed_toml_syntax_fails_closed_with_helpful_message() {
    // `[scan].severity = ` is a syntax error. The scan must fail closed (exit 2) and the
    // message must name the failure AND the fix (not silently scan on defaults).
    let dir = make_scan_dir(Some("[scan]\nseverity = \n"));
    let (code, _stdout, stderr) = scan(dir.path(), &[]);
    assert_eq!(
        code,
        Some(2),
        "a malformed `.keyhog.toml` must fail closed with exit 2.\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains("invalid .keyhog.toml configuration"),
        "error must announce the invalid config.\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains("failed to parse TOML"),
        "error must identify the TOML parse failure.\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains("correct the TOML syntax or run with --no-config"),
        "error must name the fix (correct syntax or --no-config).\n--- stderr ---\n{stderr}"
    );
}

#[test]
fn unknown_config_field_fails_closed() {
    // `deny_unknown_fields`: a typo'd/unknown key is rejected, not silently
    // ignored, so a mis-spelled security knob can never appear to be honored.
    let dir = make_scan_dir(Some("totally_unknown_key = 5\n"));
    let (code, _stdout, stderr) = scan(dir.path(), &[]);
    assert_eq!(
        code,
        Some(2),
        "an unknown config field must fail closed with exit 2.\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains("invalid .keyhog.toml configuration"),
        "error must announce the invalid config.\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains("unknown field `totally_unknown_key`"),
        "error must name the offending unknown field.\n--- stderr ---\n{stderr}"
    );
}

#[test]
fn invalid_severity_value_lists_the_valid_values() {
    // A semantically invalid enum string TOML parsing cannot catch: fail closed
    // with a message that enumerates the accepted values.
    let dir = make_scan_dir(Some("[scan]\nseverity = \"bogus\"\n"));
    let (code, _stdout, stderr) = scan(dir.path(), &[]);
    assert_eq!(
        code,
        Some(2),
        "an invalid `severity` value must fail closed with exit 2.\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains(
            "- [scan].severity = \"bogus\": expected one of info, client-safe, low, medium, high, critical"
        ),
        "error must quote the bad value and list the valid severities.\n--- stderr ---\n{stderr}"
    );
}

#[test]
fn invalid_format_value_lists_the_valid_formats() {
    // Same semantic-validation contract for the `format` enum.
    let dir = make_scan_dir(Some("[scan]\nformat = \"xmlish\"\n"));
    let (code, _stdout, stderr) = scan(dir.path(), &[]);
    assert_eq!(
        code,
        Some(2),
        "an invalid `format` value must fail closed with exit 2.\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains(
            "- [scan].format = \"xmlish\": expected one of text, json, json-envelope, jsonl, \
             jsonl-envelope, sarif, csv, github-annotations, gitlab-sast, html, junit"
        ),
        "error must quote the bad value and list the valid formats.\n--- stderr ---\n{stderr}"
    );
}

#[test]
fn invalid_scan_section_value_names_the_nested_key() {
    // A bad value under `[scan]` must be attributed to the nested key
    // (`[scan].severity`), not the flat top-level key, so the operator edits the
    // right line.
    let dir = make_scan_dir(Some("[scan]\nseverity = \"nope\"\n"));
    let (code, _stdout, stderr) = scan(dir.path(), &[]);
    assert_eq!(
        code,
        Some(2),
        "an invalid `[scan].severity` must fail closed with exit 2.\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains(
            "- [scan].severity = \"nope\": expected one of info, client-safe, low, medium, high, critical"
        ),
        "error must attribute the failure to the nested `[scan].severity` key.\n\
         --- stderr ---\n{stderr}"
    );
}

#[cfg(feature = "verify")]
#[test]
fn zero_verification_concurrency_in_config_fails_closed() {
    let dir = make_scan_dir(Some("verify_concurrency = 0\n"));
    let (code, _stdout, stderr) = scan(dir.path(), &[]);
    assert_eq!(code, Some(2), "zero verifier concurrency must fail closed");
    assert!(
        stderr.contains("verify_concurrency = 0: expected an integer >= 1"),
        "error must name the invalid key, value, and accepted range: {stderr}"
    );
}

#[cfg(feature = "verify")]
#[test]
fn ambiguous_legacy_rate_config_is_rejected() {
    let dir = make_scan_dir(Some("rate = 7\n"));
    let (code, _stdout, stderr) = scan(dir.path(), &[]);
    assert_eq!(
        code,
        Some(2),
        "legacy verifier rate key must not alias concurrency"
    );
    assert!(
        stderr.contains("unknown field `rate`") && stderr.contains("verify_concurrency"),
        "config error must reject the old key and expose the canonical replacement: {stderr}"
    );
}

#[test]
fn explicit_config_missing_file_fails_closed_with_fix() {
    // `--config` to a non-existent path must fail closed with exit 2 and name the
    // read failure + the fix (never silently fall back to a default scan).
    let scan_dir = make_scan_dir(None);
    let output = Command::new(binary())
        .arg("scan")
        .arg("--daemon=off")
        .arg("--backend")
        .arg("cpu")
        .arg("--config")
        .arg("/nonexistent/keyhog/nope.toml")
        .arg(scan_dir.path())
        .output()
        .expect("spawn keyhog scan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "`--config` to a missing file must fail closed with exit 2."
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid .keyhog.toml configuration"),
        "error must announce the invalid config.\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains("failed to read config file"),
        "error must identify the read failure.\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains(
            "make the file readable, pass a valid --config path, or run with --no-config"
        ),
        "error must name the fix for an unreadable config.\n--- stderr ---\n{stderr}"
    );
}
