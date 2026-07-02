//! E2E regression: the explicit `--config PATH` flag loading a `tool.toml`
//! through the real `keyhog` binary. Complements
//! `regression_cli_config_file_load.rs` (which centers on `.keyhog.toml`
//! walk-up discovery and rendering knobs) by exercising the two Tier-A *scan
//! policy* knobs an operator most often points `--config` at — `min_confidence`
//! and `severity` — plus the flag's precedence (explicit `--config` beats
//! walk-up discovery, and a CLI flag beats the config) and its fail-closed
//! error surface.
//!
//! Every assertion drives the shipped executable (`env!("CARGO_BIN_EXE_keyhog")`)
//! and checks a CONCRETE effect: exact exit code (0 clean / 1 finding / 2 config
//! error), exact detector id in the JSON, or the exact operator-visible error
//! substring — never merely "non-empty".
//!
//! HOST-INDEPENDENCE: every scan pins `--backend cpu`, the scalar path present
//! on every host, so no assertion depends on Hyperscan / SIMD / GPU. The
//! fixtures (a valid-CRC GitHub classic PAT and a shape-complete Slack webhook
//! URL) both fire deterministically on the scalar path, and their observed
//! confidences (0.9 / 1.0) and severities (critical / high) are the concrete
//! values the confidence/severity assertions pin.
//!
//! FIXTURE VALUES (observed from the shipped binary, cpu backend):
//!   * `github-classic-pat`  confidence 0.9,  severity critical
//!   * `slack-webhook-url`   confidence 1.0,  severity high
//!   * `aws-access-key`      confidence 1.0,  severity critical
//! The GitHub PAT carries a valid trailing CRC checksum (`...002C8GjS`); a
//! fabricated body would be silently dropped, so this canonical token is used.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

// Fixture credentials, each split with `concat!` so the literal token never
// appears verbatim in this source (the repo dogfood-scans its own tree).

/// GitHub classic PAT with a valid CRC checksum → `github-classic-pat`,
/// observed confidence 0.9, severity critical.
const GITHUB_PAT_LINE: &str = concat!(
    "github_pat = \"ghp_",
    "0000000000000000000000000000002C8GjS",
    "\"\n"
);

/// Shape-complete Slack incoming-webhook URL → `slack-webhook-url`, observed
/// confidence 1.0, severity high. The 24-char secret segment is lowercase
/// alphanumerics matching `[a-zA-Z0-9]{24}`.
const SLACK_WEBHOOK_LINE: &str = concat!(
    "url=https://hooks.slack.com/services/T0000ABCD1/B0000ABCD2/",
    "abcdefghijklmnopqrstuvwx",
    "\n"
);

/// AWS access-key id (no checksum) → `aws-access-key`, observed confidence 1.0,
/// severity critical.
const AWS_KEY_LINE: &str = concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\n");

/// Write a temp scan dir containing a single fixture file. Returns the owned
/// `TempDir` (keep it alive for the scan's duration).
fn scan_dir_with(file_name: &str, body: &str) -> TempDir {
    let dir = TempDir::new().expect("scan tempdir");
    std::fs::write(dir.path().join(file_name), body).expect("write fixture");
    dir
}

/// Write a `tool.toml` outside any scan dir and return (owned dir, path).
fn config_file(body: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("config tempdir");
    let path = dir.path().join("tool.toml");
    std::fs::write(&path, body).expect("write tool.toml");
    (dir, path)
}

/// Run `keyhog scan --no-daemon --backend cpu <extra...> <scan_dir>` and return
/// (exit code, stdout, stderr). `--backend cpu` keeps every run host-independent.
fn scan(scan_dir: &std::path::Path, extra: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(binary())
        .arg("scan")
        .arg("--no-daemon")
        .arg("--backend")
        .arg("cpu")
        .args(extra)
        .arg(scan_dir)
        .output()
        .expect("spawn keyhog scan");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

// ---------------------------------------------------------------------------
// POSITIVE: an explicit `--config PATH` with a Tier-A scan-policy knob changes
// scan behavior vs the config-free default.
// ---------------------------------------------------------------------------

#[test]
fn explicit_config_min_confidence_suppresses_below_threshold() {
    let dir = scan_dir_with("gh.txt", GITHUB_PAT_LINE);

    // Baseline FIRST: with no config the 0.9-confidence PAT fires (exit 1). If
    // this regresses the suppression assertion below would be vacuous.
    let (code, stdout, stderr) = scan(dir.path(), &["--format", "json"]);
    assert_eq!(
        code,
        Some(1),
        "no-config baseline: the github PAT must fire (exit 1) on the cpu path.\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert!(
        stdout.contains("\"detector_id\":\"github-classic-pat\""),
        "baseline stdout must carry the github-classic-pat finding.\n--- stdout ---\n{stdout}"
    );
    assert!(
        stdout.contains("\"confidence\":0.9"),
        "baseline finding confidence must be exactly 0.9.\n--- stdout ---\n{stdout}"
    );

    // A `tool.toml` at min_confidence = 0.95 sits ABOVE the 0.9 finding, so the
    // explicit --config load drops it → clean scan, empty JSON array, exit 0.
    let (_cfg, cfg_path) = config_file("min_confidence = 0.95\n");
    let cfg = cfg_path.to_str().unwrap();
    let (code, stdout, stderr) = scan(dir.path(), &["--format", "json", "--config", cfg]);
    assert_eq!(
        code,
        Some(0),
        "an explicit --config with min_confidence = 0.95 must drop the 0.9 finding \
         → exit 0.\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert_eq!(
        stdout.trim(),
        "[]",
        "the suppressed scan must emit exactly an empty JSON array.\n--- stdout ---\n{stdout}"
    );
}

#[test]
fn explicit_config_min_confidence_boundary_is_inclusive() {
    let dir = scan_dir_with("gh.txt", GITHUB_PAT_LINE);

    // At the EXACT finding confidence (0.9) the filter is inclusive (>=), so the
    // finding is kept.
    let (_c1, at_path) = config_file("min_confidence = 0.9\n");
    let (code, stdout, stderr) = scan(
        dir.path(),
        &["--format", "json", "--config", at_path.to_str().unwrap()],
    );
    assert_eq!(
        code,
        Some(1),
        "min_confidence = 0.9 == finding confidence must KEEP it (inclusive floor).\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert!(
        stdout.contains("\"detector_id\":\"github-classic-pat\""),
        "boundary-equal scan must still report the github PAT.\n--- stdout ---\n{stdout}"
    );

    // A hair above the finding confidence drops it.
    let (_c2, above_path) = config_file("min_confidence = 0.900001\n");
    let (code, stdout, _e) = scan(
        dir.path(),
        &["--format", "json", "--config", above_path.to_str().unwrap()],
    );
    assert_eq!(
        code,
        Some(0),
        "min_confidence just above 0.9 must drop the finding → exit 0.\n--- stdout ---\n{stdout}"
    );
    assert_eq!(stdout.trim(), "[]", "dropped scan must be empty JSON.");
}

#[test]
fn explicit_config_min_confidence_top_keeps_only_perfect_confidence() {
    // Two fixtures in one tree: AWS key (confidence 1.0) and GitHub PAT (0.9).
    // A `--config` min_confidence = 1.0 is the inclusive top: it keeps ONLY the
    // 1.0 finding and drops the 0.9 one.
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("aws.txt"), AWS_KEY_LINE).expect("write aws");
    std::fs::write(dir.path().join("gh.txt"), GITHUB_PAT_LINE).expect("write gh");

    let (_cfg, cfg_path) = config_file("min_confidence = 1.0\n");
    let (code, stdout, stderr) = scan(
        dir.path(),
        &["--format", "json", "--config", cfg_path.to_str().unwrap()],
    );
    assert_eq!(
        code,
        Some(1),
        "min_confidence = 1.0 must keep the confidence-1.0 aws key.\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert!(
        stdout.contains("\"detector_id\":\"aws-access-key\""),
        "the 1.0-confidence aws-access-key must survive the top floor.\n--- stdout ---\n{stdout}"
    );
    assert!(
        !stdout.contains("\"detector_id\":\"github-classic-pat\""),
        "the 0.9-confidence github PAT must be dropped by min_confidence = 1.0.\n\
         --- stdout ---\n{stdout}"
    );
}

#[test]
fn explicit_config_severity_filter_drops_lower_severity() {
    let dir = scan_dir_with("hook.txt", SLACK_WEBHOOK_LINE);

    // Baseline: the high-severity slack webhook fires with no config.
    let (code, stdout, stderr) = scan(dir.path(), &["--format", "json"]);
    assert_eq!(
        code,
        Some(1),
        "no-config baseline: the high-severity slack webhook must fire.\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert!(
        stdout.contains("\"detector_id\":\"slack-webhook-url\""),
        "baseline must report slack-webhook-url.\n--- stdout ---\n{stdout}"
    );
    assert!(
        stdout.contains("\"severity\":\"high\""),
        "the slack webhook finding must be severity high.\n--- stdout ---\n{stdout}"
    );

    // `severity = "critical"` raises the report floor ABOVE the finding's `high`,
    // so the explicit --config filters it out → exit 0, empty array.
    let (_cfg, cfg_path) = config_file("severity = \"critical\"\n");
    let (code, stdout, stderr) = scan(
        dir.path(),
        &["--format", "json", "--config", cfg_path.to_str().unwrap()],
    );
    assert_eq!(
        code,
        Some(0),
        "--config severity = \"critical\" must filter out the high finding → exit 0.\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert_eq!(
        stdout.trim(),
        "[]",
        "severity-filtered scan must emit exactly an empty JSON array.\n--- stdout ---\n{stdout}"
    );
}

#[test]
fn explicit_config_severity_at_or_below_keeps_finding() {
    let dir = scan_dir_with("hook.txt", SLACK_WEBHOOK_LINE);

    // `severity = "high"` (== the finding's severity) keeps it; the floor is
    // inclusive of the named level.
    let (_c1, high_path) = config_file("severity = \"high\"\n");
    let (code, stdout, stderr) = scan(
        dir.path(),
        &["--format", "json", "--config", high_path.to_str().unwrap()],
    );
    assert_eq!(
        code,
        Some(1),
        "severity = \"high\" (== finding severity) must keep the finding.\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert!(
        stdout.contains("\"detector_id\":\"slack-webhook-url\""),
        "severity=high scan must report slack-webhook-url.\n--- stdout ---\n{stdout}"
    );

    // `severity = "medium"` (below high) also keeps it.
    let (_c2, med_path) = config_file("severity = \"medium\"\n");
    let (code, stdout, _e) = scan(
        dir.path(),
        &["--format", "json", "--config", med_path.to_str().unwrap()],
    );
    assert_eq!(
        code,
        Some(1),
        "severity = \"medium\" (below high) must keep the high finding.\n--- stdout ---\n{stdout}"
    );
    assert!(
        stdout.contains("\"detector_id\":\"slack-webhook-url\""),
        "severity=medium scan must still report the finding.\n--- stdout ---\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// PRECEDENCE: explicit --config beats walk-up discovery; a CLI flag beats the
// config value.
// ---------------------------------------------------------------------------

#[test]
fn explicit_config_overrides_discovered_keyhog_toml() {
    // A `.keyhog.toml` in the scan dir sets min_confidence = 0.99 (would drop the
    // 0.9 PAT). An explicit `--config` at 0.5 must WIN → the PAT survives.
    let dir = scan_dir_with("gh.txt", GITHUB_PAT_LINE);
    std::fs::write(dir.path().join(".keyhog.toml"), "min_confidence = 0.99\n")
        .expect("write discovered config");

    // Control: the discovered 0.99 alone suppresses the finding.
    let (code, stdout, stderr) = scan(dir.path(), &["--format", "json"]);
    assert_eq!(
        code,
        Some(0),
        "discovered .keyhog.toml min_confidence = 0.99 alone must suppress the 0.9 PAT.\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert_eq!(
        stdout.trim(),
        "[]",
        "discovered-only scan must be empty JSON."
    );

    // Explicit --config at 0.5 overrides the discovered 0.99 → PAT reported.
    let (_cfg, cfg_path) = config_file("min_confidence = 0.5\n");
    let (code, stdout, stderr) = scan(
        dir.path(),
        &["--format", "json", "--config", cfg_path.to_str().unwrap()],
    );
    assert_eq!(
        code,
        Some(1),
        "explicit --config (0.5) must override the discovered .keyhog.toml (0.99): \
         the PAT must fire.\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert!(
        stdout.contains("\"detector_id\":\"github-classic-pat\""),
        "override scan must report the github PAT the discovered config tried to hide.\n\
         --- stdout ---\n{stdout}"
    );
}

#[test]
fn cli_min_confidence_flag_overrides_config_value() {
    // Config asks for a low floor (0.5); the explicit `--min-confidence 0.99`
    // CLI flag is the highest-precedence layer and wins, dropping the 0.9 PAT.
    let dir = scan_dir_with("gh.txt", GITHUB_PAT_LINE);
    let (_cfg, cfg_path) = config_file("min_confidence = 0.5\n");
    let (code, stdout, stderr) = scan(
        dir.path(),
        &[
            "--format",
            "json",
            "--config",
            cfg_path.to_str().unwrap(),
            "--min-confidence",
            "0.99",
        ],
    );
    assert_eq!(
        code,
        Some(0),
        "CLI --min-confidence 0.99 must override config min_confidence = 0.5 and \
         drop the 0.9 PAT → exit 0.\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert_eq!(
        stdout.trim(),
        "[]",
        "CLI-overridden scan must emit an empty JSON array.\n--- stdout ---\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// FAIL-CLOSED: a bad `--config` target fails loudly with exit 2 and a message
// that names the failure AND the fix — never a silent degrade to a default scan.
// ---------------------------------------------------------------------------

#[test]
fn explicit_config_missing_file_fails_closed_with_fix() {
    let dir = scan_dir_with("gh.txt", GITHUB_PAT_LINE);
    let (code, _stdout, stderr) = scan(
        dir.path(),
        &[
            "--config",
            "/nonexistent/keyhog/tool.toml",
            "--format",
            "json",
        ],
    );
    assert_eq!(
        code,
        Some(2),
        "--config to a missing file must fail closed with exit 2.\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains("invalid .keyhog.toml configuration"),
        "error must announce the invalid config.\n--- stderr ---\n{stderr}"
    );
    // Inner reason is wrapped; assert the inner substring, not the whole string.
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

#[test]
fn explicit_config_pointing_at_directory_fails_closed() {
    // Pointing `--config` at a directory is a distinct read failure ("Is a
    // directory") from a missing file, and must still fail closed with exit 2.
    let dir = scan_dir_with("gh.txt", GITHUB_PAT_LINE);
    let cfg_dir = TempDir::new().expect("dir-as-config");
    let (code, _stdout, stderr) = scan(
        dir.path(),
        &[
            "--config",
            cfg_dir.path().to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert_eq!(
        code,
        Some(2),
        "--config pointing at a directory must fail closed with exit 2.\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains("failed to read config file"),
        "error must identify the read failure.\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains("Is a directory"),
        "error must carry the OS read reason (Is a directory).\n--- stderr ---\n{stderr}"
    );
}

#[test]
fn explicit_config_unknown_field_fails_closed() {
    // `deny_unknown_fields`: a typo'd key in the --config file is a TOML parse
    // error, not a silent ignore — a mis-spelled security knob can never look
    // honored.
    let dir = scan_dir_with("gh.txt", GITHUB_PAT_LINE);
    let (_cfg, cfg_path) = config_file("bogus_key = 1\n");
    let (code, _stdout, stderr) = scan(
        dir.path(),
        &["--config", cfg_path.to_str().unwrap(), "--format", "json"],
    );
    assert_eq!(
        code,
        Some(2),
        "an unknown field in the --config file must fail closed with exit 2.\n\
         --- stderr ---\n{stderr}"
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
        stderr.contains("unknown field `bogus_key`"),
        "error must name the offending unknown field.\n--- stderr ---\n{stderr}"
    );
}

#[test]
fn explicit_config_invalid_severity_value_lists_valid_values() {
    // A semantically invalid enum string TOML parsing cannot catch: fail closed
    // with a message that quotes the bad value and enumerates the valid ones.
    let dir = scan_dir_with("gh.txt", GITHUB_PAT_LINE);
    let (_cfg, cfg_path) = config_file("severity = \"nope\"\n");
    let (code, _stdout, stderr) = scan(
        dir.path(),
        &["--config", cfg_path.to_str().unwrap(), "--format", "json"],
    );
    assert_eq!(
        code,
        Some(2),
        "an invalid severity value in --config must fail closed with exit 2.\n\
         --- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains("- severity = \"nope\": expected one of info, low, medium, high, critical"),
        "error must quote the bad value and list the valid severities.\n--- stderr ---\n{stderr}"
    );
}

#[test]
fn config_and_no_config_flags_are_mutually_exclusive() {
    // clap rejects `--config` together with `--no-config` before any scan runs;
    // this is a usage error (exit 2) with a message naming the conflict.
    let dir = scan_dir_with("gh.txt", GITHUB_PAT_LINE);
    let (_cfg, cfg_path) = config_file("min_confidence = 0.5\n");
    let output = Command::new(binary())
        .arg("scan")
        .arg("--no-daemon")
        .arg("--backend")
        .arg("cpu")
        .arg("--config")
        .arg(&cfg_path)
        .arg("--no-config")
        .arg(dir.path())
        .output()
        .expect("spawn keyhog scan");
    assert_eq!(
        output.status.code(),
        Some(2),
        "--config together with --no-config must be a clap usage error (exit 2)."
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be used with '--no-config'"),
        "clap error must name the --config / --no-config conflict.\n--- stderr ---\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// ADVERSARIAL / CHARACTERIZATION: the range-validation asymmetry between the
// CLI `--min-confidence` value_parser and the config `min_confidence` merge.
// ---------------------------------------------------------------------------

#[test]
fn min_confidence_range_validation_differs_between_cli_and_config() {
    // The CLI value_parser (`parse_min_confidence`) enforces [0.0, 1.0]: an
    // out-of-range 5.0 is REJECTED as a clap usage error (exit 2) naming the
    // bound.
    let dir = scan_dir_with("gh.txt", GITHUB_PAT_LINE);
    let (code, _stdout, stderr) =
        scan(dir.path(), &["--min-confidence", "5.0", "--format", "json"]);
    assert_eq!(
        code,
        Some(2),
        "CLI --min-confidence 5.0 must be rejected with exit 2.\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains("min_confidence must be between 0.0 and 1.0"),
        "CLI rejection must name the [0.0, 1.0] bound.\n--- stderr ---\n{stderr}"
    );

    // The config merge, by contrast, applies `min_confidence = 5.0` WITHOUT a
    // range check: it is silently accepted and, being above every possible
    // confidence, zeroes recall (clean scan, exit 0). This documents a real
    // validation gap — the same value that the CLI fails closed on is honored
    // as a config value with no error — so a future fix that adds a config-side
    // range check (making this exit 2 like the CLI) is an intentional change
    // this test will flag, not a silent regression.
    let (_cfg, cfg_path) = config_file("min_confidence = 5.0\n");
    let (code, stdout, stderr) = scan(
        dir.path(),
        &["--config", cfg_path.to_str().unwrap(), "--format", "json"],
    );
    assert_eq!(
        code,
        Some(0),
        "config min_confidence = 5.0 is currently accepted un-validated and \
         suppresses every finding → exit 0.\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert_eq!(
        stdout.trim(),
        "[]",
        "the un-validated over-range floor zeroes recall (empty JSON array).\n\
         --- stdout ---\n{stdout}"
    );
}
