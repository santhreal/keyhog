//! e2e for `keyhog backend --autoroute` inspection + `keyhog calibrate-autoroute`.
//!
//! `backend --autoroute [--json]` renders the persisted autoroute calibration
//! cache read-only (`run_autoroute_inspection` in
//! `crates/cli/src/subcommands/backend.rs`, backed by `inspect_autoroute_cache`
//! in `crates/cli/src/orchestrator/dispatch/backend/store/codec.rs`). It always exits
//! 0, even for a missing / corrupt / stale cache, because it is a diagnostic
//! read, not a scan; the loud status text tells the operator what a real scan
//! would fail closed on.
//!
//! These tests drive the REAL binary via `CARGO_BIN_EXE_keyhog`. The autoroute
//! cache resolves to `dirs::cache_dir()/keyhog/autoroute.json`, so each test
//! points `HOME` + `XDG_CACHE_HOME` at a fresh tempdir to stay hermetic, and
//! discovers the exact on-disk path by parsing the JSON inspection's `path`
//! field (works on every platform's cache-dir convention).
//!
//! Pinned facts (read from source, asserted exactly):
//!   * `AUTOROUTE_CACHE_VERSION = 34` (backend.rs), the schema version an
//!     inspected valid cache reports and an incompatible one is rejected against.
//!   * `AUTOROUTE_CACHE_FILE_BYTES = 8 * 1024 * 1024` in the cache codec, the read
//!     cap; a file one byte over is reported "unreadable".
//!   * `calibrate-autoroute` sweeps 92 workloads × 4 scan policies (default +
//!     `--fast`/`--deep`/`--precision`) = 368 probes, and each policy resolves a
//!     DISTINCT config digest, so the primed cache holds exactly 4 configs.

use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

/// Schema version this build's cache reports and requires.
const EXPECTED_CACHE_VERSION: u64 = 34;
/// Read cap for the cache file (kept in sync with the cache codec).
const CACHE_FILE_CAP_BYTES: usize = 8 * 1024 * 1024;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A fresh hermetic cache home: both `HOME` and `XDG_CACHE_HOME` point here so
/// `dirs::cache_dir()` lands inside the tempdir on every platform.
fn cache_home() -> TempDir {
    TempDir::new().expect("tempdir")
}

/// Build a `keyhog` command with the cache home wired in.
fn cmd(home: &Path) -> Command {
    let mut c = Command::new(binary());
    c.env("HOME", home);
    c.env("XDG_CACHE_HOME", home);
    // Keep child output deterministic / uncolored (piped stdout is already
    // non-tty, but be explicit).
    c.env("NO_COLOR", "1");
    c
}

/// Run `keyhog backend --autoroute --json` under `home` and return parsed JSON.
fn inspect_json(home: &Path) -> (i32, serde_json::Value) {
    let out = cmd(home)
        .args(["backend", "--autoroute", "--json"])
        .output()
        .expect("spawn keyhog backend --autoroute --json");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "inspection must emit valid JSON: {e}; stdout={stdout}; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out.status.code().expect("exit code"), value)
}

/// Discover the exact on-disk autoroute cache path for `home` by asking the
/// binary (its JSON inspection reports the path it resolved).
fn resolve_cache_path(home: &Path) -> PathBuf {
    let (_code, value) = inspect_json(home);
    let path = value
        .get("path")
        .and_then(serde_json::Value::as_str)
        .expect("inspection JSON exposes a `path` field");
    PathBuf::from(path)
}

/// Write `contents` to the resolved cache path (creating the parent dir).
fn write_cache(home: &Path, contents: &[u8]) -> PathBuf {
    let path = resolve_cache_path(home);
    std::fs::create_dir_all(path.parent().expect("cache path has a parent"))
        .expect("create cache parent dir");
    std::fs::write(&path, contents).expect("write crafted cache");
    path
}

// --- uncalibrated (no cache file) -------------------------------------------

#[test]
fn autoroute_json_uncalibrated_reports_not_present_exit_zero() {
    let home = cache_home();
    let (code, value) = inspect_json(home.path());

    assert_eq!(code, 0, "read-only inspection always exits 0");
    assert_eq!(
        value.get("present"),
        Some(&serde_json::Value::Bool(false)),
        "no cache file yet => present=false; value={value}"
    );
    assert_eq!(
        value.get("error"),
        Some(&serde_json::Value::Null),
        "a missing cache is not an error, just uncalibrated; value={value}"
    );
    assert_eq!(
        value.get("version"),
        Some(&serde_json::Value::Null),
        "no schema version is read from an absent cache; value={value}"
    );
    assert_eq!(
        value.get("identity_matches_build"),
        Some(&serde_json::Value::Null),
        "no identity check runs on an absent cache; value={value}"
    );
    assert_eq!(
        value
            .get("configs")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0),
        "an uncalibrated cache exposes zero configs; value={value}"
    );
}

#[test]
fn autoroute_json_uncalibrated_omits_identity_and_digest_fields() {
    let home = cache_home();
    let (code, value) = inspect_json(home.path());

    assert_eq!(code, 0);
    // The resolved path is still reported (so the operator knows WHERE to prime).
    let path = value
        .get("path")
        .and_then(serde_json::Value::as_str)
        .expect("path present");
    assert!(
        path.ends_with("autoroute.json"),
        "resolved cache path ends with autoroute.json; got {path}"
    );
    for absent in [
        "binary_version",
        "git_hash",
        "detector_digest",
        "rules_digest",
        "host",
    ] {
        assert_eq!(
            value.get(absent),
            Some(&serde_json::Value::Null),
            "field `{absent}` must be null for an absent cache; value={value}"
        );
    }
}

#[test]
fn autoroute_human_uncalibrated_prints_status_and_repair_command() {
    let home = cache_home();
    let out = cmd(home.path())
        .args(["backend", "--autoroute"])
        .output()
        .expect("spawn keyhog backend --autoroute");
    assert_eq!(out.status.code(), Some(0), "inspection exits 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("## autoroute calibration cache"),
        "human output has the section header; stdout={stdout}"
    );
    assert!(
        stdout.contains("not calibrated yet"),
        "an absent cache reports the exact `not calibrated yet` status; stdout={stdout}"
    );
    assert!(
        stdout.contains("keyhog calibrate-autoroute"),
        "the repair path names the calibrate command; stdout={stdout}"
    );
}

// --- unusable cache (wrong version / corrupt / oversized) -------------------

#[test]
fn autoroute_json_wrong_schema_version_reports_incompatible() {
    let home = cache_home();
    // A version envelope that parses but mismatches the current schema.
    write_cache(home.path(), br#"{"version": 3}"#);

    let (code, value) = inspect_json(home.path());
    assert_eq!(
        code, 0,
        "an incompatible cache is a diagnostic, still exit 0"
    );
    assert_eq!(
        value.get("present"),
        Some(&serde_json::Value::Bool(true)),
        "the file exists => present=true; value={value}"
    );
    assert_eq!(
        value.get("version"),
        Some(&serde_json::Value::Number(3u64.into())),
        "the read schema version is surfaced verbatim; value={value}"
    );
    let error = value
        .get("error")
        .and_then(serde_json::Value::as_str)
        .expect("error string present");
    assert!(
        error.contains("cache schema version 3 is incompatible")
            && error.contains(&format!("expects {EXPECTED_CACHE_VERSION}")),
        "error names both the stale version and the expected {EXPECTED_CACHE_VERSION}; error={error}"
    );
    assert_eq!(
        value
            .get("configs")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0),
        "an incompatible cache surfaces no configs; value={value}"
    );
}

#[test]
fn autoroute_json_corrupt_non_json_reports_parse_error() {
    let home = cache_home();
    write_cache(home.path(), b"not-json-at-all");

    let (code, value) = inspect_json(home.path());
    assert_eq!(code, 0);
    assert_eq!(
        value.get("present"),
        Some(&serde_json::Value::Bool(true)),
        "the corrupt file exists => present=true; value={value}"
    );
    assert_eq!(
        value.get("version"),
        Some(&serde_json::Value::Null),
        "no version can be read from non-JSON bytes; value={value}"
    );
    let error = value
        .get("error")
        .and_then(serde_json::Value::as_str)
        .expect("error string present");
    assert!(
        error.contains("autoroute cache is not valid cache JSON"),
        "error names the JSON parse failure; error={error}"
    );
}

#[test]
fn autoroute_json_version_ok_but_payload_undeserializable() {
    let home = cache_home();
    // The version envelope matches, but the full payload is missing every other
    // required field, so the second (full) deserialize fails distinctly.
    write_cache(
        home.path(),
        format!("{{\"version\": {EXPECTED_CACHE_VERSION}}}").as_bytes(),
    );

    let (code, value) = inspect_json(home.path());
    assert_eq!(code, 0);
    assert_eq!(
        value.get("version"),
        Some(&serde_json::Value::Number(EXPECTED_CACHE_VERSION.into())),
        "the compatible version is read before the payload fails; value={value}"
    );
    let error = value
        .get("error")
        .and_then(serde_json::Value::as_str)
        .expect("error string present");
    assert!(
        error.contains("autoroute cache payload did not deserialize"),
        "error distinguishes payload-shape failure from version failure; error={error}"
    );
}

#[test]
fn autoroute_json_oversized_cache_reports_unreadable_cap() {
    let home = cache_home();
    // One byte over the 8 MiB read cap => `read_autoroute_cache_file` refuses it.
    let oversized = vec![b'0'; CACHE_FILE_CAP_BYTES + 1];
    write_cache(home.path(), &oversized);

    let (code, value) = inspect_json(home.path());
    assert_eq!(code, 0);
    assert_eq!(
        value.get("present"),
        Some(&serde_json::Value::Bool(true)),
        "the (too-big) file exists => present=true; value={value}"
    );
    let error = value
        .get("error")
        .and_then(serde_json::Value::as_str)
        .expect("error string present");
    assert!(
        error.contains("unreadable") && error.contains(&CACHE_FILE_CAP_BYTES.to_string()),
        "error reports the cache as unreadable and names the {CACHE_FILE_CAP_BYTES}-byte cap; error={error}"
    );
}

#[test]
fn autoroute_human_wrong_version_prints_repair_command() {
    let home = cache_home();
    write_cache(home.path(), br#"{"version": 7}"#);

    let out = cmd(home.path())
        .args(["backend", "--autoroute"])
        .output()
        .expect("spawn keyhog backend --autoroute");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("## autoroute calibration cache"),
        "section header printed; stdout={stdout}"
    );
    assert!(
        stdout.contains("incompatible"),
        "human status surfaces the incompatible-version reason; stdout={stdout}"
    );
    assert!(
        stdout.contains("keyhog calibrate-autoroute"),
        "the repair paragraph names the calibrate command; stdout={stdout}"
    );
}

#[test]
fn autoroute_human_corrupt_cache_prints_error_and_repair() {
    let home = cache_home();
    write_cache(home.path(), b"} not json {");

    let out = cmd(home.path())
        .args(["backend", "--autoroute"])
        .output()
        .expect("spawn keyhog backend --autoroute");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("not valid cache JSON"),
        "human status surfaces the corrupt-JSON reason; stdout={stdout}"
    );
    assert!(
        stdout.contains("keyhog calibrate-autoroute"),
        "repair path named; stdout={stdout}"
    );
}

// --- argument contract ------------------------------------------------------

#[test]
fn backend_json_without_a_json_target_is_a_usage_error() {
    // `--json` requires the json_target group (`--self-test` | `--autoroute`).
    let out = Command::new(binary())
        .args(["backend", "--json"])
        .output()
        .expect("spawn keyhog backend --json");
    assert_eq!(
        out.status.code(),
        Some(2),
        "clap usage error exits 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("required arguments were not provided")
            || stderr.contains("cannot be used"),
        "clap names the unsatisfied `--json` requirement; stderr={stderr}"
    );
}

#[test]
fn backend_autoroute_and_self_test_are_mutually_exclusive() {
    // Both belong to the `json_target` ArgGroup (single-valued), so requesting
    // both is a conflict.
    let out = Command::new(binary())
        .args(["backend", "--autoroute", "--self-test"])
        .output()
        .expect("spawn keyhog backend --autoroute --self-test");
    assert_eq!(
        out.status.code(),
        Some(2),
        "conflicting inspection targets exit 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot be used with"),
        "clap reports the mutually-exclusive conflict; stderr={stderr}"
    );
}

// --- calibrate-autoroute ----------------------------------------------------

#[test]
fn calibrate_autoroute_cache_off_is_rejected_up_front() {
    // `off` disables persistence, which defeats the whole point of calibration;
    // it must be rejected once, not fail the full probe matrix closed.
    let out = Command::new(binary())
        .args(["calibrate-autoroute", "--autoroute-cache", "off"])
        .output()
        .expect("spawn keyhog calibrate-autoroute --autoroute-cache off");
    assert_eq!(
        out.status.code(),
        Some(2),
        "rejecting `off` is a user error (exit 2); stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("disables persistence") && stderr.contains("calibrate-autoroute exists to"),
        "the rejection names the off/persistence conflict; stderr={stderr}"
    );
}

#[test]
fn calibrate_autoroute_primes_cache_then_inspection_shows_configs_and_counts() {
    let home = cache_home();

    // 1. Drive the real install-time sweep into the default (hermetic) cache.
    let calibrate = cmd(home.path())
        .args(["calibrate-autoroute", "--quiet"])
        .output()
        .expect("spawn keyhog calibrate-autoroute");
    assert_eq!(
        calibrate.status.code(),
        Some(0),
        "every calibration probe must succeed; stderr={}",
        String::from_utf8_lossy(&calibrate.stderr)
    );
    let cal_stdout = String::from_utf8_lossy(&calibrate.stdout);
    // 92 workloads × 4 policies = 368 probes across 4 scan policies.
    assert!(
        cal_stdout.contains("ran 368 workload probes"),
        "summary reports the exact 368-probe sweep; stdout={cal_stdout}"
    );
    assert!(
        cal_stdout.contains("4 scan policies"),
        "summary reports the 4 swept scan policies; stdout={cal_stdout}"
    );

    // 2. The cache file now exists on disk at the resolved path.
    let cache_path = resolve_cache_path(home.path());
    assert!(
        cache_path.exists(),
        "calibration must persist the cache at {cache_path:?}"
    );

    // 3. JSON inspection reports a present, in-build, current-schema cache with
    //    exactly the 4 policy configs, each holding >=1 workload decision.
    let (code, value) = inspect_json(home.path());
    assert_eq!(code, 0);
    assert_eq!(
        value.get("present"),
        Some(&serde_json::Value::Bool(true)),
        "the primed cache is present; value={value}"
    );
    assert_eq!(
        value.get("error"),
        Some(&serde_json::Value::Null),
        "a freshly primed cache has no error; value={value}"
    );
    assert_eq!(
        value.get("version"),
        Some(&serde_json::Value::Number(EXPECTED_CACHE_VERSION.into())),
        "the cache carries the current schema version; value={value}"
    );
    assert_eq!(
        value.get("identity_matches_build"),
        Some(&serde_json::Value::Bool(true)),
        "a cache written by THIS binary matches this build; value={value}"
    );
    assert_eq!(
        value
            .get("binary_version")
            .and_then(serde_json::Value::as_str),
        Some(env!("CARGO_PKG_VERSION")),
        "the cache records this binary's crate version; value={value}"
    );

    let configs = value
        .get("configs")
        .and_then(serde_json::Value::as_array)
        .expect("configs array");
    assert_eq!(
        configs.len(),
        4,
        "default + --fast + --deep + --precision each resolve a distinct config \
         digest => exactly 4 primed configs; value={value}"
    );

    let mut total_decisions = 0u64;
    for config in configs {
        let digest = config
            .get("config_digest")
            .and_then(serde_json::Value::as_str)
            .expect("config_digest string");
        assert_eq!(
            digest.len(),
            16,
            "each config digest renders as 16 lowercase hex chars; digest={digest}"
        );
        assert!(
            digest
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "config digest is lowercase hex; digest={digest}"
        );
        let host_identity = config
            .get("host_identity")
            .and_then(serde_json::Value::as_str)
            .expect("exact host identity digest");
        assert_eq!(host_identity.len(), 64);
        assert!(host_identity
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        let count = config
            .get("decision_count")
            .and_then(serde_json::Value::as_u64)
            .expect("decision_count integer");
        let decisions_len = config
            .get("decisions")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len)
            .expect("decisions array") as u64;
        assert_eq!(
            count, decisions_len,
            "decision_count must equal the number of rendered decisions; config={config}"
        );
        assert!(
            count >= 1,
            "every primed policy config holds at least one workload decision; config={config}"
        );
        for decision in config
            .get("decisions")
            .and_then(serde_json::Value::as_array)
            .expect("decisions array")
        {
            assert!(
                decision
                    .get("backend")
                    .and_then(serde_json::Value::as_str)
                    .is_some()
                    && decision
                        .get("daemon_backend")
                        .and_then(serde_json::Value::as_str)
                        .is_some(),
                "every decision exposes one-shot and daemon routes; decision={decision}"
            );
            assert!(
                decision
                    .get("confidence_separated")
                    .and_then(serde_json::Value::as_bool)
                    .is_some()
                    && decision
                        .get("daemon_confidence_separated")
                        .and_then(serde_json::Value::as_bool)
                        .is_some(),
                "every decision exposes one-shot and daemon confidence state; decision={decision}"
            );
            for field in ["selection_basis", "daemon_selection_basis"] {
                assert!(
                    matches!(
                        decision.get(field).and_then(serde_json::Value::as_str),
                        Some("separated-95pct-confidence")
                            | Some("lowest-measured-median-among-overlapping-confidence")
                    ),
                    "{field} must name the actual resolution rule; decision={decision}"
                );
            }
        }
        total_decisions += count;
    }
    assert!(
        total_decisions >= 4,
        "at least one decision per primed config; total={total_decisions}"
    );
    assert!(
        cal_stdout.contains(&format!("cache contains {total_decisions} route decisions")),
        "calibration summary decision count must match independent cache inspection; stdout={cal_stdout}; total={total_decisions}"
    );
    assert!(
        cal_stdout.contains(&format!(
            "measured {total_decisions} unique route classes"
        )),
        "a clean sweep must report every independently inspected decision as newly measured; stdout={cal_stdout}; total={total_decisions}"
    );

    // 4. The human inspection reports the same 4-config count in prose.
    let human = cmd(home.path())
        .args(["backend", "--autoroute"])
        .output()
        .expect("spawn keyhog backend --autoroute");
    assert_eq!(human.status.code(), Some(0));
    let human_stdout = String::from_utf8_lossy(&human.stdout);
    assert!(
        human_stdout.contains("4 calibrated config(s)"),
        "human summary reports exactly 4 calibrated configs; stdout={human_stdout}"
    );
    assert!(
        human_stdout.contains("workload decision(s)"),
        "human summary reports the workload-decision total; stdout={human_stdout}"
    );
    assert!(
        human_stdout.contains("matches this build"),
        "human identity line confirms the cache matches this build; stdout={human_stdout}"
    );
    assert!(
        human_stdout.contains("one-shot ->")
            && human_stdout.contains("daemon   ->")
            && human_stdout.contains("basis="),
        "human inspection distinguishes runtime routes and their basis; stdout={human_stdout}"
    );
}
