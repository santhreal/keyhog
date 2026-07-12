//! Adversarial audit — VECTOR 5 (INSUFFICIENCY) + VECTOR 11 (UTILIZATION).
//!
//! These are black-box CLI tests: they spawn the real `keyhog` binary and use
//! the project's own documented coherence surface: `keyhog config --effective`,
//! backed by `crates/cli/src/orchestrator_config.rs::render_effective_config`.
//! That surface exists precisely to answer "what will ACTUALLY run?" so a test
//! (or an operator) can assert the tuned value, the benched value, and the
//! shipped value are the same number. We assert that the value the engine
//! receives for two numeric knobs is the value
//! `ScannerConfig::sanitise` is documented to enforce.
//!
//! FINDING (shared root cause):
//! `ScannerConfig::sanitise()` (crates/scanner/src/scanner_config.rs:138-174)
//! clamps `ml_weight` to [0.0, 1.0] and `entropy_threshold` to [0.0, 8.0],
//! and is the project's NaN/range safety net. It runs in exactly ONE place:
//! inside `From<ScanConfig> for ScannerConfig` (scanner_config.rs:221). But the
//! CLI override layer builds the config via `ScannerConfig::default()` /
//! `fast()` / `thorough()` / `high_precision()` (which DO sanitise via `From`)
//! and then MUTATES the numeric fields directly AFTER construction:
//!   - `config.entropy_threshold = threshold;`  (orchestrator_config.rs:401)
//!   - `config.ml_weight = weight;`             (orchestrator_config.rs:407)
//! Nothing re-sanitises after these mutations: `resolve_scan_config`
//! (orchestrator_config.rs:475-491) hands the un-clamped `ScannerConfig`
//! straight to `CompiledScanner::with_config` (orchestrator/mod.rs:180), and
//! `with_config` (crates/scanner/src/engine/compile.rs:254-258) merely assigns
//! the config — no clamp. The same gap exists on the `.keyhog.toml` path
//! (config.rs:435-457 fills `args.entropy_threshold` / `args.ml_weight`
//! straight from the file with no validation).
//!
//! Why this is a real defect and not cosmetic:
//!   * `--ml-weight` and `--entropy-threshold` have NO clap `value_parser`
//!     (args/scan.rs:397-398, 433-435), unlike their siblings `--min-confidence`
//!     (parse_min_confidence rejects out-of-range, value_parsers.rs:3-19) and
//!     `--ml-threshold` (parse_ml_threshold rejects out-of-range,
//!     value_parsers.rs:45-60). So the only thing that COULD clamp them is
//!     `sanitise()` — which this path bypasses.
//!   * The live ML blend in `scan_postprocess.rs:405-413` explicitly documents
//!     that it relies on `w` "already clamped to [0,1] by
//!     `ScannerConfig::sanitise`". With `--ml-weight -1.0` the blend becomes
//!     `-1·ml + 2·heuristic` (a negative ML weight — the exact malformed state
//!     sanitise() exists to prevent); with `--ml-weight 5.0` it becomes
//!     `5·ml - 4·heuristic`, which can exceed 1.0.
//!   * A negative `entropy_threshold` makes the entropy gate `entropy >= thr`
//!     always true (Shannon entropy is always ≥ 0) — the match-everything FP
//!     state sanitise() resets to 4.5.
//!
//! EXPECTED FIX: re-run `ScannerConfig::sanitise()` at the end of
//! `build_scanner_config` (after all CLI/config overrides are applied), OR add
//! a clamping `value_parser` to `--ml-weight` / `--entropy-threshold` to match
//! `--min-confidence` / `--ml-threshold`. Either makes the override layer honor
//! the same range invariant the `From` path already enforces.
//!
//! Each `#[test]` FAILS today (the oracle reports the un-clamped value) and
//! PASSES once the override layer re-sanitises.

use std::path::PathBuf;
use std::process::Command;

/// Resolve the keyhog binary under test. `CARGO_BIN_EXE_keyhog` is injected by
/// Cargo for integration tests; fall back to the prebuilt release-fast artifact.
fn binary() -> PathBuf {
    let cargo_bin = PathBuf::from(env!("CARGO_BIN_EXE_keyhog"));
    if cargo_bin.exists() {
        return cargo_bin;
    }
    let prebuilt =
        PathBuf::from("/mnt/FlareTraining/santh-archive/cargo-target/release-fast/keyhog");
    if prebuilt.exists() {
        return prebuilt;
    }
    cargo_bin
}

/// Spawn `keyhog config --effective <extra_args> <file>` and return the
/// rendered `[effective-config]` block from stdout.
///
/// The effective-config path prints-and-exits SUCCESS without scanning, so the
/// file just has to exist and be readable.
fn effective_config(extra_args: &[&str], target: &std::path::Path) -> String {
    let mut args: Vec<String> = vec![
        "config".to_string(),
        "--effective".to_string(),
        "--no-gpu".to_string(),
    ];
    args.extend(extra_args.iter().map(|s| s.to_string()));
    args.push(target.display().to_string());

    let out = Command::new(binary())
        .args(&args)
        .output()
        .expect("spawn keyhog");

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        stdout.contains("[effective-config]"),
        "expected the effective config block on stdout; \
         got stdout={stdout:?} stderr={:?} args={args:?}",
        String::from_utf8_lossy(&out.stderr),
    );
    stdout
}

/// Extract a single `key = value` scalar from the effective-config block and
/// parse it as f64. Panics with context if the key is missing or unparsable.
fn config_f64(block: &str, key: &str) -> f64 {
    for line in block.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(key) {
            // Match `key = value` exactly, not a prefix collision (e.g. the
            // `entropy_threshold` line vs the `entropy_enabled` line).
            if let Some(val) = rest.strip_prefix(" = ") {
                return val.trim().parse::<f64>().unwrap_or_else(|e| {
                    panic!("effective-config `{key}` value {val:?} not an f64: {e}")
                });
            }
        }
    }
    panic!("effective-config block has no `{key} = …` line:\n{block}");
}

/// Create a throwaway scan target inside the test's own temp dir.
fn scratch_file() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("f.txt");
    std::fs::write(&path, b"x = 1\n").expect("write scratch file");
    (dir, path)
}

/// AUD-insufficiency-1 — `--ml-weight 5.0` reaches the engine UN-CLAMPED.
///
/// FINDING: `ScannerConfig::sanitise` (scanner_config.rs:144-148) clamps
/// `ml_weight` to [0.0, 1.0], and `scan_postprocess.rs:405-413` documents that
/// the ML blend `w·ml + (1-w)·heuristic` relies on `w` being so clamped. But
/// `build_scanner_config` (orchestrator_config.rs:406-408) assigns
/// `config.ml_weight = weight` AFTER the `From`-time sanitise, and nothing
/// re-sanitises before the config is handed to the engine
/// (orchestrator/mod.rs:180 → compile.rs:254-258). With no clap value_parser on
/// `--ml-weight` (args/scan.rs:433-435), `--ml-weight 5.0` flows through whole.
///
/// EVIDENCE: the binary's own effective-config oracle reports `ml_weight = 5`.
/// EXPECTED FIX: re-sanitise after the override merge (or add a clamping
/// value_parser); then the resolved `ml_weight` is 1.0.
#[test]
fn ml_weight_above_one_is_clamped_to_one() {
    let (_dir, file) = scratch_file();
    let block = effective_config(&["--ml-weight", "5.0"], &file);
    let resolved = config_f64(&block, "ml_weight");
    assert!(
        resolved <= 1.0,
        "--ml-weight 5.0 must be clamped to the documented [0,1] range before \
         it reaches the engine (ScannerConfig::sanitise clamps to 1.0; the ML \
         blend in scan_postprocess.rs relies on it). Oracle reports \
         ml_weight = {resolved}, so the un-clamped value runs.\nblock:\n{block}"
    );
}

/// AUD-insufficiency-2 — `--ml-weight=-1.0` reaches the engine as a NEGATIVE
/// weight.
///
/// FINDING: same root cause as AUD-insufficiency-1. A negative ml_weight turns
/// the blend `w·ml + (1-w)·heuristic` into `-1·ml + 2·heuristic` — sanitise()
/// (scanner_config.rs:144-148) clamps negatives to 0.0 precisely to forbid
/// this. The override layer bypasses it.
///
/// EVIDENCE: effective-config oracle reports `ml_weight = -1`.
/// EXPECTED FIX: clamp on the override path; resolved `ml_weight` becomes 0.0.
#[test]
fn ml_weight_below_zero_is_clamped_to_zero() {
    let (_dir, file) = scratch_file();
    let block = effective_config(&["--ml-weight=-1.0"], &file);
    let resolved = config_f64(&block, "ml_weight");
    assert!(
        resolved >= 0.0,
        "--ml-weight=-1.0 must be clamped to the documented [0,1] range \
         (ScannerConfig::sanitise clamps to 0.0). A negative ML weight inverts \
         the confidence blend. Oracle reports ml_weight = {resolved}.\n\
         block:\n{block}"
    );
}

/// AUD-insufficiency-3 — `--entropy-threshold 99` reaches the engine
/// UN-CLAMPED.
///
/// FINDING: `ScannerConfig::sanitise` (scanner_config.rs:156-160) clamps
/// `entropy_threshold` to [0.0, 8.0] (8.0 is the upper bound for byte-level
/// Shannon entropy — a threshold above it can never be met, silently disabling
/// the entropy detector). `build_scanner_config` (orchestrator_config.rs:400-402)
/// assigns `config.entropy_threshold = threshold` after the `From`-time
/// sanitise; nothing re-clamps. `--entropy-threshold` has no clap value_parser
/// (args/scan.rs:397-398).
///
/// EVIDENCE: effective-config oracle reports `entropy_threshold = 99`.
/// EXPECTED FIX: re-sanitise after the override merge; resolved value ≤ 8.0.
#[test]
fn entropy_threshold_above_max_is_clamped_to_eight() {
    let (_dir, file) = scratch_file();
    let block = effective_config(&["--entropy-threshold", "99"], &file);
    let resolved = config_f64(&block, "entropy_threshold");
    assert!(
        resolved <= 8.0,
        "--entropy-threshold 99 must be clamped to the documented [0,8] range \
         (ScannerConfig::sanitise caps at 8.0; 8.0 is the max byte-level \
         Shannon entropy). A threshold above 8.0 can never fire, silently \
         disabling entropy detection. Oracle reports entropy_threshold = \
         {resolved}.\nblock:\n{block}"
    );
}

/// AUD-insufficiency-4 — `--entropy-threshold=-5` reaches the engine NEGATIVE.
///
/// FINDING: same root cause. A negative entropy threshold makes the entropy
/// gate `entropy >= threshold` ALWAYS true (Shannon entropy is always ≥ 0),
/// turning the entropy detector into a match-everything false-positive cannon.
/// `ScannerConfig::sanitise` (scanner_config.rs:156-157) resets negatives to
/// the 4.5 default for exactly this reason; the override path skips it.
///
/// EVIDENCE: effective-config oracle reports `entropy_threshold = -5`.
/// EXPECTED FIX: re-sanitise after the override merge; a negative input must
/// not survive as a negative threshold (sanitise resets it to 4.5, i.e. ≥ 0).
#[test]
fn entropy_threshold_below_zero_is_clamped_non_negative() {
    let (_dir, file) = scratch_file();
    let block = effective_config(&["--entropy-threshold=-5"], &file);
    let resolved = config_f64(&block, "entropy_threshold");
    assert!(
        resolved >= 0.0,
        "--entropy-threshold=-5 must be clamped to a non-negative value \
         (ScannerConfig::sanitise resets negatives to 4.5). A negative \
         threshold makes `entropy >= threshold` always true — every byte run \
         becomes a finding. Oracle reports entropy_threshold = {resolved}.\n\
         block:\n{block}"
    );
}
