//! Regression: `--ml-threshold` must reach scan behavior (finding M21).
//!
//! `ScanArgs::ml_threshold` was parsed and range-validated but never read by
//! any non-test path: `build_scanner_config` set `ml_weight` but never
//! `ml_threshold`, so `keyhog scan --ml-threshold 0.9` produced identical
//! findings to `--ml-threshold 0.01` — a dead precision lever advertised in
//! `--help`, giving false confidence that the ML/entropy floor had been
//! raised.
//!
//! The fix wires `--ml-threshold` into the resolved confidence floor
//! (`ScannerConfig::min_confidence`) via `.max()` composition: a raised
//! threshold tightens the bar a generic/entropy finding must clear, a value at
//! or below the floor is a no-op, and an UNSET flag (value == the declared
//! default) leaves the canonical floor untouched so default behavior is
//! unchanged.
//!
//! These assertions exercise the public `keyhog::orchestrator_config`
//! surface (`build_scanner_config` / `render_effective_config`), which is the
//! exact config the live worker hands to `CompiledScanner::with_config`.

use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::orchestrator_config::{build_scanner_config, ML_THRESHOLD_DEFAULT};
use keyhog_scanner::ScannerConfig;

/// The canonical no-preset confidence floor, read from the engine's own
/// default rather than a hardcoded literal so this test tracks the single
/// source of truth (`ScanConfig::default().min_confidence`, currently 0.40).
fn canonical_floor() -> f64 {
    ScannerConfig::default().min_confidence
}

fn args(extra: &[&str]) -> ScanArgs {
    let mut argv = vec!["scan"];
    argv.extend_from_slice(extra);
    ScanArgs::try_parse_from(argv).expect("parse scan args")
}

#[test]
fn ml_threshold_unset_leaves_canonical_floor_untouched() {
    // No `--ml-threshold` on the command line: the field defaults to
    // ML_THRESHOLD_DEFAULT and must NOT silently raise the 0.40 floor.
    let cfg = build_scanner_config(&args(&[]));
    assert_eq!(
        cfg.min_confidence,
        canonical_floor(),
        "unset --ml-threshold must leave the canonical confidence floor untouched"
    );

    // Explicitly passing the default value is also a no-op.
    let cfg_default = build_scanner_config(&args(&["--ml-threshold", "0.5"]));
    assert_eq!(
        cfg_default.min_confidence,
        canonical_floor(),
        "--ml-threshold at its declared default must be a no-op"
    );
    // Guard the const/string-literal sync the wiring relies on.
    assert_eq!(ML_THRESHOLD_DEFAULT, 0.5);
}

#[test]
fn ml_threshold_above_floor_raises_confidence_floor() {
    // The pre-fix bug: this had no effect. Now it raises the floor to 0.9.
    let cfg = build_scanner_config(&args(&["--ml-threshold", "0.9"]));
    assert!(
        (cfg.min_confidence - 0.9).abs() < 1e-9,
        "--ml-threshold 0.9 must raise the confidence floor to 0.9, got {}",
        cfg.min_confidence
    );
    assert!(
        cfg.min_confidence > canonical_floor(),
        "a raised --ml-threshold must tighten the bar above the canonical floor"
    );
}

#[test]
fn ml_threshold_below_floor_cannot_lower_it() {
    // "minimum score" semantics: composed via `.max()`, so a threshold below
    // the resolved floor can never punch a hole in it.
    let cfg = build_scanner_config(&args(&["--ml-threshold", "0.1"]));
    assert_eq!(
        cfg.min_confidence,
        canonical_floor(),
        "--ml-threshold below the floor must not lower it"
    );
}

#[test]
fn ml_threshold_composes_with_min_confidence_taking_the_higher() {
    // Both knobs are floors; the higher wins. ml-threshold above min-confidence.
    let cfg = build_scanner_config(&args(&["--min-confidence", "0.7", "--ml-threshold", "0.9"]));
    assert!(
        (cfg.min_confidence - 0.9).abs() < 1e-9,
        "with --min-confidence 0.7 --ml-threshold 0.9 the higher floor (0.9) wins, got {}",
        cfg.min_confidence
    );

    // min-confidence above ml-threshold: min-confidence wins, ml-threshold no-op.
    let cfg2 = build_scanner_config(&args(&["--min-confidence", "0.8", "--ml-threshold", "0.6"]));
    assert!(
        (cfg2.min_confidence - 0.8).abs() < 1e-9,
        "with --min-confidence 0.8 --ml-threshold 0.6 the higher floor (0.8) wins, got {}",
        cfg2.min_confidence
    );
}

#[test]
fn ml_threshold_surfaces_through_effective_config_oracle() {
    // The hidden coherence oracle (`KEYHOG_PRINT_EFFECTIVE_CONFIG`) must report
    // the raised floor: "what runs" == "what the operator asked for". We build
    // the `ResolvedScanConfig` from `build_scanner_config` directly (mirroring
    // `resolve_scan_config`'s own `min_confidence = scanner.min_confidence`
    // step) so the assertion is independent of any `.keyhog.toml` the config
    // walk-up might find in a parent directory of the test's working dir.
    use keyhog::orchestrator_config::{render_effective_config, ResolvedScanConfig};

    let scanner = build_scanner_config(&args(&["--ml-threshold", "0.95"]));
    let min_confidence = scanner.min_confidence;
    let ml_enabled = scanner.ml_enabled;
    let resolved = ResolvedScanConfig {
        scanner,
        min_confidence,
        ml_enabled,
        detector_min_confidence: std::collections::HashMap::new(),
        disabled_detectors: std::collections::HashSet::new(),
        require_lockdown: false,
    };
    let rendered = render_effective_config(&resolved);
    assert!(
        rendered.contains("min_confidence = 0.95"),
        "effective-config dump must reflect the raised --ml-threshold floor; got:\n{rendered}"
    );
}
