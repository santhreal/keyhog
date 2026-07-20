//! Adversarial audit: VECTOR 6 GENERALIZATION (KEY: generalization)
//!
//! Finding: the keyword-anchored entropy gate is a hardcoded magic constant,
//! NOT derived from the operator-configurable Tier-A
//! `entropy_threshold` knob.
//!
//! keyhog documents `--entropy-threshold <BITS>` (and the `.keyhog.toml`
//! `entropy_threshold` field) as the lever that controls entropy-based
//! detection:
//!   * `crates/cli/src/config.rs:52`: "Entropy threshold in bits per byte
//!     (default: 4.5)."
//!   * `.keyhog.toml.example:74-78`: "Entropy threshold in bits per byte
//!     (default: 4.5) … 5.5: Conservative (fewer findings, fewer false
//!     positives)."
//!   * `crates/core/src/config.rs:22,114`: `entropy_threshold: 4.5`.
//!
//! That knob is carried into the engine as `ScannerConfig.entropy_threshold`
//! (`crates/scanner/src/scanner_config.rs:200`) and it DOES drive the
//! entropy-only scanner + confidence tiers
//! (`crates/scanner/src/confidence/mod.rs:60-76`,
//! `crates/scanner/src/entropy/scanner.rs:369`).
//!
//! The generic-detector path now routes through one threshold-aware owner, but
//! the keyword-anchored entropy detector path still had a separate clamp that
//! erased conservative thresholds:
//!
//!   * `crates/scanner/src/entropy/scanner.rs::keyword_context` used
//!     `entropy_threshold.min(LOW_ENTROPY_THRESHOLD)`, so `6.0` and `8.0`
//!     both collapsed to the 3.0 keyword-context floor.
//!
//!   * `crates/scanner/src/engine/scan_filters.rs::generic_entropy_floor`
//!     remains the generic-detector owner for `generic-*` and `generic-secret`.
//!
//! Two consequences, both VECTOR-6 violations ("hardcoded lists / magic
//! constants … hardcoded thresholds … replace hardcoding with data-driven
//! contracts"):
//! There was no Tier-A value or `.keyhog.toml` setting that could tighten the
//! keyword-anchored entropy detector; the threshold was baked into the binary.
//!
//! These black-box tests drive the freshly built `keyhog` binary
//! (`env!("CARGO_BIN_EXE_keyhog")`) and prove (b): cranking
//! `--entropy-threshold` from its 4.5 default up to (and past) the documented
//! maximum has an operator-visible effect on a moderate-entropy keyword-anchored
//! finding.
//!
//! Expected fix: route the generic entropy gate through the resolved
//! `ScannerConfig.entropy_threshold` (one Tier-A source of truth). These tests
//! keep that contract live by pinning a diagnostic backend and proving that a
//! value below the operator's threshold is suppressed.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Write `content` to a neutrally named temp file and scan it with the given
/// extra args + `--format json`. Returns (parsed findings, exit code).
fn scan_json(content: &str, extra_args: &[&str]) -> (Vec<serde_json::Value>, Option<i32>) {
    let dir = TempDir::new().expect("tempdir");
    // Neutral filename: avoid tripping the test-fixture / example path
    // suppression heuristics so the entropy gate is what decides the outcome.
    let path = dir.path().join("settings_block.conf");
    std::fs::write(&path, content).expect("write fixture");
    // Isolate the generic entropy owner from the stronger structural API-key
    // detector that would otherwise win cross-detector resolution.
    std::fs::write(
        dir.path().join(".keyhog.toml"),
        "[detector.generic-api-key]\nenabled = false\n",
    )
    .expect("write detector isolation config");

    let output = Command::new(binary())
        .arg("scan")
        .args(["--backend", "simd"])
        .args(extra_args)
        .arg("--format")
        .arg("json")
        .arg(&path)
        .output()
        .expect("spawn keyhog scan");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let findings: Vec<serde_json::Value> = if stdout.trim().is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!("keyhog --format json did not emit a JSON array: {e}\nstdout was:\n{stdout}")
        })
    };
    (findings, output.status.code())
}

fn entropy_findings(findings: &[serde_json::Value]) -> Vec<String> {
    findings
        .iter()
        .filter_map(|f| f.get("detector_id").and_then(|v| v.as_str()))
        .filter(|id| *id == "generic-keyword-secret")
        .map(|s| s.to_string())
        .collect()
}

/// The fixture below is `api_key = "<24-char mixed-case+digit value>"`.
/// The value `aAbBcCdDeEfFgGhH12345678` has Shannon entropy ~4.585 bits/byte
/// and is reported by the built-in `generic-keyword-secret` entropy gate at
/// `--entropy-threshold 4.5`. The isolation config above keeps the stronger
/// structural detector from making this threshold contract vacuous.
const GENERIC_FIXTURE: &str = "api_key = \"aAbBcCdDeEfFgGhH12345678\"\n";

/// AUD-generalization-1: raising `--entropy-threshold` from 4.5 to 6.0 must
/// change which entropy-gated findings survive, per the documented semantics
/// ("5.5: Conservative (fewer findings)").
///
/// The entropy-4.585 value falls below a 6.0 threshold and is suppressed, so
/// the generic finding count drops to 0 at 6.0 while remaining 1 at 4.5.
#[test]
fn entropy_threshold_knob_governs_keyword_entropy_gate() {
    // Default-threshold baseline: the entropy finding is present.
    let (base, base_code) = scan_json(GENERIC_FIXTURE, &["--entropy-threshold", "4.5"]);
    let base_entropy = entropy_findings(&base);
    assert_eq!(
        base_entropy,
        vec!["generic-keyword-secret".to_string()],
        "precondition: at --entropy-threshold 4.5 the entropy-4.585 generic value \
         must be reported by the keyword entropy gate (got {base_entropy:?}, exit {base_code:?})"
    );

    // Conservative threshold: per the documented knob semantics this should
    // suppress a value whose entropy (4.585) is below 6.0.
    let (tight, _tight_code) = scan_json(GENERIC_FIXTURE, &["--entropy-threshold", "6.0"]);
    let tight_entropy = entropy_findings(&tight);

    assert_eq!(
        tight_entropy,
        Vec::<String>::new(),
        "VECTOR-6 GENERALIZATION DEFECT: the documented Tier-A `--entropy-threshold` \
         knob (config.rs:52, .keyhog.toml.example:74) does not govern the keyword-anchored \
         generic entropy gate. A value of entropy ~4.585 is still reported at \
         --entropy-threshold 6.0. Found: {tight_entropy:?}"
    );
}

/// AUD-generalization-2 (boundary/extreme): set `--entropy-threshold` to 8.0,
/// the documented MAXIMUM ("bits per byte", byte-level Shannon entropy is
/// bounded above by log2(256) = 8.0, and an ASCII token can never approach it).
/// At this setting NO realistic entropy-gated credential should pass an
/// entropy-driven gate. Yet `api_key = "<entropy 4.585>"` is still reported and
/// the process exits 1 (findings present).
///
/// This proves there is NO operator-reachable entropy setting that tightens the
/// keyword-anchored entropy gate, the textbook Vector-6 "hardcoded threshold
/// that should be data-driven / overridable" defect.
///
/// At threshold 8.0 every ASCII generic value is suppressed, so this file scans
/// clean (no generic finding, exit 0).
#[test]
fn max_entropy_threshold_suppresses_keyword_entropy() {
    let (findings, code) = scan_json(GENERIC_FIXTURE, &["--entropy-threshold", "8.0"]);
    let entropy = entropy_findings(&findings);

    assert!(
        entropy.is_empty(),
        "VECTOR-6 GENERALIZATION DEFECT: at --entropy-threshold 8.0 (the documented \
         maximum bits/byte, unreachable by any ASCII token) the keyword-anchored entropy \
         gate STILL reports a value of entropy ~4.585. The gate ignores the operator's \
         Tier-A entropy_threshold and uses a baked-in constant. Found entropy findings: \
         {entropy:?}"
    );

    // Exit-code corollary: with the generic gate properly threshold-aware, the
    // only finding in this fixture is suppressed at 8.0, so keyhog should exit
    // 0 (clean) rather than 1 (unverified findings present).
    assert_eq!(
        code,
        Some(0),
        "VECTOR-6 GENERALIZATION DEFECT: keyhog exits {code:?} (findings present) when \
         scanning a lone moderate-entropy generic secret at --entropy-threshold 8.0; a \
         threshold-aware generic gate would suppress it and exit 0 (clean)."
    );
}
