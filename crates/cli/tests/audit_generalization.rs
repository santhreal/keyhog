//! Adversarial audit — VECTOR 6 GENERALIZATION (KEY: generalization)
//!
//! Finding: the generic-secret / generic-detector ENTROPY GATE is a hardcoded
//! magic constant, NOT derived from the operator-configurable Tier-A
//! `entropy_threshold` knob.
//!
//! keyhog documents `--entropy-threshold <BITS>` (and the `.keyhog.toml`
//! `entropy_threshold` field) as the lever that controls entropy-based
//! detection:
//!   * `crates/cli/src/config.rs:52` — "Entropy threshold in bits per byte
//!     (default: 4.5)."
//!   * `.keyhog.toml.example:74-78` — "Entropy threshold in bits per byte
//!     (default: 4.5) … 5.5: Conservative (fewer findings, fewer false
//!     positives)."
//!   * `crates/core/src/config.rs:22,114` — `entropy_threshold: 4.5`.
//!
//! That knob is carried into the engine as `ScannerConfig.entropy_threshold`
//! (`crates/scanner/src/scanner_config.rs:200`) and it DOES drive the
//! entropy-only scanner + confidence tiers
//! (`crates/scanner/src/confidence/mod.rs:60-76`,
//! `crates/scanner/src/entropy/scanner.rs:369`).
//!
//! But the GENERIC detector path uses two SEPARATE, DIVERGENT, HARDCODED floor
//! tables that never read `entropy_threshold`:
//!
//!   * `crates/scanner/src/engine/scan_filters.rs:184-202`
//!     `generic_entropy_floor(detector_id, credential_len)`:
//!         "generic-api-key"  len<=24 => 3.0
//!         "generic-api-key"  len<=40 => 2.8
//!         "generic-api-key"          => 3.5
//!         "generic-password"         => 2.5
//!         "generic-database-url"     => 2.0
//!         _                          => 3.5
//!     (consumed by `crates/scanner/src/engine/process.rs:136`).
//!
//!   * `crates/scanner/src/engine/fallback_generic.rs:165-171`
//!     (the `SECRET_NAME = "value"` -> `generic-secret` fallback):
//!         value.len() <= 24 => 2.8
//!         value.len() <= 40 => 3.2
//!         _                 => 3.5
//!
//! Two consequences, both VECTOR-6 violations ("hardcoded lists / magic
//! constants … hardcoded thresholds … replace hardcoding with data-driven
//! contracts"):
//!   (a) The same conceptual decision ("is this generic value high-entropy
//!       enough to report?") is encoded TWICE with DIFFERENT numbers
//!       (len<=24: 3.0 vs 2.8; len 25..=40: 2.8 vs 3.2) — one constant source
//!       is required, not two.
//!   (b) NEITHER table reads the operator's `entropy_threshold`. There is no
//!       Tier-A value or `.keyhog.toml` setting that can tighten (or loosen)
//!       the generic entropy gate; the threshold is baked into the binary.
//!
//! These black-box tests drive the freshly built `keyhog` binary
//! (`env!("CARGO_BIN_EXE_keyhog")`) and prove (b): cranking
//! `--entropy-threshold` from its 4.5 default up to (and past) the documented
//! maximum has ZERO effect on a moderate-entropy generic finding.
//!
//! Expected fix: route the generic entropy gate through the resolved
//! `ScannerConfig.entropy_threshold` (one Tier-A source of truth) instead of
//! the two hardcoded match tables — e.g. a single
//! `generic_entropy_floor(cfg.entropy_threshold, detector_id, len)` that scales
//! with the operator knob. After that fix, a value below the operator's
//! threshold is suppressed and these tests PASS.

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

    let output = Command::new(binary())
        .arg("scan")
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

fn generic_findings(findings: &[serde_json::Value]) -> Vec<String> {
    findings
        .iter()
        .filter_map(|f| f.get("detector_id").and_then(|v| v.as_str()))
        .filter(|id| id.starts_with("generic"))
        .map(|s| s.to_string())
        .collect()
}

/// The fixture below is `api_key = "<24-char mixed-case+digit value>"`.
/// The value `aAbBcCdDeEfFgGhH12345678` has Shannon entropy ~4.585 bits/byte
/// and is reported by the built-in `generic-secret` detector at the default
/// `--entropy-threshold 4.5`. This is a precondition for the two assertions
/// that follow — if this stops firing, the later tests are vacuous.
const GENERIC_FIXTURE: &str = "api_key = \"aAbBcCdDeEfFgGhH12345678\"\n";

/// AUD-generalization-1: raising `--entropy-threshold` from 4.5 to 6.0 must
/// change which entropy-gated findings survive, per the documented semantics
/// ("5.5: Conservative (fewer findings)"). It does NOT, because the
/// generic-secret entropy gate is the hardcoded
/// `fallback_generic.rs:165-171` table (2.8/3.2/3.5), which ignores
/// `entropy_threshold` entirely.
///
/// FAILS NOW: the finding is reported identically at 4.5 and at 6.0.
/// PASSES AFTER FIX: once the generic gate honors `entropy_threshold`, the
/// entropy-4.585 value falls below a 6.0 threshold and is suppressed, so the
/// generic finding count drops to 0 at 6.0 while remaining 1 at 4.5.
#[test]
fn entropy_threshold_knob_governs_generic_secret_gate() {
    // Default-threshold baseline: the generic-secret finding is present.
    let (base, base_code) = scan_json(GENERIC_FIXTURE, &["--entropy-threshold", "4.5"]);
    let base_generic = generic_findings(&base);
    assert_eq!(
        base_generic,
        vec!["generic-secret".to_string()],
        "precondition: at --entropy-threshold 4.5 the entropy-4.585 generic value \
         must be reported as `generic-secret` (got {base_generic:?}, exit {base_code:?})"
    );

    // Conservative threshold: per the documented knob semantics this should
    // suppress a value whose entropy (4.585) is below 6.0.
    let (tight, _tight_code) = scan_json(GENERIC_FIXTURE, &["--entropy-threshold", "6.0"]);
    let tight_generic = generic_findings(&tight);

    assert_eq!(
        tight_generic,
        Vec::<String>::new(),
        "VECTOR-6 GENERALIZATION DEFECT: the documented Tier-A `--entropy-threshold` \
         knob (config.rs:52, .keyhog.toml.example:74) does not govern the generic-secret \
         entropy gate. A value of entropy ~4.585 is still reported as `generic-secret` at \
         --entropy-threshold 6.0 because the gate uses the hardcoded floor table in \
         fallback_generic.rs:165-171 (2.8/3.2/3.5), not the resolved \
         ScannerConfig.entropy_threshold. Found: {tight_generic:?}"
    );
}

/// AUD-generalization-2 (boundary/extreme): set `--entropy-threshold` to 8.0,
/// the documented MAXIMUM ("bits per byte" — byte-level Shannon entropy is
/// bounded above by log2(256) = 8.0, and an ASCII token can never approach it).
/// At this setting NO realistic generic credential should pass an
/// entropy-driven gate. Yet `api_key = "<entropy 4.585>"` is still reported and
/// the process exits 1 (findings present).
///
/// This proves there is NO operator-reachable entropy setting that tightens the
/// generic gate — the threshold is hardcoded in the binary
/// (fallback_generic.rs:165-171 / scan_filters.rs:184-202), the textbook
/// Vector-6 "hardcoded threshold that should be data-driven / overridable"
/// defect.
///
/// FAILS NOW: finding reported + exit 1 at the documented max threshold.
/// PASSES AFTER FIX: once the generic gate honors `entropy_threshold`, an
/// 8.0 threshold suppresses every ASCII generic value, so this file scans
/// clean (no generic finding, exit 0).
#[test]
fn max_entropy_threshold_suppresses_generic_secret() {
    let (findings, code) = scan_json(GENERIC_FIXTURE, &["--entropy-threshold", "8.0"]);
    let generic = generic_findings(&findings);

    assert!(
        generic.is_empty(),
        "VECTOR-6 GENERALIZATION DEFECT: at --entropy-threshold 8.0 (the documented \
         maximum bits/byte, unreachable by any ASCII token) the generic-secret entropy \
         gate STILL reports a value of entropy ~4.585. The gate ignores the operator's \
         Tier-A entropy_threshold and uses a baked-in constant. Found generic findings: \
         {generic:?}"
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
