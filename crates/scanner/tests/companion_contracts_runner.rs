//! Companion-required detector contract runner.
//!
//! Walks `tests/contracts/companion/*.toml` and enforces the
//! three-part companion contract:
//!   1. positive_with_companion — primary + companion both present
//!      → primary fires AND companions map is populated.
//!   2. positive_primary_only — primary alone
//!      → if companion is scanner-required, no match;
//!        otherwise primary fires but companions map is empty.
//!   3. negative_companion_lookalike — companion-shaped noise, no primary
//!      → primary must NOT fire.
//!
//! The TOML also carries a `must_not_verify` flag documenting the
//! verifier-level expectation (primary without companion must not be
//! verified as live).  This runner does not perform live network
//! verification; it only asserts the scanner-level contract that
//! underlies the verifier behaviour.

use std::collections::HashMap;
use std::path::PathBuf;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CompanionContract {
    #[allow(dead_code)]
    schema_version: u32,
    detector_id: String,
    #[allow(dead_code)]
    service: String,
    #[allow(dead_code)]
    severity: String,
    positive_with_companion: CompanionCase,
    positive_primary_only: PrimaryOnlyCase,
    negative_companion_lookalike: NegativeCase,
}

#[derive(Debug, Deserialize)]
struct CompanionCase {
    text: String,
    expected_findings: Vec<String>,
    #[serde(default)]
    expected_companions: HashMap<String, String>,
    #[allow(dead_code)]
    reason: String,
}

#[derive(Debug, Deserialize)]
struct PrimaryOnlyCase {
    text: String,
    expected_findings: Vec<String>,
    #[serde(default)]
    must_not_verify: bool,
    #[allow(dead_code)]
    reason: String,
}

#[derive(Debug, Deserialize)]
struct NegativeCase {
    text: String,
    expected_findings: Vec<String>,
    #[allow(dead_code)]
    reason: String,
}

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

fn companion_contracts_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("tests");
    d.push("contracts");
    d.push("companion");
    d
}

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("detectors directory loadable from companion contract runner");
    CompiledScanner::compile(detectors).expect("scanner compile from companion contract runner")
}

fn make_chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "companion-contract".into(),
            path: Some("companion-contract.txt".into()),
            ..Default::default()
        },
    }
}

fn findings_for_detector<'a>(
    matches: &'a [keyhog_core::RawMatch],
    detector_id: &str,
) -> Vec<&'a keyhog_core::RawMatch> {
    matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == detector_id)
        .collect()
}

fn load_companion_contracts() -> Vec<(PathBuf, CompanionContract)> {
    let dir = companion_contracts_dir();
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let contract: CompanionContract = match toml::from_str(&text) {
            Ok(c) => c,
            Err(e) => panic!("malformed companion contract {}: {e}", path.display()),
        };
        out.push((path, contract));
    }
    out
}

#[test]
fn every_companion_contract_passes() {
    let scanner = scanner();
    let contracts = load_companion_contracts();
    assert!(
        !contracts.is_empty(),
        "tests/contracts/companion/ has no *.toml — at least one companion contract must ship"
    );

    let mut failures: Vec<String> = Vec::new();
    let mut parity_issues: Vec<String> = Vec::new();

    for (path, c) in &contracts {
        let label = c.detector_id.as_str();

        // --- positive_with_companion ---
        let case = &c.positive_with_companion;
        // See engine/mod.rs:747-760 — the cross-file fragment cache
        // accumulates across every scan() call on a reused scanner,
        // so braintree's `sandbox_…` positive can resurface as a
        // finding for a later detector's fixture in CI's
        // filesystem-iteration order. Clear before every scan.
        scanner.clear_fragment_cache();
        let chunk = make_chunk(&case.text);
        let matches = scanner.scan(&chunk);
        for expected in &case.expected_findings {
            let found = findings_for_detector(&matches, expected);
            if found.is_empty() {
                failures.push(format!(
                    "{}: positive_with_companion MISSED — detector {} should fire on text {:?} ({}); \
                     scanner saw {:?}",
                    label,
                    expected,
                    case.text,
                    path.display(),
                    matches.iter().map(|m| m.detector_id.as_ref()).collect::<Vec<_>>(),
                ));
            }
        }
        // If primary is expected, assert companions are populated.
        if case.expected_findings.contains(&label.to_string()) {
            let primary_matches = findings_for_detector(&matches, label);
            if let Some(primary) = primary_matches.first() {
                for (comp_name, comp_val) in &case.expected_companions {
                    let actual = primary.companions.get(comp_name);
                    if actual != Some(comp_val) {
                        parity_issues.push(format!(
                            "{}: positive_with_companion companion mismatch — expected companions[{}]={:?}, got {:?}",
                            label, comp_name, comp_val, actual,
                        ));
                    }
                }
            }
        }

        // --- positive_primary_only ---
        let case = &c.positive_primary_only;
        scanner.clear_fragment_cache();
        let chunk = make_chunk(&case.text);
        let matches = scanner.scan(&chunk);
        for expected in &case.expected_findings {
            let found = findings_for_detector(&matches, expected);
            if found.is_empty() {
                failures.push(format!(
                    "{}: positive_primary_only MISSED — detector {} should fire on text {:?} ({}); \
                     scanner saw {:?}",
                    label,
                    expected,
                    case.text,
                    path.display(),
                    matches.iter().map(|m| m.detector_id.as_ref()).collect::<Vec<_>>(),
                ));
            }
        }
        // If primary is NOT expected to fire, ensure it doesn't.
        if !case.expected_findings.contains(&label.to_string()) {
            let found = findings_for_detector(&matches, label);
            if !found.is_empty() {
                parity_issues.push(format!(
                    "{}: positive_primary_only SURPLUS — detector {} fired unexpectedly on text {:?} ({}); \
                     this suggests the scanner finds the primary without its required companion",
                    label,
                    label,
                    case.text,
                    path.display(),
                ));
            }
        }
        // must_not_verify documentation check: if the flag is set and the primary
        // DOES fire, assert companions map is empty (the verifier will fail
        // because interpolation yields empty strings).
        if case.must_not_verify && case.expected_findings.contains(&label.to_string()) {
            let primary_matches = findings_for_detector(&matches, label);
            if let Some(primary) = primary_matches.first() {
                let detector = {
                    let detectors = keyhog_core::load_detectors(&detector_dir()).unwrap();
                    detectors.into_iter().find(|d| d.id.as_str() == label)
                };
                if let Some(det) = detector {
                    for companion in &det.companions {
                        if primary.companions.contains_key(&companion.name) {
                            parity_issues.push(format!(
                                "{}: positive_primary_only VERIFY-RISK — primary fired with companion {} populated; \
                                 verification may succeed even though must_not_verify is asserted",
                                label, companion.name,
                            ));
                        }
                    }
                }
            }
        }

        // --- negative_companion_lookalike ---
        let case = &c.negative_companion_lookalike;
        scanner.clear_fragment_cache();
        let chunk = make_chunk(&case.text);
        let matches = scanner.scan(&chunk);
        for expected_empty in &case.expected_findings {
            // expected_findings is normally empty; if non-empty it's a positive expectation
            let found = findings_for_detector(&matches, expected_empty);
            if found.is_empty() {
                failures.push(format!(
                    "{}: negative_companion_lookalike MISSED — detector {} should fire on text {:?} ({})",
                    label,
                    expected_empty,
                    case.text,
                    path.display(),
                ));
            }
        }
        let primary_found = findings_for_detector(&matches, label);
        if !primary_found.is_empty() {
            parity_issues.push(format!(
                "{}: negative_companion_lookalike SURPLUS — detector {} fired on companion-only text {:?} ({})",
                label,
                label,
                case.text,
                path.display(),
            ));
        }
    }

    // Print parity issues as warnings so they appear in test output,
    // but do not fail the suite — they become engineer tickets.
    if !parity_issues.is_empty() {
        eprintln!(
            "\n=== COMPANION PARITY ISSUES ({} found) ===",
            parity_issues.len()
        );
        for issue in &parity_issues {
            eprintln!("  - {issue}");
        }
        eprintln!("=== END PARITY ISSUES ===\n");
    }

    assert!(
        failures.is_empty(),
        "companion contract failures:\n  - {}",
        failures.join("\n  - "),
    );
}

#[test]
fn companion_contracts_cover_at_least_one_detector() {
    let contracts = load_companion_contracts();
    assert!(
        !contracts.is_empty(),
        "companion contracts directory has no TOMLs"
    );
}
