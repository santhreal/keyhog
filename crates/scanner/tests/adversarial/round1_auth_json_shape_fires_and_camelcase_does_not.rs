//! Round 1 FN-recovery regression contract: generic-password regex must
//! fire on standalone `"auth": "<secret>"` JSON shapes (positive truth)
//! and must NOT fire on CamelCase type identifiers that pass through the
//! same value slot (adversarial negative twin).
//!
//! Investigator finding (generic-password causes #1 + #2):
//!   * Cause #1: the type-name shape gate (CamelCase identifier
//!     suppression) over-suppressed any mixed-case alphanumeric credential
//!     value whose body happened to contain >=2 uppercase letters. Real
//!     credentials with embedded UU runs (two consecutive uppercase
//!     letters) were dropped as if they were Java/Rust/C# type names.
//!     Fix: require zero UU pairs before treating as a type identifier.
//!   * Cause #2: the keyword regex only contained `auth_token` /
//!     `auth_key`, not standalone `auth`. JSON `"auth": "<secret>"` and
//!     YAML `auth: "<secret>"` were walked past.
//!
//! Adversarial style: paired truth/twin around the same line shape.
//!
//! Contract:
//!   * Positive truth: `"auth": "Y6NPMwS*rWGUv!JQnSG6a#D14"` in a .json
//!     file produces a generic-secret finding with that exact credential.
//!   * Adversarial twin: `auth_token=HVupsQnTMKFMuM199OtdO` (5 UU pairs
//!     H-V T-M M-K K-F F-M) must STILL fire as a finding (UU-pair check
//!     rescues this from the type-name gate).
//!   * Negative twin: `validator = AbcDefGhi` (CamelCase identifier, no
//!     UU pairs) must NOT fire.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScannerConfig};
use std::path::PathBuf;

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let mut cfg = ScannerConfig::default();
    cfg.min_confidence = 0.0;
    CompiledScanner::compile(detectors)
        .expect("compile")
        .with_config(cfg)
}

fn scan(body: &str, path: &str) -> Vec<keyhog_core::RawMatch> {
    let chunk = Chunk {
        data: body.to_string().into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    scanner().scan(&chunk)
}

#[test]
fn auth_json_shape_fires_truth_case() {
    let body = r#"{
  "service": "billing",
  "auth": "Y6NPMwS*rWGUv!JQnSG6a#D14"
}
"#;
    let matches = scan(body, "/repo/config/api.json");
    let found = matches
        .iter()
        .any(|m| m.credential.as_ref() == "Y6NPMwS*rWGUv!JQnSG6a#D14");
    assert!(
        found,
        "standalone \"auth\" JSON-key shape must surface the symbolic \
         password; all findings: {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn credential_with_uu_pairs_survives_type_name_gate() {
    // 21-char alphanumeric value with 5 consecutive uppercase pairs:
    // H-V, T-M, M-K, K-F, F-M. CamelCase type identifiers carry zero
    // UU pairs (the gate's signature). This is a real credential.
    let body = "auth_token=HVupsQnTMKFMuM199OtdO\nstatus=200\n";
    let matches = scan(body, "/repo/logs/access.log");
    let found = matches
        .iter()
        .any(|m| m.credential.as_ref() == "HVupsQnTMKFMuM199OtdO");
    assert!(
        found,
        "credential value with UU pairs must survive the type-name gate; \
         all findings: {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn camelcase_identifier_without_uu_pairs_does_not_fire() {
    // Pure CamelCase identifier - no UU pairs (each uppercase is
    // followed by lowercase). Real Java/Rust/C# type name shape.
    // Must remain suppressed.
    let body = "secret = AbcDefGhiJklMno\n";
    let matches = scan(body, "/repo/src/lib.rs");
    let hits: Vec<_> = matches
        .iter()
        .filter(|m| m.credential.as_ref() == "AbcDefGhiJklMno")
        .collect();
    assert!(
        hits.is_empty(),
        "pure CamelCase identifier (no UU pairs) must NOT fire as a \
         credential; got hits: {:?}",
        hits.iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
