//! Shared harness for the **capability target-spec** suite.
//!
//! TESTING DOCTRINE (CLAUDE.md Law 6 / Law 9): these are TARGET-SPEC tests, not
//! regression tests. They assert the capability keyhog SHOULD have for EVERY
//! detector — that a detector fires not only on its single canonical contract
//! example but on a *realistic variant* of that same credential (a rotated key,
//! the same token surrounded by code, dropped into an env/yaml/json config, or
//! wrapped in quotes/whitespace). A detector that only matches its one hand-
//! tuned fixture is decoration; a detector that matches the credential in the
//! contexts real leaks live in is real coverage.
//!
//! Many of these WILL FAIL today — each failure is a tracked recall gap for a
//! narrow detector, NOT a bug in the test. They MUST stay visibly red until the
//! detector's regex/keyword set is widened to cover the variant. NEVER weaken a
//! variant to make the count go green (Law 9).
//!
//! The canonical credential per detector comes from the on-disk contract corpus
//! (`tests/contracts/<id>.toml`, first `[[positive]]`), the single shared source
//! of truth already used by every transform runner — we do not re-synthesize
//! token shapes here. The variant builders embed that exact credential string in
//! a new surrounding context and assert the credential SURFACES (substring of a
//! surfaced match's credential) under the REAL `CompiledScanner::scan` path.
//!
//! Recall is isolated from the confidence-floor gate the same way the
//! established `tests/gap/detector_recall_prefixes.rs` harness does it:
//! `min_confidence = 0.0`, `unicode_normalization = true`. This does NOT bypass
//! the pre-scoring checksum DROP (engine/process.rs) — a checksum-shaped token
//! whose embedded CRC is invalid still vanishes, which is correct. We therefore
//! drive the credential bytes the CONTRACT already proved valid, so any
//! disappearance is a context-sensitivity hole, never a checksum artifact.

#![allow(dead_code)] // each test binary uses a subset of these helpers.

use std::path::PathBuf;
use std::sync::OnceLock;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScannerConfig};
use serde::Deserialize;

// Single owner of the detector-dir path: `support.rs` re-mounts
// `../support/paths.rs`, the tree-wide canonical `detector_dir()`.
mod support;
pub use support::paths::detector_dir;

/// Absolute path to `tests/contracts/` (the canonical positive corpus).
pub fn contracts_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("tests");
    d.push("contracts");
    d
}

/// One per-detector contract file (the subset of fields the capability suite
/// needs: id + canonical positives).
#[derive(Debug, Deserialize)]
pub struct Contract {
    pub detector_id: String,
    #[serde(default)]
    pub positive: Vec<Positive>,
}

#[derive(Debug, Deserialize)]
pub struct Positive {
    pub text: String,
    pub credential: String,
    #[serde(default)]
    pub reason: String,
}

/// The canonical (detector_id, credential) pair the capability variants build
/// from. `text` is the contract's own minimal positive context, kept so a base
/// sanity assertion can confirm the credential fires in SOME context before we
/// blame a variant.
#[derive(Debug, Clone)]
pub struct Canonical {
    pub detector_id: String,
    pub credential: String,
    pub canonical_text: String,
}

/// Load every `tests/contracts/*.toml` (NOT the `companion/` subtree — those are
/// companion-gated fixtures with a different schema). Fails LOUDLY on a read or
/// parse error: a malformed contract is a finding, never a silent skip (Law 10).
pub fn load_canonicals() -> Vec<Canonical> {
    let dir = contracts_dir();
    let mut out = Vec::new();
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read tests/contracts dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("contracts dir entry readable").path();
        // Skip the companion/ subdir and any non-toml file.
        if path.is_dir() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read contract {}: {e}", path.display()));
        let contract = toml::from_str::<Contract>(&text)
            .unwrap_or_else(|e| panic!("parse contract {}: {e}", path.display()));
        if let Some(pos) = contract.positive.first() {
            out.push(Canonical {
                detector_id: contract.detector_id,
                credential: pos.credential.clone(),
                canonical_text: pos.text.clone(),
            });
        }
    }
    assert!(
        !out.is_empty(),
        "tests/contracts/ yielded no canonical positives — the capability suite has nothing to drive"
    );
    out.sort_by(|a, b| a.detector_id.cmp(&b.detector_id));
    out
}

/// The shared scanner: real on-disk detector set, compiled once. Recall-isolated
/// config (min_confidence 0.0, unicode normalization on) — see module docs.
pub fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors/ must load");
        let mut config = ScannerConfig::default();
        config.unicode_normalization = true;
        config.min_confidence = 0.0;
        // Variants land tokens in `.env` / `.yaml` / `config.json` style paths;
        // keep test-path suppression OFF so a config-context variant isn't
        // dropped as a "fixture" — we are measuring the regex/keyword reach,
        // not the suppression heuristic.
        config.penalize_test_paths = false;
        CompiledScanner::compile(detectors)
            .expect("on-disk corpus must compile into one scanner")
            .with_config(config)
    })
}

/// Scan one text body under a given logical path; clears the cross-file fragment
/// cache first so variant cases never leak reassembly state into each other.
pub fn scan(text: &str, path: &str) -> Vec<RawMatch> {
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "capability-target-spec".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    scanner().clear_fragment_cache();
    scanner().scan(&chunk)
}

/// True iff some surfaced match's credential CONTAINS `credential`. Substring
/// (not equality) because the engine legitimately widens the captured span for
/// some detectors (prefix + body), and dedup-cross-detector may relabel — but
/// the planted bytes must appear in SOME surfaced credential.
pub fn surfaces(matches: &[RawMatch], credential: &str) -> bool {
    matches
        .iter()
        .any(|m| m.credential.as_ref().contains(credential))
}

/// True iff some surfaced match's credential contains `credential` AND is
/// attributed to `detector_id`. Stronger than [`surfaces`]: proves the RIGHT
/// detector saw it, not merely a generic high-entropy fallback.
pub fn surfaces_as(matches: &[RawMatch], credential: &str, detector_id: &str) -> bool {
    matches.iter().any(|m| {
        m.detector_id.as_ref() == detector_id && m.credential.as_ref().contains(credential)
    })
}

/// The subset of canonicals whose credential is **credential-sufficient**: it
/// surfaces from its OWN bytes alone, with no surrounding context. Only these
/// can be context-varied all-or-nothing — a detector that NEEDS a `key=` anchor
/// next to its value (a bare UUID, a low-entropy generic body) legitimately
/// depends on context a variant may perturb, so those are reported but not
/// gated by the context-variant lane. This mirrors the soundness partition in
/// `tests/support/contracts.rs::credential_sufficient`.
pub fn sufficient_canonicals(all: &[Canonical]) -> Vec<Canonical> {
    all.iter()
        .filter(|c| {
            let m = scan(&c.credential, "sufficiency-probe.txt");
            surfaces(&m, &c.credential)
        })
        .cloned()
        .collect()
}

/// Format a bounded failure list for an assertion message.
pub fn join_capped(failures: &[String], cap: usize) -> String {
    if failures.len() <= cap {
        failures.join("\n  - ")
    } else {
        let head = failures[..cap].join("\n  - ");
        format!("{head}\n  - … and {} more", failures.len() - cap)
    }
}
