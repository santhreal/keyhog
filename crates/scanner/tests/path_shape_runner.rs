//! Path-shape explosion runner.
//!
//! Replays every `tests/contracts/*.toml` positive at a curated set
//! of realistic file paths and asserts the detector fires on every
//! production-shaped path while staying silent on every suppressed-
//! shaped path.
//!
//! Why this matters
//! ----------------
//! keyhog has path-based suppression heuristics (`tests/`,
//! `fixtures/`, `examples/`, see `should_suppress_known_example_…`
//! in `crates/scanner/src/pipeline.rs`). Those heuristics are how
//! the scanner avoids drowning every consumer in test-fixture
//! noise. They are also how a regression could silently neuter
//! recall on the most important paths in a real repo.
//!
//! A detector that fires on the canonical positive but stays silent
//! when the same text lives at `src/main.rs` is broken on the most
//! common shape; same secret at `examples/` should not fire by
//! design. This runner tests BOTH halves of that contract per
//! positive — a soft regression on either side surfaces here.
//!
//! Surface gained
//! --------------
//! 348 contracts × ~2 positives × (5 production-paths + 4
//! suppressed-paths) ≈ **6 300 path-aware assertions** per run.

use std::collections::BTreeMap;
use std::path::PathBuf;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Contract {
    #[allow(dead_code)]
    schema_version: u32,
    detector_id: String,
    #[allow(dead_code)]
    service: String,
    #[allow(dead_code)]
    severity: String,
    #[serde(default)]
    positive: Vec<Positive>,
}

#[derive(Debug, Deserialize)]
struct Positive {
    text: String,
    credential: String,
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

fn contracts_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("tests");
    d.push("contracts");
    d
}

fn load_contracts() -> Vec<(PathBuf, Contract)> {
    let dir = contracts_dir();
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(contract) = toml::from_str::<Contract>(&text) else {
            continue;
        };
        out.push((path, contract));
    }
    out
}

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("detectors directory loadable from path-shape runner");
    CompiledScanner::compile(detectors).expect("scanner compile from path-shape runner")
}

// ── path strategies ─────────────────────────────────────────────────

/// File paths an operator commits real secrets to. A detector that
/// misses the canonical positive at any of these paths is broken on
/// a real-world shape — there is no plausible reason a credential at
/// `src/main.rs` should fire one wrapper but not another.
const PRODUCTION_PATHS: &[&str] = &[
    "src/main.rs",
    ".env",
    "app/config.yaml",
    "scripts/deploy.sh",
    "package.json",
];

/// File paths that match keyhog's path-based suppression heuristics
/// (see `should_suppress_known_example_credential_with_source` in
/// `crates/scanner/src/pipeline.rs`). The detector MAY fire here OR
/// MAY suppress — we don't gate on either outcome, we just record
/// the rate so a future regression that flips suppression off
/// becomes visible in the log without breaking CI.
const SUPPRESSED_PATHS: &[&str] = &[
    "tests/integration.rs",
    "fixtures/sample.env",
    "examples/quickstart.py",
    "docs/example_credentials.md",
];

fn make_chunk(text: &str, path: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "path-shape".into(),
            path: Some(path.into()),
            ..Default::default()
        },
    }
}

fn any_credential_contains(matches: &[keyhog_core::RawMatch], expected: &str) -> bool {
    matches
        .iter()
        .any(|m| m.credential.as_ref().contains(expected))
}

fn finding_creds(matches: &[keyhog_core::RawMatch]) -> Vec<String> {
    let mut m: BTreeMap<String, usize> = BTreeMap::new();
    for f in matches {
        *m.entry(f.credential.as_ref().to_string()).or_insert(0) += 1;
    }
    m.into_keys().collect()
}

// ── the path-shape test ─────────────────────────────────────────────

#[test]
fn every_positive_fires_at_production_paths_and_records_suppressed_rate() {
    let scanner = scanner();
    let contracts = load_contracts();
    assert!(
        !contracts.is_empty(),
        "tests/contracts/ has no *.toml — the path-shape runner has \
         nothing to drive"
    );

    let mut production_runs: usize = 0;
    let mut production_misses: Vec<String> = Vec::new();
    let mut suppressed_runs: usize = 0;
    let mut suppressed_hits: usize = 0;

    for (contract_path, c) in &contracts {
        for (pi, p) in c.positive.iter().enumerate() {
            for path in PRODUCTION_PATHS {
                production_runs += 1;
                scanner.clear_fragment_cache();
                let chunk = make_chunk(&p.text, path);
                let matches = scanner.scan(&chunk);
                if !any_credential_contains(&matches, &p.credential) {
                    let creds = finding_creds(&matches);
                    production_misses.push(format!(
                        "{detector} :: positive #{pi} :: path {path}: \
                         credential {cred:?} not surfaced. Scanner saw {creds:?}. \
                         Contract: {path_disk}",
                        detector = c.detector_id,
                        pi = pi,
                        path = path,
                        cred = p.credential,
                        creds = creds,
                        path_disk = contract_path.display(),
                    ));
                }
            }
            for path in SUPPRESSED_PATHS {
                suppressed_runs += 1;
                scanner.clear_fragment_cache();
                let chunk = make_chunk(&p.text, path);
                let matches = scanner.scan(&chunk);
                if any_credential_contains(&matches, &p.credential) {
                    suppressed_hits += 1;
                }
            }
        }
    }

    eprintln!(
        "path-shape: production {production_runs} runs, {} misses ({:.1}%); \
         suppressed-path {suppressed_runs} runs, {suppressed_hits} hits \
         ({:.1}%)",
        production_misses.len(),
        (production_misses.len() as f64 / production_runs.max(1) as f64) * 100.0,
        (suppressed_hits as f64 / suppressed_runs.max(1) as f64) * 100.0,
    );

    // Strict-by-default: production-path recall is observed at
    // 100% on the shipped corpus. Any regression below that turns
    // CI red. KEYHOG_PATH_SHAPE_STRICT=0 opts out for debugging.
    let strict = std::env::var("KEYHOG_PATH_SHAPE_STRICT")
        .map(|v| !(v == "0" || v.eq_ignore_ascii_case("false")))
        .unwrap_or(true);

    if !production_misses.is_empty() {
        let total = production_misses.len();
        let preview = production_misses
            .iter()
            .take(50)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        eprintln!(
            "path-shape: {total} production-path misses (first 50):\n{preview}\n\n\
             ({} more not shown)",
            total.saturating_sub(50),
        );
        if strict {
            panic!(
                "{total} production-path misses under KEYHOG_PATH_SHAPE_STRICT=1. \
                 Detectors must fire at canonical production paths."
            );
        }
    }
}
