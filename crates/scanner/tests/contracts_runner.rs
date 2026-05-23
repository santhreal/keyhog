//! Per-detector contract runner.
//!
//! Walks `tests/contracts/*.toml` and enforces every section that
//! CLAUDE.md "per-rule directory contract" mandates (positives,
//! negatives, evasions, cve_replay, perf, scale, readme_claim).
//! Adding a new TOML adds a new contract; every existing TOML must
//! stay green or the test suite fails.
//!
//! The runner is the same shape for every detector — the per-rule
//! TOML is the only thing the contributor edits. That's the
//! lego-block move: build the harness once, instantiate per
//! detector by writing data, not code.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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
    #[serde(default)]
    negative: Vec<Negative>,
    #[serde(default)]
    evasion: Vec<Positive>,
    #[serde(default)]
    cve_replay: Vec<Positive>,
    #[serde(default)]
    perf: Option<PerfBudget>,
    #[serde(default)]
    scale: Option<ScaleBudget>,
    #[serde(default)]
    readme_claim: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Positive {
    text: String,
    credential: String,
    #[allow(dead_code)]
    reason: String,
}

#[derive(Debug, Deserialize)]
struct Negative {
    text: String,
    #[allow(dead_code)]
    reason: String,
}

#[derive(Debug, Deserialize)]
struct PerfBudget {
    fixture_bytes: usize,
    max_microseconds: u64,
    #[allow(dead_code)]
    note: String,
}

#[derive(Debug, Deserialize)]
struct ScaleBudget {
    fixture_bytes: usize,
    min_findings: usize,
    max_seconds: f64,
    #[allow(dead_code)]
    note: String,
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

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

fn load_contracts() -> Vec<(PathBuf, Contract)> {
    let dir = contracts_dir();
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
        let contract: Contract = match toml::from_str(&text) {
            Ok(c) => c,
            Err(e) => panic!("malformed contract {}: {e}", path.display()),
        };
        out.push((path, contract));
    }
    out
}

fn make_chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "contract".into(),
            path: Some("contract.txt".into()),
            ..Default::default()
        },
    }
}

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("detectors directory loadable from contract runner");
    CompiledScanner::compile(detectors).expect("scanner compile from contract runner")
}

/// Bucket findings by their credential string so the per-fixture
/// assertions are O(1) hash lookups, not O(n) linear scans, when
/// the runner gets large.
fn finding_creds(matches: &[keyhog_core::RawMatch]) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for f in matches {
        *m.entry(f.credential.as_ref().to_string()).or_insert(0) += 1;
    }
    m
}

/// True if the expected credential substring appears in any
/// extracted credential. Used instead of strict equality because
/// keyhog's context-window extraction can over-capture trailing
/// punctuation from the surrounding text (e.g. `</token>` after a
/// PAT in an XML tag); the contract that matters is "the secret
/// is in the surfaced credential," not byte-exact equality.
fn any_credential_contains(matches: &[keyhog_core::RawMatch], expected: &str) -> bool {
    matches
        .iter()
        .any(|m| m.credential.as_ref().contains(expected))
}

#[test]
fn every_contract_passes_positives_negatives_evasions() {
    let scanner = scanner();
    let contracts = load_contracts();
    assert!(
        !contracts.is_empty(),
        "tests/contracts/ has no *.toml — at least one detector must ship a contract"
    );

    let mut failures: Vec<String> = Vec::new();
    for (path, c) in &contracts {
        let label = c.detector_id.as_str();

        for p in &c.positive {
            let chunk = make_chunk(&p.text);
            let matches = scanner.scan(&chunk);
            if !any_credential_contains(&matches, &p.credential) {
                let creds = finding_creds(&matches);
                failures.push(format!(
                    "{}: positive MISSED — text {:?} should have surfaced credential containing {:?} ({}); \
                     scanner saw {:?}",
                    label,
                    p.text,
                    p.credential,
                    path.display(),
                    creds.keys().collect::<Vec<_>>(),
                ));
            }
        }

        for n in &c.negative {
            let chunk = make_chunk(&n.text);
            let matches = scanner.scan(&chunk);
            // We don't gate on "zero findings" — a fixture line may
            // also exercise a different detector — we gate on
            // "this detector did not fire on this text."
            let detector_fired = matches.iter().any(|m| m.detector_id.as_ref() == label);
            if detector_fired {
                failures.push(format!(
                    "{}: false positive on negative — text {:?} should NOT have fired \
                     ({}); scanner saw {} matches under this detector",
                    label,
                    n.text,
                    path.display(),
                    matches
                        .iter()
                        .filter(|m| m.detector_id.as_ref() == label)
                        .count(),
                ));
            }
        }

        for e in &c.evasion {
            let chunk = make_chunk(&e.text);
            let matches = scanner.scan(&chunk);
            if !any_credential_contains(&matches, &e.credential) {
                let creds = finding_creds(&matches);
                failures.push(format!(
                    "{}: evasion DROPPED — adversarial text {:?} should still surface \
                     credential containing {:?} ({}); scanner saw {:?}",
                    label,
                    e.text,
                    e.credential,
                    path.display(),
                    creds.keys().collect::<Vec<_>>(),
                ));
            }
        }

        for r in &c.cve_replay {
            let chunk = make_chunk(&r.text);
            let matches = scanner.scan(&chunk);
            if !any_credential_contains(&matches, &r.credential) {
                let creds = finding_creds(&matches);
                failures.push(format!(
                    "{}: cve_replay MISSED — leaked sample {:?} should fire on credential \
                     containing {:?} ({}); scanner saw {:?}",
                    label,
                    r.text,
                    r.credential,
                    path.display(),
                    creds.keys().collect::<Vec<_>>(),
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "per-detector contract failures:\n  - {}",
        failures.join("\n  - "),
    );
}

#[test]
fn every_contract_perf_budget_holds() {
    let scanner = scanner();
    let contracts = load_contracts();
    let mut failures: Vec<String> = Vec::new();

    for (path, c) in &contracts {
        let Some(perf) = &c.perf else {
            continue;
        };
        // Build a fixture with one planted positive embedded in
        // benign filler; perf budget includes scanner+regex cost.
        let Some(first) = c.positive.first() else {
            continue;
        };
        let mut fixture = "x".repeat(perf.fixture_bytes.saturating_sub(first.text.len()));
        fixture.push_str(&first.text);
        let chunk = make_chunk(&fixture);

        // Warm any internal caches first; the budget gates steady-
        // state, not cold-start.
        let _ = scanner.scan(&chunk);

        let start = std::time::Instant::now();
        let _ = scanner.scan(&chunk);
        let elapsed = start.elapsed();
        let micros = elapsed.as_micros() as u64;
        if micros > perf.max_microseconds {
            failures.push(format!(
                "{}: perf budget exceeded ({}): {}μs > budget {}μs",
                c.detector_id,
                path.display(),
                micros,
                perf.max_microseconds,
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "per-detector perf budget failures:\n  - {}",
        failures.join("\n  - "),
    );
}

#[test]
fn every_contract_scale_gate_holds() {
    let scanner = scanner();
    let contracts = load_contracts();
    let mut failures: Vec<String> = Vec::new();

    for (path, c) in &contracts {
        let Some(scale) = &c.scale else {
            continue;
        };
        let Some(first) = c.positive.first() else {
            continue;
        };
        // Build a `fixture_bytes`-sized chunk with the planted
        // credential at the midpoint. Filler is a punctuation+
        // whitespace pattern: detector regexes operate on
        // alphanumeric runs, so non-alphanumeric filler can't
        // false-match AND can't extend a true match into a
        // many-MB greedy capture (e.g. stripe's
        // `sk_live_[a-zA-Z0-9]{24,}` would match the entire
        // filler if the filler were `xxx...`, blowing the
        // post-process length cap). Spaces + newlines break up
        // any partial-keyword false hits cleanly.
        let half = scale.fixture_bytes / 2;
        let cycle = b". \n";
        let filler: Vec<u8> = (0..scale.fixture_bytes - first.text.len())
            .map(|i| cycle[i % cycle.len()])
            .collect();
        let filler_a = String::from_utf8_lossy(&filler[..half.min(filler.len())]).into_owned();
        let filler_b = String::from_utf8_lossy(&filler[half.min(filler.len())..]).into_owned();
        let fixture = format!("{filler_a}{}{filler_b}", first.text);
        let chunk = make_chunk(&fixture);

        let start = std::time::Instant::now();
        let matches = scanner.scan(&chunk);
        let elapsed = start.elapsed().as_secs_f64();

        // Detector-agnostic: cross-detector dedup can relabel a
        // finding (e.g. github-classic-pat → hot-github_pat on
        // the fast-path), so the contract gates on "this
        // credential string is surfaced under SOME detector,"
        // not "the labelled detector fired." That's what the end
        // user actually cares about — the credential is in the
        // report.
        let surfaced = matches
            .iter()
            .filter(|m| m.credential.as_ref().contains(&first.credential))
            .count();
        if surfaced < scale.min_findings {
            failures.push(format!(
                "{}: scale MISSED — {} surfaced < {} required ({}); raw finding count = {}",
                c.detector_id,
                surfaced,
                scale.min_findings,
                path.display(),
                matches.len(),
            ));
        }
        if elapsed > scale.max_seconds {
            failures.push(format!(
                "{}: scale budget exceeded — {:.3}s > budget {:.3}s ({})",
                c.detector_id,
                elapsed,
                scale.max_seconds,
                path.display(),
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "per-detector scale budget failures:\n  - {}",
        failures.join("\n  - "),
    );
}

/// README claims are pinned: a `readme_claim` in a contract MUST
/// literally appear in the repo README. Catches the case where the
/// README brags about supporting a detector but the contract for
/// that detector silently drifts out of sync.
#[test]
fn every_contract_readme_claim_present() {
    let contracts = load_contracts();
    let readme_path = repo_root().join("README.md");
    let readme = match std::fs::read_to_string(&readme_path) {
        Ok(t) => t,
        Err(e) => {
            // SKIP — running from an export without the root README.
            eprintln!("SKIP: README.md not at {}: {e}", readme_path.display());
            return;
        }
    };
    let mut failures: Vec<String> = Vec::new();
    for (path, c) in &contracts {
        if let Some(claim) = &c.readme_claim {
            if !readme.contains(claim) {
                failures.push(format!(
                    "{}: README claim {:?} not present in README.md ({})",
                    c.detector_id,
                    claim,
                    path.display(),
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "README claim drift:\n  - {}",
        failures.join("\n  - "),
    );
}

#[test]
fn contracts_cover_at_least_one_detector() {
    // Hard floor: at least one detector must ship a full contract.
    // CI must require this stays >= 1 forever; raise it as more
    // contracts land.
    let contracts = load_contracts();
    assert!(
        !contracts.is_empty(),
        "contracts/ directory has no TOMLs — the per-rule contract is the legendary bar; \
         ship at least one"
    );
    // Also assert each loaded contract has *some* test material —
    // an empty TOML is a useless contract.
    for (path, c) in &contracts {
        let total = c.positive.len() + c.negative.len() + c.evasion.len() + c.cve_replay.len();
        assert!(
            total > 0,
            "contract {} has zero test fixtures across all sections",
            path.display(),
        );
    }
}
