//! Per-detector hostile near-miss twins driven from `tests/contracts/*.toml`
//! (KH-GAP-128). Every loaded detector gets at least one near-miss oracle:
//! contract [[negative]] rows when present, otherwise a programmatic twin
//! derived from the canonical positive. Each twin is also split across a
//! chunk boundary to exercise reassembly without false positives.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Contract {
    detector_id: String,
    #[serde(default)]
    positive: Vec<Positive>,
    #[serde(default)]
    negative: Vec<Negative>,
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

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

fn contracts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("contracts")
}

fn load_contracts() -> Vec<(PathBuf, Contract)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(contracts_dir()) else {
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
        let contract: Contract = toml::from_str(&text)
            .unwrap_or_else(|e| panic!("malformed contract {}: {e}", path.display()));
        out.push((path, contract));
    }
    out
}

fn make_chunk(text: &str, path: &str, base_offset: usize) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "hostile-near-miss".into(),
            path: Some(path.into()),
            base_offset,
            ..Default::default()
        },
    }
}

fn synthesize_near_miss(positive: &Positive) -> String {
    if positive.credential.len() > 4 {
        let truncated = &positive.credential[..positive.credential.len() - 1];
        return positive.text.replace(&positive.credential, truncated);
    }
    format!("{} near_miss_suffix", positive.text)
}

fn chunk_boundary_twins(text: &str, path: &str) -> Vec<Vec<Chunk>> {
    // Place the full near-miss after a large pad chunk so boundary
    // reassembly must not fabricate a finding from the seam alone.
    let pad = "z\n".repeat(4096);
    let len_a = pad.len();
    vec![vec![
        make_chunk(&pad, path, 0),
        make_chunk(text, path, len_a),
    ]]
}

fn detector_fired(matches: &[keyhog_core::RawMatch], detector_id: &str) -> bool {
    matches.iter().any(|m| m.detector_id.as_ref() == detector_id)
}

#[test]
fn every_detector_has_hostile_near_miss_twin() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors.clone()).expect("compile scanner");
    let contracts = load_contracts();

    let contract_ids: BTreeSet<String> = contracts
        .iter()
        .map(|(_, c)| c.detector_id.clone())
        .collect();
    let loaded_ids: BTreeSet<String> = detectors.iter().map(|d| d.id.to_string()).collect();
    assert_eq!(
        contract_ids, loaded_ids,
        "contract corpus must cover every loaded detector id before near-miss twins run"
    );

    let mut covered: BTreeSet<String> = BTreeSet::new();
    let mut failures: Vec<String> = Vec::new();

    for (path, contract) in &contracts {
        let label = contract.detector_id.as_str();
        let near_miss_texts: Vec<String> = if contract.negative.is_empty() {
            let Some(first) = contract.positive.first() else {
                failures.push(format!(
                    "{label}: no [[negative]] and no [[positive]] to synthesize near-miss ({})",
                    path.display()
                ));
                continue;
            };
            vec![synthesize_near_miss(first)]
        } else {
            contract.negative.iter().map(|n| n.text.clone()).collect()
        };

        for text in near_miss_texts {
            covered.insert(label.to_string());

            scanner.clear_fragment_cache();
            let single = make_chunk(&text, &format!("{label}-near-miss.txt"), 0);
            let matches = scanner.scan(&single);
            if detector_fired(&matches, label) {
                let captured: Vec<_> = matches
                    .iter()
                    .filter(|m| m.detector_id.as_ref() == label)
                    .map(|m| m.credential.as_ref())
                    .collect();
                failures.push(format!(
                    "{label}: near-miss fired on single chunk — text {:?} ({}) captured {:?}",
                    text,
                    path.display(),
                    captured
                ));
            }

            for (split_idx, chunks) in chunk_boundary_twins(&text, &format!("{label}-split.txt"))
                .into_iter()
                .enumerate()
            {
                scanner.clear_fragment_cache();
                let results = scanner.scan_coalesced(&chunks);
                let flat: Vec<_> = results.into_iter().flatten().collect();
                if detector_fired(&flat, label) {
                    let captured: Vec<_> = flat
                        .iter()
                        .filter(|m| m.detector_id.as_ref() == label)
                        .map(|m| m.credential.as_ref())
                        .collect();
                    failures.push(format!(
                        "{label}: near-miss fired across chunk boundary (split {split_idx}) — text {:?} ({}) captured {:?}",
                        text,
                        path.display(),
                        captured
                    ));
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "per-detector hostile near-miss failures (first {}):\n  - {}",
        failures.len(),
        failures.iter().take(20).cloned().collect::<Vec<_>>().join("\n  - ")
    );

    assert!(
        covered.len() >= loaded_ids.len(),
        "near-miss coverage floor missed: {}/{} detectors covered",
        covered.len(),
        loaded_ids.len()
    );

    let uncovered: Vec<_> = loaded_ids.difference(&covered).collect();
    assert!(
        uncovered.is_empty(),
        "detectors without near-miss twins: {:?}",
        uncovered.iter().take(20).collect::<Vec<_>>()
    );
}

#[test]
fn near_miss_contract_row_floor_meets_detector_count() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let contracts = load_contracts();
    let rows: BTreeMap<String, usize> = contracts.iter().fold(BTreeMap::new(), |mut acc, (_, c)| {
        let count = if c.negative.is_empty() {
            usize::from(!c.positive.is_empty())
        } else {
            c.negative.len()
        };
        acc.insert(c.detector_id.clone(), count);
        acc
    });

    assert_eq!(
        rows.len(),
        detectors.len(),
        "contract near-miss row floor must cover all {} detectors, got {}",
        detectors.len(),
        rows.len()
    );
    assert!(
        rows.values().all(|&n| n >= 1),
        "every detector must ship at least one near-miss contract row (negative or synthesized)"
    );
}
