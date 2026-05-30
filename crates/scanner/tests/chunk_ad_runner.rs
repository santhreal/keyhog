//! Validate contract TOMLs listed in KEYHOG_CHUNK_IDS (newline-separated paths or IDs).
//! Used by Round-1 parallel agents to gate their chunk without running the full suite.

mod support;
use support::paths::detector_dir;

use std::env;
use std::path::{Path, PathBuf};

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
}

#[derive(Debug, Deserialize)]
struct Negative {
    text: String,
}

fn contracts_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("tests");
    d.push("contracts");
    d
}

fn load_toml(path: &Path) -> Contract {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!("read {}: {e}", path.display());
    });
    toml::from_str(&text).unwrap_or_else(|e| {
        panic!("malformed contract {}: {e}", path.display());
    })
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
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("detectors directory loadable");
    CompiledScanner::compile(detectors).expect("scanner compile")
}

fn any_credential_contains(matches: &[keyhog_core::RawMatch], expected: &str) -> bool {
    matches
        .iter()
        .any(|m| m.credential.as_ref().contains(expected))
}

fn resolve_contract_path(chunk_id: &str) -> PathBuf {
    let direct = contracts_dir().join(format!("{chunk_id}.toml"));
    if direct.is_file() {
        return direct;
    }
    let det_path = detector_dir().join(format!("{chunk_id}.toml"));
    if det_path.is_file() {
        let text = std::fs::read_to_string(&det_path).expect("read detector");
        let value: toml::Value = toml::from_str(&text).expect("parse detector");
        if let Some(det_id) = value
            .get("detector")
            .and_then(|d| d.get("id"))
            .and_then(|id| id.as_str())
        {
            let mapped = contracts_dir().join(format!("{det_id}.toml"));
            if mapped.is_file() {
                return mapped;
            }
        }
    }
    direct
}

fn chunk_ids() -> Vec<String> {
    let path = env::var("KEYHOG_CHUNK_IDS")
        .expect("KEYHOG_CHUNK_IDS must point to a newline-separated ID list");
    std::fs::read_to_string(path)
        .expect("read KEYHOG_CHUNK_IDS file")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

#[test]
fn chunk_contracts_pass_positives_and_negatives() {
    let scanner = scanner();
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for chunk_id in chunk_ids() {
        let path = resolve_contract_path(&chunk_id);
        if !path.is_file() {
            failures.push(format!(
                "{chunk_id}: contract missing at {}",
                path.display()
            ));
            continue;
        }
        let c = load_toml(&path);
        checked += 1;

        for p in &c.positive {
            scanner.clear_fragment_cache();
            let matches = scanner.scan(&make_chunk(&p.text));
            if !any_credential_contains(&matches, &p.credential) {
                let creds: Vec<_> = matches.iter().map(|m| m.credential.as_ref()).collect();
                failures.push(format!(
                    "{}: positive MISSED - credential {:?} not in {:?} ({})",
                    c.detector_id,
                    p.credential,
                    creds,
                    path.display(),
                ));
            }
        }

        for n in &c.negative {
            scanner.clear_fragment_cache();
            let matches = scanner.scan(&make_chunk(&n.text));
            let fired = matches
                .iter()
                .any(|m| m.detector_id.as_ref() == c.detector_id);
            if fired {
                let captured: Vec<&str> = matches
                    .iter()
                    .filter(|m| m.detector_id.as_ref() == c.detector_id)
                    .map(|m| m.credential.as_ref())
                    .collect();
                failures.push(format!(
                    "{}: false positive on negative - {:?} ({}) saw {:?}",
                    c.detector_id,
                    n.text,
                    path.display(),
                    captured,
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "chunk contract failures (checked {checked}):\n  - {}",
        failures.join("\n  - "),
    );
}
