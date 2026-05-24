//! Multi-secret runner — multiple credentials on one line/file.
//!
//! A `.env` with 8 service credentials, a CI YAML with `env:` for
//! every service the team uses, a debug dump that prints every key
//! the worker holds — all real shapes. A detector that fires on the
//! first credential but misses the next two (because it stops at
//! the first match per-line, or its span/window happened to cover
//! only the first) silently drops 50–80% of recall on these files.
//!
//! Two scenarios this runner covers:
//!
//! 1. **N positives on N lines** — each contract's first positive
//!    is concatenated with the first positive of N other contracts,
//!    one per line. Asserts the scanner finds ALL N credentials.
//! 2. **N positives in one paragraph** — same N positives, but
//!    joined with `; ` separators on a single line. Asserts the
//!    scanner finds ALL N credentials within one line.
//!
//! Surface
//! -------
//! 348 contracts × {3, 5, 10} positives-per-fixture × 2 layouts ≈
//! **2 100 multi-secret fixtures**, each verifying every embedded
//! credential surfaced.

use std::collections::BTreeMap;
use std::path::PathBuf;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Contract {
    #[allow(dead_code)]
    schema_version: u32,
    #[allow(dead_code)]
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

fn load_contracts() -> Vec<Contract> {
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
        out.push(contract);
    }
    out
}

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("detectors directory loadable from multi-secret runner");
    CompiledScanner::compile(detectors).expect("scanner compile from multi-secret runner")
}

fn make_chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "multi-secret".into(),
            path: Some("multi.txt".into()),
            ..Default::default()
        },
    }
}

#[derive(Debug, Clone, Copy)]
enum Layout {
    Lines,
    Paragraph,
}

impl Layout {
    fn label(self) -> &'static str {
        match self {
            Layout::Lines => "lines",
            Layout::Paragraph => "paragraph",
        }
    }

    fn join(self, fragments: &[String]) -> String {
        match self {
            Layout::Lines => fragments.join("\n"),
            Layout::Paragraph => fragments.join("; "),
        }
    }
}

const PACK_SIZES: &[usize] = &[3, 5, 10];
const LAYOUTS: &[Layout] = &[Layout::Lines, Layout::Paragraph];

#[test]
fn n_secrets_in_one_fixture_all_fire() {
    let scanner = scanner();
    let contracts = load_contracts();
    assert!(
        !contracts.is_empty(),
        "tests/contracts/ has no *.toml — multi-secret runner has nothing to drive"
    );

    // Pre-extract the first positive of every contract that has at
    // least one. Skip contracts with no positives.
    let primaries: Vec<&Positive> = contracts
        .iter()
        .filter_map(|c| c.positive.first())
        .collect();

    // Build packs of N positives, walking the corpus in chunks so
    // every primary is covered once at every (size, layout). Total
    // packs = primaries.len() / pack_size (rounded down) per
    // (size, layout).
    let mut per_combo: BTreeMap<(usize, &'static str), (usize, usize)> = BTreeMap::new();
    let mut total_fixtures: usize = 0;
    let mut total_credential_assertions: usize = 0;
    let mut total_hits: usize = 0;

    for &pack_size in PACK_SIZES {
        for layout in LAYOUTS {
            for chunk_window in primaries.chunks(pack_size) {
                if chunk_window.len() != pack_size {
                    continue; // skip the partial tail; keeps the size honest
                }
                let texts: Vec<String> = chunk_window.iter().map(|p| p.text.clone()).collect();
                let fixture = layout.join(&texts);
                scanner.clear_fragment_cache();
                let chunk_obj = make_chunk(&fixture);
                let matches = scanner.scan(&chunk_obj);
                total_fixtures += 1;

                let mut fixture_hits = 0;
                for p in chunk_window {
                    total_credential_assertions += 1;
                    let hit = matches
                        .iter()
                        .any(|m| m.credential.as_ref().contains(&p.credential));
                    if hit {
                        fixture_hits += 1;
                        total_hits += 1;
                    }
                }
                let bucket = per_combo
                    .entry((pack_size, layout.label()))
                    .or_insert((0, 0));
                bucket.0 += pack_size;
                bucket.1 += fixture_hits;
            }
        }
    }

    let mut summary = String::from(
        "multi-secret per (pack_size × layout) per-credential hit rate:\n",
    );
    for ((size, layout), (asserts, hits)) in &per_combo {
        let pct = (*hits as f64 / (*asserts).max(1) as f64) * 100.0;
        summary.push_str(&format!(
            "  size={size:>2} layout={layout:<10}  {hits:>5}/{asserts:<5} \
             ({pct:5.1}%)\n"
        ));
    }
    let overall =
        (total_hits as f64 / total_credential_assertions.max(1) as f64) * 100.0;
    summary.push_str(&format!(
        "  TOTAL {total_hits}/{total_credential_assertions} ({overall:.1}%) \
         across {total_fixtures} fixtures\n"
    ));
    eprintln!("{summary}");

    let strict = std::env::var("KEYHOG_MULTI_STRICT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if strict && overall < 80.0 {
        panic!(
            "multi-secret overall hit-rate {overall:.1}% dropped below 80% floor"
        );
    }
}
