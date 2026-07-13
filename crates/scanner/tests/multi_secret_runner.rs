//! Multi-secret runner (multiple credentials on one line/file).
//!
//! A `.env` with 8 service credentials, a CI YAML with `env:` for
//! every service the team uses, a debug dump that prints every key
//! the worker holds, all real shapes. A detector that fires on the
//! first credential but misses the next two (because it stops at the
//! first match per-line, or its span/window happened to cover only
//! the first) silently drops 50–80% of recall on these files.
//!
//! BEHAVIOR contract, not an accuracy rate
//! ---------------------------------------
//! The gate asserts a sound PROPERTY, all-or-nothing, never a
//! recall/precision *rate* over a corpus (those live in the
//! differential bench):
//!
//!   *credential-sufficiency invariance*, if a detector fires on its
//!   credential ALONE (a distinctive prefix/shape, no companion
//!   context needed), then co-locating other secrets on the same
//!   line/file CANNOT remove that match. Every such credential MUST
//!   surface in every pack it appears in.
//!
//! A detector whose credential does NOT fire standalone is
//! companion-REQUIRED: a bare UUID, or a low-entropy generic body
//! that needs an `api`/`secret`/`credentials` anchor. Dense
//! co-location legitimately perturbs that companion attribution
//! how well it survives is evasion ACCURACY owned by the bench, so
//! those positives are recorded for visibility but never gated.
//! (Forcing them to 100% would assert an accuracy rate in
//! `cargo test`, the exact T-01 violation this rewrite removes.)
//!
//! Two scenarios this runner covers:
//!
//! 1. **N positives on N lines**: each contract's first positive is
//!    concatenated with the first positive of N other contracts, one
//!    per line.
//! 2. **N positives in one paragraph**: same N positives, joined
//!    with `; ` separators on a single line.

mod support;
use support::paths::detector_dir;

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

/// One contract's first positive, carrying the detector id so a miss
/// names the exact offending detector instead of an anonymous count.
struct Primary {
    detector_id: String,
    text: String,
    credential: String,
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
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read tests/contracts dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry readable").path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read contract {}: {e}", path.display()));
        let contract = toml::from_str::<Contract>(&text)
            .unwrap_or_else(|e| panic!("parse contract {}: {e}", path.display()));
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

fn surfaces(scanner: &CompiledScanner, text: &str, credential: &str) -> bool {
    scanner.clear_fragment_cache();
    let matches = scanner.scan(&make_chunk(text));
    matches
        .iter()
        .any(|m| m.credential.as_ref().contains(credential))
}

#[test]
fn credential_sufficient_secrets_survive_colocation() {
    let scanner = scanner();
    let contracts = load_contracts();
    assert!(
        !contracts.is_empty(),
        "tests/contracts/ has no *.toml, multi-secret runner has nothing to drive"
    );

    // First positive of every contract that has one, carrying its
    // detector id so a miss is attributable.
    let primaries: Vec<Primary> = contracts
        .iter()
        .filter_map(|c| {
            c.positive.first().map(|p| Primary {
                detector_id: c.detector_id.clone(),
                text: p.text.clone(),
                credential: p.credential.clone(),
            })
        })
        .collect();

    // Partition once: does each credential fire on its own (no
    // companion context)? Only the credential-sufficient set is gated.
    let credential_sufficient: Vec<bool> = primaries
        .iter()
        .map(|p| surfaces(&scanner, &p.credential, &p.credential))
        .collect();
    let n_sufficient = credential_sufficient.iter().filter(|b| **b).count();

    let mut gated_assertions: usize = 0;
    let mut gated_hits: usize = 0;
    let mut companion_runs: usize = 0;
    let mut companion_hits: usize = 0;
    let mut violations: Vec<String> = Vec::new();

    for &pack_size in PACK_SIZES {
        for layout in LAYOUTS {
            for (wi, window) in primaries.chunks(pack_size).enumerate() {
                if window.len() != pack_size {
                    continue; // skip the partial tail; keeps the size honest
                }
                let texts: Vec<String> = window.iter().map(|p| p.text.clone()).collect();
                let fixture = layout.join(&texts);
                scanner.clear_fragment_cache();
                let matches = scanner.scan(&make_chunk(&fixture));

                let base = wi * pack_size;
                for (offset, p) in window.iter().enumerate() {
                    let hit = matches
                        .iter()
                        .any(|m| m.credential.as_ref().contains(&p.credential));
                    if credential_sufficient[base + offset] {
                        gated_assertions += 1;
                        if hit {
                            gated_hits += 1;
                        } else {
                            let pack: Vec<&str> =
                                window.iter().map(|q| q.detector_id.as_str()).collect();
                            violations.push(format!(
                                "{detector} :: size={pack_size} layout={layout} :: \
                                 standalone-firing credential {cred:?} DROPPED when \
                                 co-located; pack={pack:?}",
                                detector = p.detector_id,
                                layout = layout.label(),
                                cred = p.credential,
                            ));
                        }
                    } else {
                        companion_runs += 1;
                        if hit {
                            companion_hits += 1;
                        }
                    }
                }
            }
        }
    }

    let companion_rate = if companion_runs > 0 {
        (companion_hits as f64 / companion_runs as f64) * 100.0
    } else {
        100.0
    };
    eprintln!(
        "multi-secret: {n_sufficient}/{} primaries fire standalone; gated co-location \
         recall {gated_hits}/{gated_assertions} (must be 100%); companion-required \
         co-location {companion_hits}/{companion_runs} = {companion_rate:.1}% (informational)",
        primaries.len(),
    );

    assert!(
        violations.is_empty(),
        "multi-secret credential-sufficiency invariance violated ({} cases): a credential \
         that fires standalone was dropped when other secrets were co-located. This is a \
         multi-match recall bug (the engine stopped at an earlier match or its window \
         missed a later secret). NOT a fixture artifact, because the credential needs no \
         companion context:\n  - {}",
        violations.len(),
        violations.join("\n  - "),
    );
}
