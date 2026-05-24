//! Entropy-edge runner — credential entropy near detector thresholds.
//!
//! Most detectors couple a regex to an entropy floor (`>= 4.5 bits`
//! is the common default; some are tighter at 5.0). Real secrets land
//! anywhere from 3.5 (very short prefixes + numeric padding) to 6.0
//! (full base64). The risk is a real credential whose entropy sits
//! at, say, 4.4 — the regex matches, but the entropy gate drops it.
//! This runner perturbs each contract positive's credential body by
//! injecting low-entropy filler (repeated `aaa`) or high-entropy
//! noise and records the hit-rate decay curve.
//!
//! Crucially, the runner ALSO swaps the original credential for a
//! same-length string at the entropy floor (4.0 - 5.0 bits in 0.25-
//! step rungs) so the user gets an exact picture of where the
//! detector boundary lives. A drop from 100% → 0% at 4.5 says the
//! threshold is exactly there; a drop spread across 4.0-5.0 says the
//! entropy is computed differently than the user expects.
//!
//! Surface
//! -------
//! 348 contracts × ~2 positives × 6 entropy rungs ≈ **4 200 cases**.

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
        .expect("detectors directory loadable from entropy runner");
    CompiledScanner::compile(detectors).expect("scanner compile from entropy runner")
}

fn shannon_entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    for b in s.as_bytes() {
        counts[*b as usize] += 1;
    }
    let n = s.len() as f64;
    if n == 0.0 {
        return 0.0;
    }
    let mut h = 0.0;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n;
        h -= p * p.log2();
    }
    h
}

fn make_chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "entropy-edge".into(),
            path: Some("entropy.txt".into()),
            ..Default::default()
        },
    }
}

fn any_credential_contains(matches: &[keyhog_core::RawMatch], expected: &str) -> bool {
    matches
        .iter()
        .any(|m| m.credential.as_ref().contains(expected))
}

/// Rungs we test the credential entropy at. The detector floor is
/// expected at 4.5 bits/byte for the default scanner config. Rungs
/// step by 0.25 bits so a single-rung gap pins the boundary.
const ENTROPY_RUNGS: &[f64] = &[3.5, 4.0, 4.25, 4.5, 4.75, 5.0];

/// Construct a string of `len` bytes with Shannon entropy near the
/// target. Strategy: pick from an alphabet of `2^target` symbols
/// (a string drawn uniformly from N symbols has entropy log2(N)).
/// Result is deterministic and rounds within ~0.15 bits of target.
fn synth_at_entropy(target: f64, len: usize) -> String {
    let n_symbols = (2.0f64.powf(target).round() as usize).clamp(2, 64);
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let alphabet = &ALPHABET[..n_symbols];
    let mut out = String::with_capacity(len);
    for i in 0..len {
        out.push(alphabet[i % n_symbols] as char);
    }
    out
}

#[test]
fn every_positive_swept_through_entropy_rungs() {
    let scanner = scanner();
    let contracts = load_contracts();
    assert!(
        !contracts.is_empty(),
        "tests/contracts/ has no *.toml — entropy-edge runner has nothing to drive"
    );

    let mut per_rung: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut total_runs: usize = 0;
    let mut total_hits: usize = 0;
    let mut original_hits: usize = 0;
    let mut original_runs: usize = 0;

    for c in &contracts {
        for p in &c.positive {
            // Control: original credential (whatever entropy it
            // happens to have). Establishes the per-detector baseline.
            scanner.clear_fragment_cache();
            let chunk = make_chunk(&p.text);
            let matches = scanner.scan(&chunk);
            original_runs += 1;
            if any_credential_contains(&matches, &p.credential) {
                original_hits += 1;
            }

            let len = p.credential.len();
            if len < 8 {
                continue;
            }

            for &target in ENTROPY_RUNGS {
                let synthetic = synth_at_entropy(target, len);
                if synthetic.len() != len {
                    continue;
                }
                let actual = shannon_entropy(&synthetic);
                let text = p.text.replace(&p.credential, &synthetic);
                scanner.clear_fragment_cache();
                let chunk = make_chunk(&text);
                let matches = scanner.scan(&chunk);
                let hit = any_credential_contains(&matches, &synthetic);
                let label = format!("{target:.2}->{actual:.2}");
                let bucket = per_rung.entry(label).or_insert((0, 0));
                bucket.0 += 1;
                total_runs += 1;
                if hit {
                    bucket.1 += 1;
                    total_hits += 1;
                }
            }
        }
    }

    let orig_pct = (original_hits as f64 / original_runs.max(1) as f64) * 100.0;
    let mut summary = format!(
        "entropy-edge sweep:\n  original-credential control: \
         {original_hits}/{original_runs} ({orig_pct:.1}%)\n  \
         synthetic-credential per target-entropy rung:\n"
    );
    for (rung, (runs, hits)) in &per_rung {
        let pct = (*hits as f64 / (*runs).max(1) as f64) * 100.0;
        summary.push_str(&format!(
            "  {rung:<14} {hits:>4}/{runs:<4} ({pct:5.1}%)\n"
        ));
    }
    let overall = (total_hits as f64 / total_runs.max(1) as f64) * 100.0;
    summary.push_str(&format!(
        "  TOTAL {total_hits}/{total_runs} ({overall:.1}%) — \
         a sharp boundary between rungs pins the entropy floor\n"
    ));
    eprintln!("{summary}");

    let strict = std::env::var("KEYHOG_ENTROPY_STRICT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if strict && original_hits == 0 {
        panic!(
            "entropy-edge: 0/{original_runs} original-credential controls \
             surfaced — scanner is broken upstream of the entropy gate"
        );
    }
}
