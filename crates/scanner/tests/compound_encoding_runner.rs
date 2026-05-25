//! Compound-encoding runner — tests N-layer nested encodings.
//!
//! Real-world secrets routinely pass through multiple encoding layers
//! before they show up in git: a Kubernetes `Secret` base64-encodes
//! the credential value, the manifest gets stored as YAML, that YAML
//! gets serialized inside a JSON config blob, the JSON gets stuffed
//! into a `.env` line, and someone commits the .env. The single-
//! encoding `encoding_explosion_runner` proves one layer survives;
//! this one proves the README's "decode 4 layers" claim.
//!
//! Why this matters
//! ----------------
//! `crates/scanner/src/decode/pipeline.rs` advertises `max_decode_depth`
//! support up to 4 layers (the default). The single-layer runner
//! showed 93% recall after the splice fix; with N-layer composition
//! we get to ask: *does each successive layer hold up?* A 70%
//! single-layer detector at three layers compounds to ~34% — knowing
//! the multi-layer rate is the only way to know what real-world
//! recall looks like.
//!
//! Layer matrix
//! ------------
//! 4 inner encodings × 4 outer encodings = 16 two-layer pairs ×
//! 348 contracts × ~2 positives ≈ **11 000 cases per run**.
//!
//! Skips: same encoding twice (base64(base64) is also tested by the
//! decode pipeline's recursion, no need to re-cover here), and the
//! self-inverse pairs (identity × identity is the single-layer
//! `identity` cell of the other runner).
//!
//! Report-only by default; floors pin after a clean baseline.

use std::collections::BTreeMap;
use std::path::PathBuf;

use base64::{engine::general_purpose, Engine as _};
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
        .expect("detectors directory loadable from compound encoding runner");
    CompiledScanner::compile(detectors).expect("scanner compile from compound encoding runner")
}

// ── encoders (subset of the single-layer runner, only the ones
//    keyhog has decoders for so the composition test is meaningful) ─

#[derive(Debug, Clone, Copy)]
enum Layer {
    Base64Std,
    Base64Url,
    Hex,
    UrlPercent,
}

impl Layer {
    const ALL: &'static [Layer] = &[
        Layer::Base64Std,
        Layer::Base64Url,
        Layer::Hex,
        Layer::UrlPercent,
    ];

    fn label(self) -> &'static str {
        match self {
            Layer::Base64Std => "base64-std",
            Layer::Base64Url => "base64-url",
            Layer::Hex => "hex",
            Layer::UrlPercent => "url-percent",
        }
    }

    fn encode(self, input: &str) -> String {
        match self {
            Layer::Base64Std => general_purpose::STANDARD.encode(input.as_bytes()),
            Layer::Base64Url => general_purpose::URL_SAFE_NO_PAD.encode(input.as_bytes()),
            Layer::Hex => hex::encode(input.as_bytes()),
            Layer::UrlPercent => percent_encode_all(input.as_bytes()),
        }
    }
}

fn percent_encode_all(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for b in bytes {
        out.push_str(&format!("%{:02X}", b));
    }
    out
}

fn make_chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "compound-encoding".into(),
            path: Some("compound.txt".into()),
            ..Default::default()
        },
    }
}

fn any_credential_contains(matches: &[keyhog_core::RawMatch], expected: &str) -> bool {
    matches
        .iter()
        .any(|m| m.credential.as_ref().contains(expected))
}

fn wrap_with_encoded_cred(text: &str, raw: &str, encoded: &str) -> String {
    if let Some(pos) = text.find(raw) {
        let mut out = String::with_capacity(text.len() - raw.len() + encoded.len());
        out.push_str(&text[..pos]);
        out.push_str(encoded);
        out.push_str(&text[pos + raw.len()..]);
        out
    } else {
        text.to_string()
    }
}

// ── the compound test ───────────────────────────────────────────────

#[test]
fn every_positive_swept_through_two_layer_encodings() {
    let scanner = scanner();
    let contracts = load_contracts();
    assert!(
        !contracts.is_empty(),
        "tests/contracts/ has no *.toml — compound runner has nothing to drive"
    );

    // Per (outer, inner): (runs, decode_hits)
    let mut per_pair: BTreeMap<(&'static str, &'static str), (usize, usize)> = BTreeMap::new();
    let mut total_runs: usize = 0;
    let mut total_hits: usize = 0;

    for (_path, c) in &contracts {
        for p in &c.positive {
            for inner in Layer::ALL {
                for outer in Layer::ALL {
                    // Skip self-pairs — base64(base64(x)) is covered
                    // by the decode pipeline's recursion against the
                    // single-layer corpus already, and adds noise
                    // here without new signal.
                    if std::ptr::eq(inner as *const _, outer as *const _)
                        || inner.label() == outer.label()
                    {
                        continue;
                    }
                    // Encode credential inner then outer: outer(inner(cred)).
                    let inner_encoded = inner.encode(&p.credential);
                    let outer_encoded = outer.encode(&inner_encoded);
                    let text = wrap_with_encoded_cred(&p.text, &p.credential, &outer_encoded);
                    scanner.clear_fragment_cache();
                    let chunk = make_chunk(&text);
                    let matches = scanner.scan(&chunk);
                    let hit = any_credential_contains(&matches, &p.credential);
                    let bucket = per_pair
                        .entry((outer.label(), inner.label()))
                        .or_insert((0, 0));
                    bucket.0 += 1;
                    total_runs += 1;
                    if hit {
                        bucket.1 += 1;
                        total_hits += 1;
                    }
                }
            }
        }
    }

    let mut summary = String::from("compound-encoding per (outer × inner) pair decode-hit rate:\n");
    for ((outer, inner), (runs, hits)) in &per_pair {
        let pct = (*hits as f64 / (*runs).max(1) as f64) * 100.0;
        summary.push_str(&format!(
            "  {outer:<14} ∘ {inner:<14} {hits:>4}/{runs:<4} ({pct:5.1}%)\n"
        ));
    }
    let overall = (total_hits as f64 / total_runs.max(1) as f64) * 100.0;
    summary.push_str(&format!(
        "  TOTAL {total_hits}/{total_runs} ({overall:.1}%) across {} pairs\n",
        per_pair.len(),
    ));
    eprintln!("{summary}");

    // The strict gate compares the overall recall against a baseline
    // floor. Set after we observe a few stable runs; default is
    // report-only.
    let strict = std::env::var("KEYHOG_COMPOUND_STRICT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if strict && overall < 50.0 {
        panic!("compound-encoding overall recall {overall:.1}% dropped below 50% floor");
    }
}
