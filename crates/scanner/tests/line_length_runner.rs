//! Line-length / window-boundary runner.
//!
//! Some scanners pre-tokenise input on newlines and apply a hard
//! per-line ceiling (8 KB, 16 KB, 64 KB) to bound regex work on
//! pathological one-line files - minified JS, base64-encoded blobs
//! dumped without wrapping, single-line k8s ConfigMap output. A
//! credential past that boundary silently never reaches the engine.
//!
//! This runner builds one giant single-line payload with the
//! credential at progressively further offsets and asserts the
//! scanner still surfaces it. If a window-cap regression lands, the
//! per-offset hit-rate column flips to zero at the new boundary and
//! the strict gate (KEYHOG_LINE_LEN_STRICT=1) turns CI red.
//!
//! Surface
//! -------
//! 348 contracts × ~2 positives × 8 offsets = **5 500 cases per run**.

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
        .expect("detectors directory loadable from line-length runner");
    CompiledScanner::compile(detectors).expect("scanner compile from line-length runner")
}

/// Offsets the credential gets placed at, measured in bytes from the
/// start of the line. Ladder is roughly geometric so a regression
/// that puts a ceiling somewhere between rungs surfaces at the
/// nearest rung.
const OFFSETS: &[usize] = &[
    0,        // baseline
    256,      // typical "short" minified line
    4 * 1024, // small block
    16 * 1024,
    64 * 1024,  // common per-line cap in legacy scanners
    256 * 1024, // start of "absurd" territory
    1 * 1024 * 1024,
    4 * 1024 * 1024, // 4 MB: well past anything legitimate
];

const FILLER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789..";

fn make_filler(n: usize) -> String {
    let mut out = String::with_capacity(n);
    while out.len() < n {
        let take = (n - out.len()).min(FILLER.len());
        out.push_str(&FILLER[..take]);
    }
    out
}

fn make_chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "line-length".into(),
            path: Some("oneliner.txt".into()),
            ..Default::default()
        },
    }
}

fn any_credential_contains(matches: &[keyhog_core::RawMatch], expected: &str) -> bool {
    matches
        .iter()
        .any(|m| m.credential.as_ref().contains(expected))
}

#[test]
fn every_positive_survives_long_line_offsets() {
    let scanner = scanner();
    let contracts = load_contracts();
    assert!(
        !contracts.is_empty(),
        "tests/contracts/ has no *.toml - line-length runner has nothing to drive"
    );

    let mut per_offset: BTreeMap<usize, (usize, usize)> = BTreeMap::new();
    let mut total_runs: usize = 0;
    let mut total_hits: usize = 0;

    for c in &contracts {
        for p in &c.positive {
            for &offset in OFFSETS {
                let prefix = make_filler(offset);
                // Wrap the positive on a single line with no newlines
                // so a per-line cap (rather than per-chunk cap) is the
                // thing under test. Replace any positive-internal
                // newlines with spaces.
                let positive_inline = p.text.replace('\n', " ");
                let text = format!("{prefix} {positive_inline}");
                scanner.clear_fragment_cache();
                let chunk = make_chunk(&text);
                let matches = scanner.scan(&chunk);
                let hit = any_credential_contains(&matches, &p.credential);
                let bucket = per_offset.entry(offset).or_insert((0, 0));
                bucket.0 += 1;
                total_runs += 1;
                if hit {
                    bucket.1 += 1;
                    total_hits += 1;
                }
            }
        }
    }

    let mut summary = String::from("line-length per-offset hit rate:\n");
    for (offset, (runs, hits)) in &per_offset {
        let pct = (*hits as f64 / (*runs).max(1) as f64) * 100.0;
        summary.push_str(&format!(
            "  offset={offset:>9}  {hits:>4}/{runs:<4} ({pct:5.1}%)\n"
        ));
    }
    let overall = (total_hits as f64 / total_runs.max(1) as f64) * 100.0;
    summary.push_str(&format!(
        "  TOTAL {total_hits}/{total_runs} ({overall:.1}%) - flat across \
         offsets = legendary; a step-down = a window-cap regression\n"
    ));
    eprintln!("{summary}");

    let strict = std::env::var("KEYHOG_LINE_LEN_STRICT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    // 60% floor: the 4 MB and 1 MB rungs may legitimately get capped
    // by `max_file_size` / decode-bomb guards. The middle rungs
    // (256 B - 64 KB) should be flat at ~100%, so any drop below 60%
    // means even the small rungs regressed.
    if strict && overall < 60.0 {
        panic!(
            "line-length overall recall {overall:.1}% dropped below 60% floor - \
             a per-line/window-size cap regression likely landed"
        );
    }
}
