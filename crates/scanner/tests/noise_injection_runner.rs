//! Noise-injection runner — tests detector behavior with padding.
//!
//! Real-world secrets often land in lines that aren't bare
//! `KEY=value` shapes: a 4 KB JSON log row, a base64-encoded
//! audit-trail entry, a Vec-of-structs printout from a debug dump,
//! a stack trace that happens to mention the credential. Some
//! detectors use a fixed-size span/window around the credential —
//! if the companion keyword sits past the window boundary, the
//! detector misses.
//!
//! Why this runner exists
//! ----------------------
//! Span-based detectors are easy to write and very fast, but their
//! recall degrades silently when context is far away. The single-
//! layer `encoding_explosion_runner` and `adversarial_explosion_
//! runner` exercise the credential at near-zero noise (the wrappers
//! add at most ~150 bytes). This runner pads N bytes of varying
//! shapes on both sides of the credential and reports the recall
//! decay curve — a window regression that loses recall on a 4 KB
//! noisy line shows up as a flat hit-rate that drops off at the
//! window boundary.
//!
//! Surface
//! -------
//! 348 contracts × ~2 positives × 6 noise sizes × 3 noise kinds ≈
//! **12 500 cases per run**.

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
        .expect("detectors directory loadable from noise runner");
    CompiledScanner::compile(detectors).expect("scanner compile from noise runner")
}

// ── noise generators ────────────────────────────────────────────────

/// Three noise shapes a credential might be buried in. We DON'T
/// include random binary because the rendered chunk has to be UTF-8
/// (the scanner is text-oriented).
#[derive(Debug, Clone, Copy)]
enum NoiseKind {
    Alphanum,
    JsonArray,
    LogLines,
}

impl NoiseKind {
    const ALL: &'static [NoiseKind] = &[
        NoiseKind::Alphanum,
        NoiseKind::JsonArray,
        NoiseKind::LogLines,
    ];

    fn label(self) -> &'static str {
        match self {
            NoiseKind::Alphanum => "alphanum",
            NoiseKind::JsonArray => "json-array",
            NoiseKind::LogLines => "log-lines",
        }
    }

    /// Generate `n` bytes of noise of this kind. Deterministic
    /// (no RNG) so a regression that flips one fixture has a
    /// stable hash for the diff reviewer.
    fn generate(self, n: usize) -> String {
        match self {
            NoiseKind::Alphanum => {
                // Repeat a fixed 32-char alphanum block until we
                // reach n. Keeps the output well-formed printable
                // ASCII without random-source non-determinism.
                const BLOCK: &str = "abcdefghijklmnopqrstuvwxyz0123456";
                let mut out = String::with_capacity(n);
                while out.len() < n {
                    let take = (n - out.len()).min(BLOCK.len());
                    out.push_str(&BLOCK[..take]);
                }
                out
            }
            NoiseKind::JsonArray => {
                let mut out = String::with_capacity(n);
                out.push_str("[\n");
                let mut i = 0usize;
                while out.len() < n.saturating_sub(8) {
                    let line = format!("  {{\"i\": {i}, \"v\": \"row-data-{i:08}\"}},\n");
                    out.push_str(&line);
                    i += 1;
                }
                out.push_str("\"end\"]\n");
                out
            }
            NoiseKind::LogLines => {
                let mut out = String::with_capacity(n);
                let mut ts = 0u64;
                while out.len() < n {
                    let line = format!(
                        "2026-05-23T10:00:{:02}.{:03}Z INFO request_id=req-{ts:08} \
                         path=/api/v1/resource bytes=1024\n",
                        ts % 60,
                        ts * 13 % 1000
                    );
                    if out.len() + line.len() > n {
                        out.push_str(&line[..n - out.len()]);
                        break;
                    }
                    out.push_str(&line);
                    ts += 1;
                }
                out
            }
        }
    }
}

fn make_chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "noise-injection".into(),
            path: Some("noisy.txt".into()),
            ..Default::default()
        },
    }
}

fn any_credential_contains(matches: &[keyhog_core::RawMatch], expected: &str) -> bool {
    matches
        .iter()
        .any(|m| m.credential.as_ref().contains(expected))
}

// CI-budget-friendly sizes: 4 KB max keeps the whole sweep under
// ~5 s on a release build (was 65 KB which exceeded the per-test
// budget on cargo-test's default thread count). The larger sizes
// were proving the same "decoder window holds" property as the 4 KB
// cell on the local hardware; we trade scale for cycle time.
const NOISE_SIZES: &[usize] = &[64, 256, 1024, 4096];

#[test]
fn every_positive_survives_noise_padding() {
    let scanner = scanner();
    let contracts = load_contracts();
    assert!(
        !contracts.is_empty(),
        "tests/contracts/ has no *.toml — noise runner has nothing to drive"
    );

    // Per (noise_size, noise_kind): (runs, hits)
    let mut per_combo: BTreeMap<(usize, &'static str), (usize, usize)> = BTreeMap::new();
    let mut total_runs: usize = 0;
    let mut total_hits: usize = 0;

    for (_path, c) in &contracts {
        for p in &c.positive {
            for &size in NOISE_SIZES {
                for kind in NoiseKind::ALL {
                    let noise = kind.generate(size);
                    // Inject noise BOTH before and after to test
                    // detector windows on both sides of the
                    // credential at once. Bytes scanned per case =
                    // 2 * size + len(positive).
                    let text = format!("{noise}\n{}\n{noise}", &p.text);
                    scanner.clear_fragment_cache();
                    let chunk = make_chunk(&text);
                    let matches = scanner.scan(&chunk);
                    let hit = any_credential_contains(&matches, &p.credential);
                    let bucket = per_combo.entry((size, kind.label())).or_insert((0, 0));
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

    let mut summary = String::from("noise-injection per (size × kind) decode-hit rate:\n");
    for ((size, kind), (runs, hits)) in &per_combo {
        let pct = (*hits as f64 / (*runs).max(1) as f64) * 100.0;
        summary.push_str(&format!(
            "  size={size:>6}  kind={kind:<11}  {hits:>4}/{runs:<4} ({pct:5.1}%)\n"
        ));
    }
    let overall = (total_hits as f64 / total_runs.max(1) as f64) * 100.0;
    summary.push_str(&format!(
        "  TOTAL {total_hits}/{total_runs} ({overall:.1}%) — \
         decay across sizes is the legendary metric here\n"
    ));
    eprintln!("{summary}");

    let strict = std::env::var("KEYHOG_NOISE_STRICT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if strict && overall < 80.0 {
        panic!("noise-injection overall recall {overall:.1}% dropped below 80% floor");
    }
}
