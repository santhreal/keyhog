//! Noise-injection runner (a credential-sufficient secret survives padding).
//!
//! Real-world secrets rarely land in a bare `KEY=value` line: a 4 KB JSON log
//! row, a base64 audit-trail entry, a Vec-of-structs debug dump, a stack trace
//! that happens to mention the credential. A detector that uses a fixed-size
//! span/window around the credential misses when the companion keyword sits
//! past the window boundary.
//!
//! BEHAVIOR contract, not an accuracy rate
//! ---------------------------------------
//! Padding noise on both sides of a positive leaves the credential BYTES
//! intact, so this is a *credential-sufficiency invariance* contract (see
//! `support::contracts`): a credential that fires on its own bytes alone MUST
//! still surface with arbitrary noise padded around it, the padding cannot
//! remove bytes the detector already matched standalone. We gate exactly that,
//! all-or-nothing, across every noise size and kind. Companion-required
//! positives (no standalone fire) legitimately depend on context the padding
//! pushes away; their survival is an accuracy RATE owned by the differential
//! bench (`benchmarks/bench`), recorded here for visibility but never gated
//! asserting that rate in `cargo test` is the exact T-01 violation this rewrite
//! removes.
//!
//! Noise stays ≤4 KiB each side (≤~8 KiB total), well inside the 1 MiB scan
//! window, so there is no legitimate size cap that could drop an in-bounds
//! credential (every credential-sufficient miss here is a real recall bug).

mod support;
use support::contracts::{load_contracts, primaries, scanner, sufficiency_mask, surfaces, Primary};

use std::collections::BTreeMap;

const SOURCE_TYPE: &str = "noise-injection";

/// Three noise shapes a credential might be buried in. No random binary: the
/// rendered chunk must stay UTF-8 (the scanner is text-oriented).
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

    /// Generate `n` bytes of noise of this kind. Deterministic (no RNG) so a
    /// regression that flips one fixture has a stable diff.
    fn generate(self, n: usize) -> String {
        match self {
            NoiseKind::Alphanum => {
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

/// ≤4 KiB each side keeps the credential well inside the 1 MiB scan window and
/// the whole sweep under a few seconds on a release build.
const NOISE_SIZES: &[usize] = &[64, 256, 1024, 4096];

#[test]
fn credential_sufficient_secrets_survive_noise_padding() {
    let scanner = scanner();
    let contracts = load_contracts();
    let primaries: Vec<Primary> = primaries(&contracts);
    let sufficient = sufficiency_mask(&scanner, SOURCE_TYPE, &primaries);
    let n_sufficient = sufficient.iter().filter(|b| **b).count();

    // Informational only: companion-required survival per (size × kind).
    let mut companion_combo: BTreeMap<(usize, &'static str), (usize, usize)> = BTreeMap::new();
    let mut gated_assertions = 0usize;
    let mut gated_hits = 0usize;
    let mut violations: Vec<String> = Vec::new();

    for (idx, p) in primaries.iter().enumerate() {
        for &size in NOISE_SIZES {
            for kind in NoiseKind::ALL {
                let noise = kind.generate(size);
                // Pad both sides at once so a window regression on either side
                // of the credential surfaces. Bytes scanned = 2*size + len.
                let text = format!("{noise}\n{}\n{noise}", &p.text);
                let chunk = support::contracts::make_chunk(&text, SOURCE_TYPE, "noisy.txt");
                let hit = surfaces(&scanner, &chunk, &p.credential);

                if sufficient[idx] {
                    gated_assertions += 1;
                    if hit {
                        gated_hits += 1;
                    } else {
                        violations.push(format!(
                            "{detector} :: size={size} kind={kind} :: standalone-firing \
                             credential {cred:?} DROPPED when padded with noise",
                            detector = p.detector_id,
                            kind = kind.label(),
                            cred = p.credential,
                        ));
                    }
                } else {
                    let bucket = companion_combo
                        .entry((size, kind.label()))
                        .or_insert((0, 0));
                    bucket.0 += 1;
                    if hit {
                        bucket.1 += 1;
                    }
                }
            }
        }
    }

    let mut summary = format!(
        "noise-injection: {n_sufficient}/{} primaries fire standalone; gated survival \
         {gated_hits}/{gated_assertions} (must be 100%).\n  companion-required survival \
         per (size × kind), informational:\n",
        primaries.len(),
    );
    for ((size, kind), (runs, hits)) in &companion_combo {
        let pct = (*hits as f64 / (*runs).max(1) as f64) * 100.0;
        summary.push_str(&format!(
            "    size={size:>6} kind={kind:<11} {hits:>4}/{runs:<4} ({pct:5.1}%)\n"
        ));
    }
    eprintln!("{summary}");

    assert!(
        violations.is_empty(),
        "noise-injection credential-sufficiency invariance violated ({} cases): a credential \
         that fires standalone was dropped when noise was padded around it, a window/span \
         recall bug, NOT a fixture artifact (the credential needs no companion context):\n  - {}",
        violations.len(),
        violations.join("\n  - "),
    );
}
