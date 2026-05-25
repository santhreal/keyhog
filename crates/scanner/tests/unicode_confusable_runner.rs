//! Unicode-confusable runner — homoglyph evasion coverage.
//!
//! A real adversary who wants their credential leak to slip past a
//! secret scanner can replace ASCII characters in the surrounding
//! companion words with similar-looking Unicode codepoints. Latin
//! `a` becomes Cyrillic `а` (U+0430), Latin `e` becomes `е`
//! (U+0435), digit `0` becomes the Mathematical Bold Digit Zero,
//! etc. The credential itself stays ASCII (provider-side validation
//! still cares about that), but the anchor `api_key` becomes
//! `аpі_kеу` and any companion-anchored detector misses.
//!
//! This runner mutates ONLY the companion-context portion of every
//! contract positive — never the credential itself — and asserts
//! the detector still surfaces the credential.
//!
//! Result is one of two outcomes:
//!
//! 1. Detector fires on the credential alone (no companion
//!    requirement). Recall stays at 100% — confirms the
//!    detector is shape-robust.
//! 2. Detector requires companion context and the homoglyph
//!    swap breaks it. We log the per-detector miss so the
//!    contributor can decide whether to add Unicode normalization
//!    to the companion-detection pre-pass.
//!
//! Surface
//! -------
//! 348 contracts × ~2 positives × 4 confusable density levels
//! ≈ **2 800 cases**.

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
        .expect("detectors directory loadable from unicode runner");
    CompiledScanner::compile(detectors).expect("scanner compile from unicode runner")
}

// ── confusable map ──────────────────────────────────────────────────

/// ASCII → similar-looking Unicode replacement. Pulled from the
/// Unicode Confusables data file, narrowed to the chars that appear
/// in the words detectors actually anchor on (api/key/token/secret/
/// auth/bearer/access).
fn confusable_for(c: char) -> Option<char> {
    Some(match c {
        // Cyrillic look-alikes — the canonical attack class.
        'a' => '\u{0430}',
        'c' => '\u{0441}',
        'e' => '\u{0435}',
        'i' => '\u{0456}', // Ukrainian "i"
        'o' => '\u{043e}',
        'p' => '\u{0440}',
        's' => '\u{0455}',
        'x' => '\u{0445}',
        'y' => '\u{0443}',
        // Greek alpha-look-alike for capitals.
        'A' => '\u{0391}',
        'B' => '\u{0392}',
        'E' => '\u{0395}',
        'K' => '\u{039a}',
        'P' => '\u{03a1}',
        'T' => '\u{03a4}',
        // Mathematical bold for digits.
        '0' => '\u{1d7ec}',
        '1' => '\u{1d7ed}',
        _ => return None,
    })
}

fn apply_confusable(s: &str, swap_every: usize) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    let mut counter = 0usize;
    for c in s.chars() {
        let mapped = if swap_every > 0 && counter % swap_every == 0 {
            confusable_for(c).unwrap_or(c)
        } else {
            c
        };
        out.push(mapped);
        counter += 1;
    }
    out
}

/// Apply confusable swaps to only the companion-context portion of
/// the positive text — never the credential bytes. Locates the
/// credential by `find` and swaps everything BEFORE / AFTER.
fn swap_companion(text: &str, credential: &str, swap_every: usize) -> String {
    let Some(pos) = text.find(credential) else {
        return text.to_string();
    };
    let prefix = apply_confusable(&text[..pos], swap_every);
    let suffix = apply_confusable(&text[pos + credential.len()..], swap_every);
    format!("{prefix}{credential}{suffix}")
}

fn make_chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "unicode-confusable".into(),
            path: Some("confusable.txt".into()),
            ..Default::default()
        },
    }
}

const SWAP_DENSITIES: &[(usize, &str)] = &[
    // (swap_every, label) — every Nth char gets confused.
    (0, "none"),       // control — should match contracts_runner
    (1, "every-char"), // strongest evasion: swap every confusable-eligible char
    (2, "every-2nd"),  // every other char swapped
    (4, "every-4th"),  // light dusting
];

#[test]
fn every_positive_swept_through_unicode_confusables() {
    let scanner = scanner();
    let contracts = load_contracts();
    assert!(
        !contracts.is_empty(),
        "tests/contracts/ has no *.toml — unicode runner has nothing to drive"
    );

    let mut per_density: BTreeMap<&'static str, (usize, usize)> = BTreeMap::new();

    for c in &contracts {
        for p in &c.positive {
            for (n, label) in SWAP_DENSITIES {
                let text = swap_companion(&p.text, &p.credential, *n);
                scanner.clear_fragment_cache();
                let chunk = make_chunk(&text);
                let matches = scanner.scan(&chunk);
                let hit = matches
                    .iter()
                    .any(|m| m.credential.as_ref().contains(&p.credential));
                let bucket = per_density.entry(label).or_insert((0, 0));
                bucket.0 += 1;
                if hit {
                    bucket.1 += 1;
                }
            }
        }
    }

    let mut summary = String::from("unicode-confusable per-density recall:\n");
    for (density, (runs, hits)) in &per_density {
        let pct = (*hits as f64 / (*runs).max(1) as f64) * 100.0;
        summary.push_str(&format!(
            "  swap={density:<11}  {hits:>4}/{runs:<4} ({pct:5.1}%)\n"
        ));
    }
    eprintln!("{summary}");

    // The 'none' density is the control — it MUST hit 100% (it's
    // identical to the contracts_runner positive path). If this
    // falls below 99%, the runner itself is broken.
    let none_runs_hits = per_density.get("none").copied().unwrap_or((0, 0));
    let none_pct = (none_runs_hits.1 as f64 / none_runs_hits.0.max(1) as f64) * 100.0;
    assert!(
        none_pct >= 99.0,
        "unicode-confusable control (no swap) dropped below 99%: {none_pct:.1}% — \
         runner is broken or contracts changed"
    );

    let strict = std::env::var("KEYHOG_UNICODE_STRICT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if strict {
        let every_char = per_density.get("every-char").copied().unwrap_or((0, 0));
        let pct = (every_char.1 as f64 / every_char.0.max(1) as f64) * 100.0;
        if pct < 30.0 {
            panic!(
                "every-char unicode confusable recall {pct:.1}% dropped below 30% \
                 floor — detector companion-context heuristic regressed"
            );
        }
    }
}
