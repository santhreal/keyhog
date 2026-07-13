//! Unicode-confusable runner (homoglyph evasion coverage).
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
//! contract positive (never the credential itself).
//!
//! BEHAVIOR contract, not an accuracy rate
//! ---------------------------------------
//! The gate asserts a sound PROPERTY, all-or-nothing, never a
//! recall/precision *rate* over the corpus:
//!
//!   *credential-sufficiency invariance*, if a detector fires on the
//!   credential ALONE (it does not need the companion context), then
//!   homoglyphing the companion CANNOT break it at any swap density.
//!   Every such positive MUST surface its credential at every density.
//!
//! Positives whose detector REQUIRES companion context (the credential
//! alone does not fire) are a different question: how well unicode
//! normalization *recovers* a homoglyphed anchor is genuine evasion
//! ACCURACY, measured by the differential bench, it is recorded here
//! for visibility but never gated, because forcing it to 100% would be
//! asserting an accuracy rate in `cargo test` (T-01).

mod support;
use support::paths::detector_dir;

use std::collections::BTreeMap;
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
        // Cyrillic look-alikes (the canonical attack class).
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
/// the positive text, never the credential bytes. Locates the
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

fn surfaces(scanner: &CompiledScanner, text: &str, credential: &str) -> bool {
    scanner.clear_fragment_cache();
    let matches = scanner.scan(&make_chunk(text));
    matches
        .iter()
        .any(|m| m.credential.as_ref().contains(credential))
}

/// (swap_every, label) (every Nth confusable-eligible char swapped).
/// `0` is the no-swap control. `1` is the strongest evasion.
const SWAP_DENSITIES: &[(usize, &str)] = &[(1, "every-char"), (2, "every-2nd"), (4, "every-4th")];

/// BEHAVIOR gate: a detector that fires on the credential ALONE must
/// remain swap-invariant, homoglyphing companion context it does not
/// use cannot drop it. All-or-nothing, no rate. Companion-required
/// positives are recorded but not gated (evasion accuracy → bench).
#[test]
fn credential_sufficient_detectors_are_swap_invariant() {
    let scanner = scanner();
    let contracts = load_contracts();
    assert!(
        !contracts.is_empty(),
        "tests/contracts/ has no *.toml, unicode runner has nothing to drive"
    );

    let mut credential_sufficient = 0usize;
    let mut companion_required = 0usize;
    let mut companion_recovered = 0usize; // recovered via normalization despite swap
    let mut companion_runs = 0usize;
    let mut violations: Vec<String> = Vec::new();

    for c in &contracts {
        for p in &c.positive {
            // Does the credential surface on its own, with no companion?
            let credential_only = surfaces(&scanner, &p.credential, &p.credential);

            if credential_only {
                credential_sufficient += 1;
                for (n, label) in SWAP_DENSITIES {
                    let text = swap_companion(&p.text, &p.credential, *n);
                    if !surfaces(&scanner, &text, &p.credential) {
                        violations.push(format!(
                            "{detector}: credential fires standalone but was DROPPED at \
                             swap={label} (homoglyphing unused companion context broke it). \
                             credential={cred:?}",
                            detector = c.detector_id,
                            cred = p.credential,
                        ));
                    }
                }
            } else {
                companion_required += 1;
                for (n, _label) in SWAP_DENSITIES {
                    companion_runs += 1;
                    let text = swap_companion(&p.text, &p.credential, *n);
                    if surfaces(&scanner, &text, &p.credential) {
                        companion_recovered += 1;
                    }
                }
            }
        }
    }

    // Informational only, the companion-recovery rate is evasion
    // ACCURACY (how well normalization rescues a homoglyphed anchor),
    // owned by the differential bench, never a cargo-test gate.
    let recovery = if companion_runs > 0 {
        (companion_recovered as f64 / companion_runs as f64) * 100.0
    } else {
        100.0
    };
    eprintln!(
        "unicode-confusable: {credential_sufficient} credential-sufficient positives \
         (gated swap-invariant), {companion_required} companion-required positives \
         (normalization recovered {companion_recovered}/{companion_runs} = {recovery:.1}%, \
         informational)"
    );

    assert!(
        violations.is_empty(),
        "unicode credential-sufficiency invariance violated ({} cases): a detector that \
         fires on the bare credential must not be broken by homoglyphing companion \
         context it does not depend on:\n  - {}",
        violations.len(),
        violations.join("\n  - "),
    );
}

/// Control: the no-swap path must reproduce the contract-runner
/// positive exactly. If this drops, the runner harness (not the
/// engine) is broken.
#[test]
fn no_swap_control_matches_contract_positives() {
    let scanner = scanner();
    let contracts = load_contracts();

    let mut per_outcome: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut misses: Vec<String> = Vec::new();
    let mut total = 0usize;

    for c in &contracts {
        for p in &c.positive {
            total += 1;
            // density 0 == identical bytes to the contract positive.
            let text = swap_companion(&p.text, &p.credential, 0);
            assert_eq!(
                text, p.text,
                "swap_every=0 must be a byte-identical no-op for {}",
                c.detector_id
            );
            if surfaces(&scanner, &text, &p.credential) {
                *per_outcome.entry("hit").or_default() += 1;
            } else {
                *per_outcome.entry("miss").or_default() += 1;
                misses.push(format!("{}: {:?}", c.detector_id, p.credential));
            }
        }
    }

    let hits = per_outcome.get("hit").copied().unwrap_or(0);
    eprintln!("unicode no-swap control: {hits}/{total} contract positives surfaced");
    assert!(
        misses.is_empty(),
        "no-swap control dropped {} contract positive(s), the runner is mutating bytes it \
         must not, or the contract corpus changed:\n  - {}",
        misses.len(),
        misses.join("\n  - "),
    );
}
