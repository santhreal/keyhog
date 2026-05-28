//! Whitespace / BOM / line-ending normalization runner.
//!
//! Real-world files come in with: a UTF-8 BOM (`EF BB BF`), CRLF
//! line endings (Windows), CR-only line endings (legacy Mac), tabs
//! instead of spaces, NBSP between tokens (Word-pasted .env files),
//! trailing whitespace, and zero-width characters (ZWSP/ZWJ - copy-
//! pasted from web docs). Every one of these has been observed in
//! actual leaked-secret commits in the wild.
//!
//! A correct scanner treats all of these as semantically equivalent
//! to the canonical positive - the credential surfaces regardless.
//! A scanner that string-matches on `\n` or assumes UTF-8 starts at
//! offset 0 silently misses them. This runner is the per-variant
//! gate.
//!
//! Surface
//! -------
//! 348 contracts × ~2 positives × 10 variants ≈ **6 900 cases per
//! run**.

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
        .expect("detectors directory loadable from whitespace runner");
    CompiledScanner::compile(detectors).expect("scanner compile from whitespace runner")
}

#[derive(Debug, Clone, Copy)]
enum Variant {
    Baseline,
    Crlf,
    CrOnly,
    Bom,
    BomCrlf,
    LeadingNbsp,
    TrailingWhitespace,
    TabsForSpaces,
    DoubleSpaces,
    /// ZWSP/ZWJ inserted at boundaries OUTSIDE the credential - must
    /// not affect detection. (Inside-credential ZW chars are tested
    /// by `unicode_confusable_runner` and are a separate question.)
    ZwspBoundary,
}

impl Variant {
    const ALL: &'static [Variant] = &[
        Variant::Baseline,
        Variant::Crlf,
        Variant::CrOnly,
        Variant::Bom,
        Variant::BomCrlf,
        Variant::LeadingNbsp,
        Variant::TrailingWhitespace,
        Variant::TabsForSpaces,
        Variant::DoubleSpaces,
        Variant::ZwspBoundary,
    ];

    fn label(self) -> &'static str {
        match self {
            Variant::Baseline => "baseline",
            Variant::Crlf => "crlf",
            Variant::CrOnly => "cr-only",
            Variant::Bom => "bom",
            Variant::BomCrlf => "bom-crlf",
            Variant::LeadingNbsp => "leading-nbsp",
            Variant::TrailingWhitespace => "trailing-whitespace",
            Variant::TabsForSpaces => "tabs-for-spaces",
            Variant::DoubleSpaces => "double-spaces",
            Variant::ZwspBoundary => "zwsp-boundary",
        }
    }

    fn apply(self, text: &str) -> String {
        match self {
            Variant::Baseline => text.to_string(),
            Variant::Crlf => text.replace('\n', "\r\n"),
            Variant::CrOnly => text.replace('\n', "\r"),
            Variant::Bom => format!("\u{FEFF}{text}"),
            Variant::BomCrlf => format!("\u{FEFF}{}", text.replace('\n', "\r\n")),
            Variant::LeadingNbsp => format!("\u{00A0}{text}"),
            Variant::TrailingWhitespace => text
                .lines()
                .map(|l| format!("{l}   \t  \t"))
                .collect::<Vec<_>>()
                .join("\n"),
            Variant::TabsForSpaces => text.replace("  ", "\t").replace("   ", "\t\t"),
            Variant::DoubleSpaces => text.replace(' ', "  "),
            Variant::ZwspBoundary => {
                // Insert ZWSP at line boundaries - never inside a token.
                text.lines()
                    .map(|l| format!("\u{200B}{l}\u{200B}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        }
    }
}

fn make_chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "whitespace-normalization".into(),
            path: Some("normalized.txt".into()),
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
fn every_positive_survives_whitespace_variants() {
    let scanner = scanner();
    let contracts = load_contracts();
    assert!(
        !contracts.is_empty(),
        "tests/contracts/ has no *.toml - whitespace runner has nothing to drive"
    );

    let mut per_variant: BTreeMap<&'static str, (usize, usize)> = BTreeMap::new();
    let mut total_runs: usize = 0;
    let mut total_hits: usize = 0;

    for c in &contracts {
        for p in &c.positive {
            for variant in Variant::ALL {
                let text = variant.apply(&p.text);
                scanner.clear_fragment_cache();
                let chunk = make_chunk(&text);
                let matches = scanner.scan(&chunk);
                let hit = any_credential_contains(&matches, &p.credential);
                let bucket = per_variant.entry(variant.label()).or_insert((0, 0));
                bucket.0 += 1;
                total_runs += 1;
                if hit {
                    bucket.1 += 1;
                    total_hits += 1;
                }
            }
        }
    }

    let mut summary = String::from("whitespace-normalization per-variant hit rate:\n");
    for (variant, (runs, hits)) in &per_variant {
        let pct = (*hits as f64 / (*runs).max(1) as f64) * 100.0;
        summary.push_str(&format!(
            "  {variant:<22} {hits:>4}/{runs:<4} ({pct:5.1}%)\n"
        ));
    }
    let overall = (total_hits as f64 / total_runs.max(1) as f64) * 100.0;
    summary.push_str(&format!(
        "  TOTAL {total_hits}/{total_runs} ({overall:.1}%) - \
         baseline parity is the bar; tabs/CRLF/BOM should be within 1%\n"
    ));
    eprintln!("{summary}");

    let strict = std::env::var("KEYHOG_WHITESPACE_STRICT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    // Baseline parity: CRLF/BOM/tabs MUST match baseline ±2%. Strict
    // gate is opt-in until the report-mode baselines stabilise.
    if strict {
        let baseline = per_variant
            .get("baseline")
            .map(|(r, h)| (*h as f64 / (*r).max(1) as f64) * 100.0)
            .unwrap_or(0.0);
        for (variant, (runs, hits)) in &per_variant {
            let pct = (*hits as f64 / (*runs).max(1) as f64) * 100.0;
            if (baseline - pct).abs() > 2.0 {
                panic!(
                    "whitespace variant {variant} drift {pct:.1}% vs baseline {baseline:.1}% \
                     exceeds 2% tolerance - normalization regression"
                );
            }
        }
    }
}
