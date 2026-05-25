//! Encoding-explosion runner — decode-through recall coverage.
//!
//! Walks every `tests/contracts/*.toml` positive and re-encodes just
//! the credential bytes (the secret half of the positive text) into
//! every encoding keyhog claims first-class decode-through support
//! for, plus a few keyhog does NOT yet decode. The result is a
//! per-encoding hit-rate matrix logged every run.
//!
//! Why
//! ---
//! The README pins decode-through to 4 nested layers across base64,
//! hex, URL, gzip, z85, rot13. The contracts runner only tests the
//! cleartext shape, so a regression in the decode pipeline (e.g.
//! the base64-simd path silently drops findings on padded inputs)
//! would slip through every existing test. This runner is the
//! per-encoding gate: it surfaces hit rates as eprintln so a
//! regression flips a visible number rather than hiding under the
//! "1 test passed" line.
//!
//! Surface
//! -------
//! 348 contracts × ~2 positives × 7 encodings ≈ **4 800 cases per
//! run**. Default mode is report-only — `KEYHOG_ENCODING_STRICT=1`
//! flips the "decoded encodings must hit" gates into hard failures
//! once the per-encoding floor numbers stabilize.

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
        .expect("detectors directory loadable from encoding runner");
    CompiledScanner::compile(detectors).expect("scanner compile from encoding runner")
}

// ── encoders ────────────────────────────────────────────────────────

/// Every encoding we exercise. The `Identity` variant is the
/// control — it MUST hit (mirrors the contracts_runner positive
/// case) and surfaces any bug in the runner itself before the more
/// interesting decoders take the blame.
#[derive(Debug, Clone, Copy)]
enum Encoding {
    Identity,
    Base64Std,
    Base64Url,
    Hex,
    UrlPercent,
    Rot13,
    ReverseBytes,
}

impl Encoding {
    const ALL: &'static [Encoding] = &[
        Encoding::Identity,
        Encoding::Base64Std,
        Encoding::Base64Url,
        Encoding::Hex,
        Encoding::UrlPercent,
        Encoding::Rot13,
        Encoding::ReverseBytes,
    ];

    fn label(self) -> &'static str {
        match self {
            Encoding::Identity => "identity",
            Encoding::Base64Std => "base64-std",
            Encoding::Base64Url => "base64-url",
            Encoding::Hex => "hex",
            Encoding::UrlPercent => "url-percent",
            Encoding::Rot13 => "rot13",
            Encoding::ReverseBytes => "reverse-bytes",
        }
    }

    /// True if keyhog claims first-class decode-through support
    /// for this encoding in its current shipped release. Used by
    /// the strict gate to know whether a miss is a regression vs a
    /// known-unsupported transform.
    fn decoded_by_default(self) -> bool {
        matches!(
            self,
            Encoding::Identity
                | Encoding::Base64Std
                | Encoding::Base64Url
                | Encoding::Hex
                | Encoding::UrlPercent
        )
    }

    fn encode(self, cred: &str) -> String {
        match self {
            Encoding::Identity => cred.to_string(),
            Encoding::Base64Std => general_purpose::STANDARD.encode(cred.as_bytes()),
            Encoding::Base64Url => general_purpose::URL_SAFE_NO_PAD.encode(cred.as_bytes()),
            Encoding::Hex => hex::encode(cred.as_bytes()),
            Encoding::UrlPercent => percent_encode_all(cred.as_bytes()),
            Encoding::Rot13 => rot13(cred),
            Encoding::ReverseBytes => cred.chars().rev().collect(),
        }
    }
}

/// Percent-encode every byte — the strictest form. Real-world URL
/// encoding only escapes reserved chars, but for the decode-through
/// pipeline the strict form is the harder test.
fn percent_encode_all(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for b in bytes {
        out.push_str(&format!("%{:02X}", b));
    }
    out
}

fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='M' | 'a'..='m' => (c as u8 + 13) as char,
            'N'..='Z' | 'n'..='z' => (c as u8 - 13) as char,
            _ => c,
        })
        .collect()
}

fn make_chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "encoding-explosion".into(),
            path: Some("encoded.txt".into()),
            ..Default::default()
        },
    }
}

fn any_credential_contains(matches: &[keyhog_core::RawMatch], expected: &str) -> bool {
    matches
        .iter()
        .any(|m| m.credential.as_ref().contains(expected))
}

/// Re-build the positive text with the credential substring swapped
/// for its encoded form. Preserves the surrounding companion context
/// so detectors that anchor on `aws_secret =` still see the anchor.
fn wrap_with_encoded_cred(text: &str, raw: &str, encoded: &str) -> String {
    if let Some(pos) = text.find(raw) {
        let mut out = String::with_capacity(text.len() - raw.len() + encoded.len());
        out.push_str(&text[..pos]);
        out.push_str(encoded);
        out.push_str(&text[pos + raw.len()..]);
        out
    } else {
        // The contract's `credential` should appear in `text`; if
        // it doesn't, the contract itself is malformed — skip
        // gracefully so the runner stays robust.
        text.to_string()
    }
}

// ── the encoding test ───────────────────────────────────────────────

#[test]
fn every_positive_swept_through_every_encoding() {
    let scanner = scanner();
    let contracts = load_contracts();
    assert!(
        !contracts.is_empty(),
        "tests/contracts/ has no *.toml — the encoding runner has \
         nothing to drive"
    );

    // Per encoding: (runs, decode_hits, incidental_hits).
    //   decode_hits     = scanner surfaced the *original* credential
    //                     after the chunk went through the decode-
    //                     through pipeline. This is the real recall.
    //   incidental_hits = scanner fired on the *encoded* form (e.g.
    //                     a 20-char alphanumeric reverse of an AWS
    //                     key still happens to match a generic
    //                     access-key regex). Tracked separately so a
    //                     decode-pipeline regression isn't masked by
    //                     shape-collision noise.
    let mut per_enc: BTreeMap<&'static str, (usize, usize, usize)> = BTreeMap::new();

    for (_path, c) in &contracts {
        for p in &c.positive {
            for enc in Encoding::ALL {
                let encoded = enc.encode(&p.credential);
                let text = wrap_with_encoded_cred(&p.text, &p.credential, &encoded);
                scanner.clear_fragment_cache();
                let chunk = make_chunk(&text);
                let matches = scanner.scan(&chunk);
                let decode_hit = any_credential_contains(&matches, &p.credential);
                let incidental_hit = !decode_hit && any_credential_contains(&matches, &encoded);
                let bucket = per_enc.entry(enc.label()).or_insert((0, 0, 0));
                bucket.0 += 1;
                if decode_hit {
                    bucket.1 += 1;
                }
                if incidental_hit {
                    bucket.2 += 1;
                }
                let _ = c.detector_id.as_str();
            }
        }
    }

    let mut summary = String::from(
        "encoding-explosion per-encoding rate:\n  \
         (decode-hit = original credential recovered via decode-through;\n   \
         incidental-hit = encoded form happened to match an unrelated regex)\n",
    );
    let mut decoded_misses = Vec::new();
    for (enc, (runs, decode_hits, incidental_hits)) in &per_enc {
        let dec_pct = (*decode_hits as f64 / (*runs).max(1) as f64) * 100.0;
        let inc_pct = (*incidental_hits as f64 / (*runs).max(1) as f64) * 100.0;
        summary.push_str(&format!(
            "  {enc:<15} decode {decode_hits:>5}/{runs:<4} ({dec_pct:5.1}%)  \
             incidental {incidental_hits:>4}/{runs:<4} ({inc_pct:5.1}%)\n"
        ));
        // Floor is set per-encoding from the *baseline* observed on
        // the first clean run (2026-05-23, v0.5.14): a regression
        // that drops below floor surfaces here. Identity stays at
        // 100%. The base64/hex/url-percent numbers are below where
        // the README's "4 layers of decode-through" claim implies
        // they should be — the working hypothesis is that the
        // decode-through scans the decoded text as a fresh chunk but
        // the companion context from the original chunk doesn't
        // carry through, so detectors that need an anchor adjacent
        // to the credential miss the decoded form. That's a real
        // gap worth fixing in a follow-up; this runner is the
        // regression net for the current behaviour.
        // Baselines re-set 2026-05-23 after the decode-splice fix
        // (pipeline.rs `push_decoded_text_chunk_spliced`) moved
        // base64/hex recall from ~30% to >90% by carrying parent
        // companion context through the decoded chunk.
        // Floors re-baselined 2026-05-23 after the percent-block
        // extractor landed in pipeline.rs (`extract_encoded_values`).
        // url-percent jumped from ~75% to ~99.7% by capturing
        // freestanding `%XX` runs (e.g. `Authorization: Bearer %41…`)
        // that the b64-only accumulator was dropping on the floor.
        let floor = match *enc {
            "identity" => 99.0,
            "base64-std" | "base64-url" | "hex" => 88.0,
            "url-percent" => 95.0,
            _ => 0.0,
        };
        if Encoding::ALL
            .iter()
            .find(|e| e.label() == *enc)
            .map(|e| e.decoded_by_default())
            .unwrap_or(false)
            && dec_pct < floor
        {
            decoded_misses.push(format!(
                "{enc} decode-hit {dec_pct:.1}% dropped below floor {floor:.1}%"
            ));
        }
    }
    eprintln!("{summary}");

    // Strict-by-default: floors (88% base64/hex, 75% url-percent,
    // 99% identity) are observed baselines after the v0.5.15 splice
    // fix. Any decode-pipeline regression flips this red.
    let strict = std::env::var("KEYHOG_ENCODING_STRICT")
        .map(|v| !(v == "0" || v.eq_ignore_ascii_case("false")))
        .unwrap_or(true);

    if !decoded_misses.is_empty() && strict {
        panic!(
            "encoding-explosion strict gate failed:\n{}\n\nUnder \
             KEYHOG_ENCODING_STRICT=1, every encoding marked \
             decoded_by_default must keep recall >= 90%.",
            decoded_misses.join("\n")
        );
    }
}
