//! Compound-encoding runner — on-demand diagnostic for N-layer nested
//! decoding. NOT a `cargo test` gate.
//!
//! Real secrets pass through several encoding layers before they reach git: a
//! k8s `Secret` base64-encodes the value, the manifest is YAML, that YAML is
//! embedded in a JSON blob, the JSON is stuffed in a `.env`. The single-layer
//! `encoding_explosion_runner` proves one layer survives; this probe reports
//! the decode-hit rate across all two-layer encoding pairs, the empirical read
//! on the README's "decode 4 layers" claim.
//!
//! Why `#[ignore]` and not a gate (T-01)
//! -------------------------------------
//! Encoding the credential and asking whether keyhog re-derives it is a decode
//! RECALL RATE over a corpus; detection-accuracy rates are owned by the
//! differential bench (`benchmarks/bench`), never asserted in `cargo test`
//! (`backlog/testing.md` T-01). It is also not a sound all-or-nothing contract:
//! the decode pipeline decides whether to recurse from what each decoded layer
//! looks like, so a given two-layer pair legitimately may or may not round-trip
//! without that being a bug. Single-layer decode BEHAVIOR on known inputs is
//! covered by the decode unit tests; this file stays a report-only probe, run
//! explicitly with `--ignored --nocapture`.

mod support;
use support::contracts::{load_contracts, make_chunk, scanner, surfaces};

use std::collections::BTreeMap;

use base64::{engine::general_purpose, Engine as _};

const SOURCE_TYPE: &str = "compound-encoding";

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

#[test]
#[ignore = "measurement: two-layer decode recall over the contract corpus; rates are owned by the bench (T-01). Run with --ignored --nocapture"]
fn two_layer_decode_sweep() {
    let scanner = scanner();
    let contracts = load_contracts();

    let mut per_pair: BTreeMap<(&'static str, &'static str), (usize, usize)> = BTreeMap::new();
    let mut total_runs = 0usize;
    let mut total_hits = 0usize;

    for c in &contracts {
        for p in &c.positive {
            for inner in Layer::ALL {
                for outer in Layer::ALL {
                    // Skip self-pairs: base64(base64(x)) is covered by the decode
                    // pipeline's recursion against the single-layer corpus.
                    if inner.label() == outer.label() {
                        continue;
                    }
                    let inner_encoded = inner.encode(&p.credential);
                    let outer_encoded = outer.encode(&inner_encoded);
                    let text = wrap_with_encoded_cred(&p.text, &p.credential, &outer_encoded);
                    let chunk = make_chunk(&text, SOURCE_TYPE, "compound.txt");
                    let hit = surfaces(&scanner, &chunk, &p.credential);
                    let bucket = per_pair.entry((outer.label(), inner.label())).or_insert((0, 0));
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

    let mut summary =
        String::from("compound-encoding per (outer ∘ inner) pair decode-hit rate (diagnostic):\n");
    for ((outer, inner), (runs, hits)) in &per_pair {
        let pct = (*hits as f64 / (*runs).max(1) as f64) * 100.0;
        summary.push_str(&format!(
            "    {outer:<14} ∘ {inner:<14} {hits:>4}/{runs:<4} ({pct:5.1}%)\n"
        ));
    }
    let overall = (total_hits as f64 / total_runs.max(1) as f64) * 100.0;
    summary.push_str(&format!(
        "    TOTAL {total_hits}/{total_runs} ({overall:.1}%) across {} pairs\n",
        per_pair.len(),
    ));
    eprintln!("{summary}");
}
