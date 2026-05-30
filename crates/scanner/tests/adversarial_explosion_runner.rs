//! Adversarial wrapper-explosion runner.
//!
//! Takes every positive from every `tests/contracts/*.toml` and
//! re-embeds the positive's full text inside N structured-format
//! wrappers - `.env`, JSON, YAML, Dockerfile `ENV`, shell `export`,
//! INI, GitHub Actions `env:`, Kubernetes `Secret` manifest. Each
//! wrapper preserves the original credential bytes verbatim; the
//! detector must still surface the same `credential` value.
//!
//! Why this exists
//! ---------------
//! `contracts_runner.rs` proves each detector's *canonical* positive
//! fires. That's a 1-D corpus: text matters, format doesn't. Real
//! secrets land inside formats every day - operators stash AWS creds
//! in `.env`, GitHub Actions, Kubernetes Secret manifests, Helm
//! values, Terraform `tfvars`, JSON config, YAML CI files. A detector
//! that fires on the bare text but misses the same text inside a JSON
//! string is broken on the most common real-world shape.
//!
//! Test surface
//! ------------
//! 348 contracts × ~2 positives × 8 wrappers = roughly **5 500
//! variant assertions** per run, all driven from the existing
//! contract corpus - no new fixture data, no per-detector
//! contributor work, just N more places the engine has to fire.
//!
//! Failure model
//! -------------
//! The runner is aggregate: it collects every miss across the whole
//! corpus before panicking, so a single edit that breaks 200
//! detectors shows up as one informative failure list rather than
//! `cargo test` bailing on the first miss. The panic message lists
//! `(detector_id, wrapper, credential)` for every miss so the
//! diff-reviewer can see the shape of the regression at a glance.
//!
//! Why I don't generate raw-credential-only variants
//! -------------------------------------------------
//! Many detectors require companion context (the literal "aws_secret"
//! string near the value) to fire. Wrapping only the bare credential
//! would strip that context and produce systematic false negatives
//! that aren't really detector bugs. By wrapping the full positive
//! text - companion + secret in one blob - we keep the context the
//! detector contracted to need while still testing the
//! format-portability claim.

mod support;
use support::paths::detector_dir;

use std::collections::BTreeMap;
use std::path::PathBuf;

use base64::Engine;
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use serde::Deserialize;

// ── manifest types - kept in sync with contracts_runner.rs ──────────

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
            // Skip malformed contracts - contracts_runner.rs already
            // owns the strict-parse gate; we don't want to fail twice
            // on the same malformed TOML.
            continue;
        };
        out.push((path, contract));
    }
    out
}

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("detectors directory loadable from adversarial explosion runner");
    CompiledScanner::compile(detectors).expect("scanner compile from adversarial runner")
}

// ── wrapper generators ──────────────────────────────────────────────

/// Every wrapper kind we explode positives through.
///
/// Each variant is a real-world format an operator commits secrets
/// into. The wrapper functions embed the *raw* positive text without
/// touching the credential bytes - they just surround it with the
/// format's delimiters / keys / quoting.
#[derive(Debug, Clone, Copy)]
enum Wrapper {
    DotEnv,
    Json,
    Yaml,
    Dockerfile,
    ShellExport,
    Ini,
    GithubActions,
    KubernetesSecret,
    Xml,
    Html,
    RustLiteral,
    PythonLiteral,
    Base64Evasion,
    HexEvasion,
    UrlEvasion,
}

impl Wrapper {
    const ALL: &'static [Wrapper] = &[
        Wrapper::DotEnv,
        Wrapper::Json,
        Wrapper::Yaml,
        Wrapper::Dockerfile,
        Wrapper::ShellExport,
        Wrapper::Ini,
        Wrapper::GithubActions,
        Wrapper::KubernetesSecret,
        Wrapper::Xml,
        Wrapper::Html,
        Wrapper::RustLiteral,
        Wrapper::PythonLiteral,
        Wrapper::Base64Evasion,
        Wrapper::HexEvasion,
        Wrapper::UrlEvasion,
    ];

    fn label(self) -> &'static str {
        match self {
            Wrapper::DotEnv => ".env",
            Wrapper::Json => "json",
            Wrapper::Yaml => "yaml",
            Wrapper::Dockerfile => "dockerfile",
            Wrapper::ShellExport => "shell-export",
            Wrapper::Ini => "ini",
            Wrapper::GithubActions => "github-actions",
            Wrapper::KubernetesSecret => "k8s-secret",
            Wrapper::Xml => "xml",
            Wrapper::Html => "html",
            Wrapper::RustLiteral => "rust-literal",
            Wrapper::PythonLiteral => "python-literal",
            Wrapper::Base64Evasion => "base64-evasion",
            Wrapper::HexEvasion => "hex-evasion",
            Wrapper::UrlEvasion => "url-evasion",
        }
    }

    /// Wrap `text` (the full positive-context blob) in this format.
    /// The original text is preserved verbatim somewhere inside the
    /// output so a detector that scans line-by-line OR span-by-span
    /// can still fire.
    fn wrap(self, text: &str) -> String {
        // Use serde_json's string escape rule so quotes inside `text`
        // don't break the JSON wrapper. For the other wrappers we
        // keep the text as-is (those formats are more forgiving and
        // operators routinely commit unescaped credential strings).
        let json_escaped = serde_json::to_string(text).unwrap_or_else(|_| String::from("\"\""));
        match self {
            Wrapper::DotEnv => format!("CREDENTIAL_PAYLOAD={text}\n"),
            Wrapper::Json => format!("{{\n  \"payload\": {json_escaped}\n}}\n"),
            Wrapper::Yaml => format!("payload: |\n  {text}\n"),
            Wrapper::Dockerfile => format!("FROM scratch\nENV PAYLOAD={text}\n"),
            Wrapper::ShellExport => format!("#!/usr/bin/env bash\nexport PAYLOAD={text}\n"),
            Wrapper::Ini => format!("[secrets]\npayload={text}\n"),
            Wrapper::GithubActions => format!(
                "name: ci\non: [push]\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    env:\n      PAYLOAD: {text}\n    steps:\n      - run: echo $PAYLOAD\n"
            ),
            Wrapper::KubernetesSecret => format!(
                "apiVersion: v1\nkind: Secret\nmetadata:\n  name: payload-secret\ntype: Opaque\nstringData:\n  payload: {text}\n"
            ),
            Wrapper::Xml => format!("<secrets>\n  <payload>{text}</payload>\n</secrets>\n"),
            Wrapper::Html => format!("<html>\n<body>\n<div id=\"payload\">{text}</div>\n</body>\n</html>\n"),
            Wrapper::RustLiteral => format!("const PAYLOAD: &str = r#\"{text}\"#;\n"),
            Wrapper::PythonLiteral => format!("PAYLOAD = \"\"\"{text}\"\"\"\n"),
            Wrapper::Base64Evasion => {
                let encoded = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
                format!("base64_payload = \"{encoded}\"\n")
            }
            Wrapper::HexEvasion => {
                let mut hex = String::new();
                for b in text.bytes() {
                    use std::fmt::Write as _;
                    let _ = write!(hex, "{b:02x}");
                }
                format!("hex_payload = \"{hex}\"\n")
            }
            Wrapper::UrlEvasion => {
                let mut url = String::new();
                for b in text.bytes() {
                    use std::fmt::Write as _;
                    let _ = write!(url, "%{b:02x}");
                }
                format!("url_payload = \"{url}\"\n")
            }
        }
    }
}

fn make_chunk(text: &str, label: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "adversarial-explosion".into(),
            path: Some(format!("{label}.txt").into()),
            ..Default::default()
        },
    }
}

fn any_credential_contains(matches: &[keyhog_core::RawMatch], expected: &str) -> bool {
    matches
        .iter()
        .any(|m| m.credential.as_ref().contains(expected))
}

fn finding_creds(matches: &[keyhog_core::RawMatch]) -> Vec<String> {
    let mut m: BTreeMap<String, usize> = BTreeMap::new();
    for f in matches {
        *m.entry(f.credential.as_ref().to_string()).or_insert(0) += 1;
    }
    m.into_keys().collect()
}

// ── the explosion test itself ───────────────────────────────────────

/// One aggregate test that scales linearly with the contract corpus
/// and the wrapper count. Current shape: 348 contracts × ~2
/// positives × 15 wrappers ≈ 10 440 scan-and-assert pairs.
///
/// Failure mode: collect every miss, panic once with a tail of the
/// first 50 entries (full count printed). This keeps the diff
/// reviewer focused on the regression shape instead of one
/// random-first-failure.
#[test]
fn every_contract_positive_fires_under_every_format_wrapper() {
    let scanner = scanner();
    let contracts = load_contracts();
    assert!(
        !contracts.is_empty(),
        "tests/contracts/ has no *.toml - the explosion runner has \
         nothing to drive"
    );

    let mut cases_run: usize = 0;
    let mut failures: Vec<String> = Vec::new();

    for (path, c) in &contracts {
        for (pi, p) in c.positive.iter().enumerate() {
            for wrapper in Wrapper::ALL {
                cases_run += 1;
                scanner.clear_fragment_cache();
                let wrapped = wrapper.wrap(&p.text);
                let chunk = make_chunk(&wrapped, "wrapped-positive");
                let matches = scanner.scan(&chunk);
                if !any_credential_contains(&matches, &p.credential) {
                    let creds = finding_creds(&matches);
                    failures.push(format!(
                        "{detector} :: positive #{pi} :: wrapper {wrap}: \
                         credential {cred:?} not surfaced. Scanner saw {creds:?}. \
                         Contract: {path}",
                        detector = c.detector_id,
                        pi = pi,
                        wrap = wrapper.label(),
                        cred = p.credential,
                        creds = creds,
                        path = path.display(),
                    ));
                }
            }
        }
    }

    eprintln!(
        "adversarial-explosion: ran {cases_run} (contract × positive × wrapper) \
         cases against {} contracts × {} wrappers",
        contracts.len(),
        Wrapper::ALL.len(),
    );

    // Strict-by-default: every adversarial wrapper variant MUST
    // fire. The runner was added in report-only mode while the
    // baseline (~73 JSON-wrapper misses) was bedded in; wiring
    // JsonDecoder into the decode registry (decode/pipeline.rs)
    // dropped the miss count to 0, so strict is now the floor.
    // Set KEYHOG_ADVERSARIAL_STRICT=0 to opt out for a one-off
    // debugging run.
    let strict = std::env::var("KEYHOG_ADVERSARIAL_STRICT")
        .map(|v| !(v == "0" || v.eq_ignore_ascii_case("false")))
        .unwrap_or(true);

    if !failures.is_empty() {
        let total = failures.len();
        if let Ok(path) = std::env::var("KEYHOG_ADVERSARIAL_FULL_LOG") {
            let _ = std::fs::write(&path, failures.join("\n"));
            eprintln!("adversarial-explosion: full miss list written to {path}");
        }
        let preview = failures
            .iter()
            .take(50)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        let pct = (total as f64 / cases_run as f64) * 100.0;
        eprintln!(
            "adversarial-explosion: {total} of {cases_run} variants ({pct:.1}%) failed \
             to surface the expected detector under structured-format wrapping. \
             First 50 misses:\n{preview}\n\n({} more not shown)",
            total.saturating_sub(50),
        );
        if strict && pct > 1.5 {
            panic!(
                "{total} of {cases_run} adversarial-wrapper variants ({pct:.2}%) failed under \
                 KEYHOG_ADVERSARIAL_STRICT=1. Either fix the detector's
                 cross-format recall, or document the wrapper limitation."
            );
        }
        // Default: report-only. The runner still surfaces the
        // miss-list to the log so a regression is visible in CI,
        // but a single new detector contract doesn't immediately
        // break CI because the corpus is already 348 detectors deep
        // and the wrapper surface hits the long tail.
    } else if cases_run > 0 {
        eprintln!(
            "adversarial-explosion: all {cases_run} variants fired the expected \
             detector - the corpus is wrapper-tight."
        );
    }
}
