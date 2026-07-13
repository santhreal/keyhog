//! CVE-corpus replay runner (single-file fixture variant).
//!
//! Loads `crates/scanner/tests/cve_corpus.toml`, a single TOML file
//! holding an `[[entry]]` array of public-disclosure / CVE shapes.
//! For each entry, drives the same `CompiledScanner` keyhog ships
//! against the entry's `fixture_text` and asserts at least one of
//! the surfaced findings has a `credential` that matches the entry's
//! `redacted_credential_pattern` (a Rust regex).
//!
//! This is intentionally distinct from `cve_replay_runner.rs`:
//!  - `cve_replay/` is one file per shape, asserts detector-id OR
//!    credential-contained semantics, and tracks per-detector recall
//!    on canonical leaks.
//!  - `cve_corpus.toml` is a single bundled fixture file that asserts
//!    against a regex pattern of the surfaced credential string, so
//!    "wrong detector_id but right shape" still counts as recall on
//!    a real-world leak, what matters at CVE-replay scale is that
//!    the BYTES of the leaked credential surface, not which label
//!    they surface under.
//!
//! Truth, not shape: if the scanner returned `Ok(())` with zero
//! findings, every entry would fail. The assertion checks a regex
//! over the surfaced `credential` substring, which the scanner only
//! produces by actually matching the planted secret.

mod support;
use support::paths::detector_dir;

use std::path::PathBuf;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use regex::Regex;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CorpusFile {
    schema_version: u32,
    entry: Vec<CorpusEntry>,
}

#[derive(Debug, Deserialize)]
struct CorpusEntry {
    cve_id: String,
    source_url: String,
    redacted_credential_pattern: String,
    fixture_text: String,
}

fn corpus_path() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("tests");
    d.push("cve_corpus.toml");
    d
}

fn load_corpus() -> CorpusFile {
    let path = corpus_path();
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    toml::from_str::<CorpusFile>(&text)
        .unwrap_or_else(|e| panic!("malformed {}: {e}", path.display()))
}

#[test]
fn cve_corpus_loads_with_expected_size() {
    // Truth-asserting structural gate: the corpus exists, parses, and
    // has the 10..20 entries the task pins. Returning `Ok(())` would
    // fail this because the file would not parse to a populated vec.
    let corpus = load_corpus();
    assert_eq!(
        corpus.schema_version, 1,
        "schema_version must be 1; bump intentionally with runner."
    );
    assert!(
        corpus.entry.len() >= 10 && corpus.entry.len() <= 20,
        "cve_corpus.toml must hold 10..=20 entries, found {}",
        corpus.entry.len(),
    );

    // Every entry's `redacted_credential_pattern` MUST compile as a
    // Rust regex; otherwise the per-entry truth test below is vacuous.
    for e in &corpus.entry {
        Regex::new(&e.redacted_credential_pattern).unwrap_or_else(|err| {
            panic!(
                "entry {} ({}) has uncompilable redacted_credential_pattern {:?}: {err}",
                e.cve_id, e.source_url, e.redacted_credential_pattern,
            )
        });
        assert!(
            !e.fixture_text.is_empty(),
            "entry {} has empty fixture_text",
            e.cve_id,
        );
        assert!(
            e.source_url.starts_with("https://") || e.source_url.starts_with("http://"),
            "entry {} source_url {:?} must be a URL",
            e.cve_id,
            e.source_url,
        );
    }
}

#[test]
fn every_cve_corpus_entry_surfaces_a_credential_matching_the_pattern() {
    let corpus = load_corpus();
    let detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("detectors directory loadable from cve_corpus_runner");
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    let mut failures: Vec<String> = Vec::new();
    for entry in &corpus.entry {
        let pattern = Regex::new(&entry.redacted_credential_pattern)
            .expect("pattern compiled in cve_corpus_loads_with_expected_size");

        let chunk = Chunk {
            data: entry.fixture_text.clone().into(),
            metadata: ChunkMetadata {
                // `contract.txt` matches the path the per-detector
                // contract runner uses, so any path-shape suppression
                // path is consistent with proven-positive contract
                // fixtures.
                source_type: "cve_corpus".into(),
                path: Some("contract.txt".into()),
                ..Default::default()
            },
        };
        let matches = scanner.scan(&chunk);

        // Truth: the regex must match the credential of at least one
        // surfaced finding. If the scanner returns zero findings, or
        // every finding's credential fails the regex, this fails.
        let hit = matches
            .iter()
            .any(|m| pattern.is_match(m.credential.as_ref()));

        if !hit {
            let surfaced: Vec<_> = matches
                .iter()
                .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
                .collect();
            failures.push(format!(
                "{} ({}): no finding.credential matched pattern {:?}. \
                 Scanner surfaced {:?}",
                entry.cve_id, entry.source_url, entry.redacted_credential_pattern, surfaced,
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "CVE corpus regressions ({} of {} entries failed):\n  - {}",
        failures.len(),
        corpus.entry.len(),
        failures.join("\n  - "),
    );
}

#[test]
fn cve_corpus_redacted_pattern_does_not_match_empty_or_arbitrary_text() {
    // Negative twin: every redacted_credential_pattern is a SHAPE
    // pattern, not "anything". If a pattern matched the empty string,
    // a synthetic "" credential surfaced by an over-broad detector
    // would silently satisfy the positive test. This guards against
    // that class of accidentally-vacuous patterns.
    let corpus = load_corpus();
    for entry in &corpus.entry {
        let pattern = Regex::new(&entry.redacted_credential_pattern).unwrap();
        assert!(
            !pattern.is_match(""),
            "{}: redacted_credential_pattern {:?} matches empty string \
             (would let the positive test pass trivially)",
            entry.cve_id,
            entry.redacted_credential_pattern,
        );
        assert!(
            !pattern.is_match("the quick brown fox jumps over the lazy dog"),
            "{}: redacted_credential_pattern {:?} matches arbitrary prose \
             (would let any finding satisfy it)",
            entry.cve_id,
            entry.redacted_credential_pattern,
        );
    }
}
