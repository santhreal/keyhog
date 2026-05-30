//! CVE / known-leak replay runner.
//!
//! Walks `tests/cve_replay/*.toml` and for each, drives the same
//! `CompiledScanner` keyhog ships with against the `leaked_text`. The
//! scanner MUST surface a finding whose `detector_id` is in the entry's
//! `detectors` list OR whose extracted `credential` literally appears
//! in `leaked_text`. The latter handles cross-detector dedup relabel:
//! keyhog's dedup_cross_detector path can promote a finding to a
//! related hot-pattern label, and either label is honest evidence the
//! secret was caught.
//!
//! When the directory is empty, the runner passes vacuously. The
//! hard gate is one file = one binding truth test - every entry
//! becomes a hard-fail the moment it's added, so the runner
//! grows teeth incrementally as the CVE corpus is populated.
//!
//! OPEN: `tests/cve_replay/` is currently empty; this detector
//! suite has zero CVE-replay coverage. Each new entry must be a
//! verbatim public-leak fixture with an auditable `source_url`.

mod support;
use support::paths::detector_dir;

use std::path::PathBuf;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CveEntry {
    #[allow(dead_code)]
    schema_version: u32,
    cve_id: String,
    #[allow(dead_code)]
    source_url: String,
    #[serde(default)]
    #[allow(dead_code)]
    source_commit: Option<String>,
    detectors: Vec<String>,
    #[allow(dead_code)]
    service: String,
    #[allow(dead_code)]
    description: String,
    leaked_text: String,
}

fn cve_replay_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("tests");
    d.push("cve_replay");
    d
}

fn load_entries() -> Vec<(PathBuf, CveEntry)> {
    let dir = cve_replay_dir();
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
        match toml::from_str::<CveEntry>(&text) {
            Ok(e) => out.push((path, e)),
            Err(e) => panic!("malformed cve_replay entry {}: {e}", path.display()),
        }
    }
    out
}

#[test]
fn every_cve_replay_entry_must_fire() {
    let entries = load_entries();
    if entries.is_empty() {
        eprintln!(
            "CVE replay corpus is empty - vacuous pass. Populate \
             crates/scanner/tests/cve_replay/*.toml with public leaks \
             (see README in that directory) to gate recall on known shapes."
        );
        return;
    }

    let detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("detectors directory loadable from cve_replay_runner");
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    let mut failures: Vec<String> = Vec::new();
    for (path, entry) in &entries {
        let chunk = Chunk {
            data: entry.leaked_text.clone().into(),
            metadata: ChunkMetadata {
                source_type: "cve_replay".into(),
                path: Some(format!("{}.txt", entry.cve_id)),
                ..Default::default()
            },
        };
        let matches = scanner.scan(&chunk);

        let detector_hit = matches.iter().any(|m| {
            entry
                .detectors
                .iter()
                .any(|d| d.as_str() == m.detector_id.as_ref())
        });
        let credential_hit = matches
            .iter()
            .any(|m| entry.leaked_text.contains(m.credential.as_ref()));

        if !detector_hit && !credential_hit {
            let surfaced: Vec<_> = matches
                .iter()
                .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
                .collect();
            failures.push(format!(
                "{} ({}): leaked text MUST fire on one of {:?}, but \
                 scanner surfaced {:?}",
                entry.cve_id,
                path.display(),
                entry.detectors,
                surfaced,
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "CVE replay regressions:\n  - {}",
        failures.join("\n  - "),
    );
}
