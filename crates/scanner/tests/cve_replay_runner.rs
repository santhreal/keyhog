//! CVE / known-leak replay runner.
//!
//! Walks `tests/cve_replay/*.toml` and for each, drives the same
//! `CompiledScanner` keyhog ships with against the `leaked_text`. The
//! scanner MUST surface a finding whose `detector_id` is in the entry's
//! `detectors` list OR whose extracted `credential` literally appears
//! in `leaked_text`. The latter keeps overlapping detector ownership from
//! making the replay brittle while all reported ids remain canonical.
//!
//! The replay corpus is a hard gate, not a vacuous directory walk:
//! deleting fixtures, breaking the directory, or adding malformed
//! TOML fails before scanning.

mod support;
use support::paths::detector_dir;

use std::path::PathBuf;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use serde::Deserialize;

const MIN_CVE_REPLAY_ENTRIES: usize = 4;

#[derive(Debug, Deserialize)]
struct CveEntry {
    schema_version: u32,
    cve_id: String,
    source_url: String,
    #[serde(default)]
    source_commit: Option<String>,
    detectors: Vec<String>,
    service: String,
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
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read cve_replay directory {}: {e}", dir.display()));
    for entry in entries {
        let entry = entry
            .unwrap_or_else(|e| panic!("read cve_replay directory entry {}: {e}", dir.display()));
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read cve_replay entry {}: {e}", path.display()));
        match toml::from_str::<CveEntry>(&text) {
            Ok(e) => {
                validate_entry(&path, &e);
                out.push((path, e));
            }
            Err(e) => panic!("malformed cve_replay entry {}: {e}", path.display()),
        }
    }
    out.sort_by(|(left, _), (right, _)| left.cmp(right));
    out
}

fn validate_entry(path: &std::path::Path, entry: &CveEntry) {
    assert_eq!(
        entry.schema_version,
        1,
        "{}: cve_replay schema_version must be 1",
        path.display()
    );
    assert!(
        !entry.cve_id.trim().is_empty(),
        "{}: cve_id must be present",
        path.display()
    );
    assert!(
        entry.source_url.starts_with("https://"),
        "{}: source_url must be an auditable https URL",
        path.display()
    );
    if let Some(commit) = &entry.source_commit {
        assert!(
            !commit.trim().is_empty(),
            "{}: source_commit must be omitted or non-empty",
            path.display()
        );
    }
    assert!(
        !entry.detectors.is_empty(),
        "{}: at least one expected detector id is required",
        path.display()
    );
    assert!(
        entry.detectors.iter().all(|d| !d.trim().is_empty()),
        "{}: detector ids must be non-empty",
        path.display()
    );
    assert!(
        !entry.service.trim().is_empty(),
        "{}: service must be present",
        path.display()
    );
    assert!(
        !entry.description.trim().is_empty(),
        "{}: description must be present",
        path.display()
    );
    assert!(
        !entry.leaked_text.trim().is_empty(),
        "{}: leaked_text must contain the replay fixture",
        path.display()
    );
}

#[test]
fn every_cve_replay_entry_must_fire() {
    let entries = load_entries();
    assert!(
        entries.len() >= MIN_CVE_REPLAY_ENTRIES,
        "CVE replay corpus shrank to {} entries; expected at least \
         {MIN_CVE_REPLAY_ENTRIES} public-leak fixtures",
        entries.len()
    );

    let detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("detectors directory loadable from cve_replay_runner");
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    let mut failures: Vec<String> = Vec::new();
    for (path, entry) in &entries {
        let chunk = Chunk {
            data: entry.leaked_text.clone().into(),
            metadata: ChunkMetadata {
                source_type: "cve_replay".into(),
                path: Some(format!("{}.txt", entry.cve_id).into()),
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
