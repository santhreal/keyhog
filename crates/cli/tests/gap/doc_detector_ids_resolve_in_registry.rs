//! MC-10 / DF-02 guard — shipped docs must not name a detector id/file that the
//! registry can't resolve.
//!
//! DF-02 hit `keyhog explain aws-access-key-id` → exit 2 "no detector with id":
//! `FP_AUDIT_REPORT.md` cited an id (`aws-access-key-id`) that had drifted from
//! the canonical registry id (`aws-access-key`). A doc that names a non-resolving
//! detector is a coherence bug — a reader who copies the id into `keyhog explain`
//! gets an error, and an audit keyed on a dead id silently audits nothing.
//!
//! Detector files are named `<id>.toml` (the file stem IS the canonical id), so a
//! `detectors/<stem>.toml` reference in a doc is an implicit id claim. This guard
//! extracts every such reference from the shipped Markdown docs and asserts each
//! stem resolves to an embedded detector whose `id == stem` — exactly what
//! `keyhog explain <stem>` needs to succeed. It would have failed on the
//! `aws-access-key-id` drift.

use std::collections::BTreeSet;
use std::path::PathBuf;

/// Repo root = two levels up from this crate's manifest (`crates/cli`).
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root resolves")
}

/// Canonical detector ids from the embedded corpus (what `explain` resolves).
fn embedded_ids() -> BTreeSet<String> {
    #[derive(serde::Deserialize)]
    struct DetectorFile {
        detector: Detector,
    }
    #[derive(serde::Deserialize)]
    struct Detector {
        id: String,
    }
    let mut ids = BTreeSet::new();
    for (name, toml_content) in keyhog_core::embedded_detector_tomls() {
        let file: DetectorFile = toml::from_str(toml_content)
            .unwrap_or_else(|e| panic!("embedded detector {name} parses: {e}"));
        ids.insert(file.detector.id);
    }
    assert!(ids.len() > 100, "embedded corpus must be populated; got {}", ids.len());
    ids
}

/// Every `detectors/<stem>.toml` reference found in `text`.
fn referenced_stems(text: &str) -> BTreeSet<String> {
    let mut stems = BTreeSet::new();
    let mut rest = text;
    while let Some(pos) = rest.find("detectors/") {
        let after = &rest[pos + "detectors/".len()..];
        // Read the stem up to `.toml`.
        if let Some(dot) = after.find(".toml") {
            let stem = &after[..dot];
            // A real id is kebab/alnum; reject if the slice ran across a path
            // separator or whitespace (a non-`detectors/<file>` coincidence).
            if !stem.is_empty()
                && stem
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
            {
                stems.insert(stem.to_string());
            }
            rest = &after[dot + ".toml".len()..];
        } else {
            rest = after;
        }
    }
    stems
}

#[test]
fn fp_audit_report_detector_ids_resolve() {
    let root = repo_root();
    let report = root.join("FP_AUDIT_REPORT.md");
    let text = std::fs::read_to_string(&report)
        .unwrap_or_else(|e| panic!("FP_AUDIT_REPORT.md readable at {}: {e}", report.display()));

    let ids = embedded_ids();
    let stems = referenced_stems(&text);
    assert!(
        !stems.is_empty(),
        "FP_AUDIT_REPORT.md must reference detectors by detectors/<id>.toml path"
    );

    let unresolved: Vec<&String> = stems.iter().filter(|s| !ids.contains(*s)).collect();
    assert!(
        unresolved.is_empty(),
        "FP_AUDIT_REPORT.md names detector files that do NOT resolve to a canonical \
         registry id (a reader running `keyhog explain <id>` on these gets exit 2): {unresolved:?}. \
         Fix the doc to cite the canonical id (the .toml file stem == the detector's `id`)."
    );
}

#[test]
fn readme_detector_ids_resolve_if_any() {
    let root = repo_root();
    let readme = root.join("README.md");
    let Ok(text) = std::fs::read_to_string(&readme) else {
        // No README at root is not this guard's concern.
        return;
    };
    let ids = embedded_ids();
    let stems = referenced_stems(&text);
    let unresolved: Vec<&String> = stems.iter().filter(|s| !ids.contains(*s)).collect();
    assert!(
        unresolved.is_empty(),
        "README.md names detector files that do NOT resolve to a canonical registry id: \
         {unresolved:?}. Cite the canonical id (the .toml stem == the detector `id`)."
    );
}
