//! MC-10 / DF-02 guard — shipped docs must not name a detector id/file that the
//! registry can't resolve.
//!
//! DF-02 hit `keyhog explain aws-access-key-id` → exit 2 "no detector with id":
//! the internal design notes cited an id (`aws-access-key-id`) that had drifted from
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
    let ids: BTreeSet<String> = keyhog_core::load_embedded_detectors_or_fail()
        .expect("embedded detectors load")
        .into_iter()
        .map(|detector| detector.id.to_string())
        .collect();
    assert!(
        ids.len() > 100,
        "embedded corpus must be populated; got {}",
        ids.len()
    );
    ids
}

/// Every shipped `detectors/<stem>.toml` reference found in `text`.
fn referenced_stems(text: &str) -> BTreeSet<String> {
    let mut stems = BTreeSet::new();
    let mut rest = text;
    while let Some(pos) = rest.find("detectors/") {
        let is_repo_relative = pos == 0
            || !matches!(
                rest[..pos].as_bytes().last().copied(),
                Some(b'/') | Some(b'\\')
            );
        let after = &rest[pos + "detectors/".len()..];
        // Read the stem up to `.toml`.
        if let Some(dot) = after.find(".toml") {
            let stem = &after[..dot];
            // A real id is kebab/alnum; reject if the slice ran across a path
            // separator or whitespace (a non-`detectors/<file>` coincidence).
            if is_repo_relative
                && !stem.is_empty()
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

fn shipped_markdown_docs(root: &std::path::Path) -> Vec<PathBuf> {
    let mut docs = vec![root.join("README.md")];
    let mut stack = vec![root.join("docs")];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read docs dir {}: {e}", dir.display()));
        for entry in entries {
            let entry =
                entry.unwrap_or_else(|e| panic!("read docs dir entry {}: {e}", dir.display()));
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "md") {
                docs.push(path);
            }
        }
    }
    docs.sort();
    docs
}

#[test]
fn shipped_docs_detector_ids_resolve() {
    let root = repo_root();
    let ids = embedded_ids();
    let mut stems = BTreeSet::new();
    for doc in shipped_markdown_docs(&root) {
        let text = std::fs::read_to_string(&doc)
            .unwrap_or_else(|e| panic!("shipped markdown doc readable at {}: {e}", doc.display()));
        stems.extend(referenced_stems(&text));
    }
    assert!(
        !stems.is_empty(),
        "shipped docs must contain at least one detectors/<id>.toml reference for the coherence gate"
    );

    let unresolved: Vec<&String> = stems.iter().filter(|s| !ids.contains(*s)).collect();
    assert!(
        unresolved.is_empty(),
        "shipped docs name detector files that do NOT resolve to a canonical \
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
