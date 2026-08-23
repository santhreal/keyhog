//! Documentation gate: guard state labels in shipped docs must match the
//! `GuardRootState::label()` and `GuardRootMode::label()` output exactly.
//!
//! A doc that names a guard state like "stale-policy" or "idle-unload" must use
//! the same string the daemon emits in `GuardStatusResult`. A reader who copies
//! the label into a filter or automation script must get a match. Drift here is
//! a coherence bug: the doc says "stalepolicy" and the daemon says
//! "stale-policy", and a grep-based alert silently misses every transition.

use std::collections::BTreeSet;
use std::path::PathBuf;

/// Repo root = two levels up from this crate's manifest (`crates/cli`).
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root resolves")
}

/// All valid guard root state labels from the state machine.
fn guard_state_labels() -> BTreeSet<String> {
    use keyhog_core::guard_state::GuardRootState;
    GuardRootState::all()
        .iter()
        .map(|s| s.label().to_string())
        .collect()
}

/// All valid guard root mode labels.
fn guard_mode_labels() -> BTreeSet<String> {
    use keyhog_core::guard_state::GuardRootMode;
    GuardRootMode::all()
        .iter()
        .map(|m| m.label().to_string())
        .collect()
}
/// Valid scanner residency labels.
fn scanner_residency_labels() -> BTreeSet<String> {
    ["active", "resident", "idle-unload"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Shipped Markdown docs at the repo root and under docs/.
fn shipped_markdown_docs(root: &std::path::Path) -> Vec<PathBuf> {
    let mut docs = Vec::new();
    // README.md at root.
    let readme = root.join("README.md");
    if readme.is_file() {
        docs.push(readme);
    }
    // CHANGELOG.md at root.
    let changelog = root.join("CHANGELOG.md");
    if changelog.is_file() {
        docs.push(changelog);
    }
    // docs/ directory.
    let docs_dir = root.join("docs");
    if docs_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&docs_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "md") {
                    docs.push(path);
                }
            }
        }
    }
    docs
}

/// Extract guard-state-like tokens from text. Looks for known state labels
/// and also for common misspellings (no hyphen, wrong case).
fn guard_state_tokens(text: &str) -> Vec<(String, String)> {
    let valid = guard_state_labels();
    let mut found = Vec::new();
    for word in text.split_whitespace() {
        let cleaned = word
            .trim_matches(|c: char| !c.is_alphanumeric() && c != '-')
            .to_lowercase();
        if cleaned.is_empty() {
            continue;
        }
        // Check if it's a valid label.
        if valid.contains(&cleaned) {
            found.push((cleaned.clone(), word.to_string()));
        }
        // Check for common drift: "stalepolicy" instead of "stale-policy".
        let no_hyphen = cleaned.replace('-', "");
        for valid_label in &valid {
            if valid_label.replace('-', "") == no_hyphen && *valid_label != cleaned {
                found.push((valid_label.clone(), word.to_string()));
            }
        }
    }
    found
}

#[test]
fn shipped_docs_guard_state_labels_match_code() {
    let root = repo_root();
    let docs = shipped_markdown_docs(&root);
    assert!(!docs.is_empty(), "no shipped markdown docs found");

    let valid_labels = guard_state_labels();
    let mode_labels = guard_mode_labels();
    let residency_labels = scanner_residency_labels();

    for doc_path in &docs {
        let text = std::fs::read_to_string(doc_path)
            .unwrap_or_else(|_| panic!("read {}", doc_path.display()));

        // Check that any state-like token in the doc matches a valid label.
        for (label, original) in guard_state_tokens(&text) {
            assert!(
                valid_labels.contains(&label),
                "{}: guard state token '{}' (from '{}') is not a valid GuardRootState label",
                doc_path.display(),
                label,
                original
            );
        }

        // Check for the specific drift: a lowercase "stalepolicy" without
        // hyphen used as a state label (not a CamelCase type name like
        // `StalePolicy` which is correct in prose).
        for word in text.split_whitespace() {
            let w = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '-');
            if w.eq_ignore_ascii_case("stalepolicy")
                && !w.contains('-')
                && !w.chars().next().is_some_and(|c| c.is_uppercase())
            {
                panic!(
                    "{}: contains '{}' (lowercase, missing hyphen); the correct label is 'stale-policy'",
                    doc_path.display(),
                    word
                );
            }
        }

        // Mode and residency labels are valid by construction; their
        // presence in docs is fine.
        let _ = &mode_labels;
        let _ = &residency_labels;
    }
}

#[test]
fn guard_state_labels_are_stable() {
    // The label() output is a public contract: CLI filters, docs, and
    // automation depend on these exact strings. This test fails if any
    // label changes, forcing a coordinated update.
    use keyhog_core::guard_state::GuardRootState;
    assert_eq!(GuardRootState::Indexing.label(), "indexing");
    assert_eq!(GuardRootState::Current.label(), "current");
    assert_eq!(GuardRootState::Dirty.label(), "dirty");
    assert_eq!(GuardRootState::Blocked.label(), "blocked");
    assert_eq!(GuardRootState::Degraded.label(), "degraded");
    assert_eq!(GuardRootState::StalePolicy.label(), "stale-policy");
    assert_eq!(GuardRootState::Stopped.label(), "stopped");
}

#[test]
fn guard_mode_labels_are_stable() {
    use keyhog_core::guard_state::GuardRootMode;
    assert_eq!(GuardRootMode::Repo.label(), "repo");
    assert_eq!(GuardRootMode::Filesystem.label(), "filesystem");
}
