//! Allowlist and declarative rule suppressor loading for scan runs.

use std::path::{Path, PathBuf};

pub(crate) fn load_allowlist(scan_path: Option<&Path>) -> keyhog_core::allowlist::Allowlist {
    let base_path = scan_path
        .map(allowlist_root)
        .unwrap_or_else(|| PathBuf::from("."));
    let ignore_path = base_path.join(".keyhogignore");
    if ignore_path.exists() {
        keyhog_core::allowlist::Allowlist::load(&ignore_path)
            .unwrap_or_else(|_| keyhog_core::allowlist::Allowlist::empty())
    } else {
        keyhog_core::allowlist::Allowlist::empty()
    }
}

/// Load the declarative `.keyhogignore.toml` rule suppressor (vyre
/// rule engine via CPU evaluator) alongside the legacy line-based
/// allowlist. Returns an empty suppressor when the file is missing
/// or fails to parse — a malformed rules file shouldn't stop the
/// scan; the parse error is surfaced via `tracing::warn!` so the
/// operator still notices.
pub(crate) fn load_rule_suppressor(scan_path: Option<&Path>) -> keyhog_core::RuleSuppressor {
    let base_path = scan_path
        .map(allowlist_root)
        .unwrap_or_else(|| PathBuf::from("."));
    let toml_path = base_path.join(".keyhogignore.toml");
    match keyhog_core::RuleSuppressor::load(&toml_path) {
        Ok(s) => {
            if !s.is_empty() {
                tracing::info!(
                    rules = s.len(),
                    file = %toml_path.display(),
                    "loaded declarative suppression rules"
                );
            }
            s
        }
        Err(e) => {
            tracing::warn!(
                file = %toml_path.display(),
                error = %e,
                "failed to load .keyhogignore.toml; ignoring rules. \
                 Fix: validate the TOML schema (see docs/keyhogignore-toml.md)."
            );
            keyhog_core::RuleSuppressor::empty()
        }
    }
}

pub(crate) fn allowlist_root(path: &Path) -> PathBuf {
    if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    }
}
