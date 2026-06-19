//! Allowlist and declarative rule suppressor loading for scan runs.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::orchestrator_config::ResolvedAllowlistConfig;

pub(crate) fn load_allowlist(
    scan_path: Option<&Path>,
    config: &ResolvedAllowlistConfig,
) -> Result<keyhog_core::Allowlist> {
    let base_path = scan_path
        .map(allowlist_root)
        .unwrap_or_else(|| PathBuf::from(".")); // LAW10: no parent/unresolved path => '.' (current dir), intended path default; recall-safe
    let configured_file = config.file.is_some();
    let ignore_path = match config.file.as_ref() {
        Some(path) => path.clone(),
        None => base_path.join(".keyhogignore"),
    };
    if configured_file || ignore_path.exists() {
        keyhog_core::Allowlist::load_with_metadata_policy(
            &ignore_path,
            config.require_reason,
            config.require_approved_by,
            config.max_expires_days,
        )
        .with_context(|| {
            format!(
                "failed to load {}. Fix or remove the allowlist; refusing to scan with silently ignored policy.",
                ignore_path.display()
            )
        })
    } else {
        Ok(keyhog_core::Allowlist::empty())
    }
}

/// Load the declarative `.keyhogignore.toml` rule suppressor (vyre
/// rule engine via CPU evaluator) alongside the legacy line-based
/// allowlist. Missing file means empty suppressor; malformed present file is a
/// policy failure and stops the scan.
pub(crate) fn load_rule_suppressor(
    scan_path: Option<&Path>,
) -> Result<keyhog_core::RuleSuppressor> {
    let base_path = scan_path
        .map(allowlist_root)
        .unwrap_or_else(|| PathBuf::from(".")); // LAW10: no parent/unresolved path => '.' (current dir), intended path default; recall-safe
    let toml_path = base_path.join(".keyhogignore.toml");
    match keyhog_core::RuleSuppressor::load(&toml_path) {
        Ok(s) => {
            tracing::debug!(
                file = %toml_path.display(),
                "loaded declarative suppression policy"
            );
            Ok(s)
        }
        Err(e) => anyhow::bail!(
            "failed to load {}: {e}. Fix the TOML schema (see docs/keyhogignore-toml.md) \
             or remove the file; refusing to scan with silently ignored suppression rules.",
            toml_path.display()
        ),
    }
}

pub(crate) fn allowlist_root(path: &Path) -> PathBuf {
    // FS-based when we can: a real directory IS the root; a real file
    // delegates to its parent (with "." as the bare-filename fallback).
    if path.is_dir() {
        return path.to_path_buf();
    }
    if path.is_file() {
        return path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(".")); // LAW10: no parent/unresolved path => '.' (current dir), intended path default; recall-safe
    }
    // Non-existent path. Shape heuristic:
    //   * has a file extension AND has a parent  -> treat as file
    //   * no parent (bare filename like file.rs) -> "."
    //   * has parent and no extension            -> treat as directory
    // The extension test catches the common case (`scan /tmp/x.txt`,
    // `scan src/main.rs`) without an FS round trip, while still
    // letting an extensionless target like `/tmp/project` anchor at
    // itself even when the dir hasn't been created yet.
    let has_extension = path.extension().is_some();
    let parent_opt = path.parent().filter(|p| !p.as_os_str().is_empty());
    match (has_extension, parent_opt) {
        (true, Some(parent)) => parent.to_path_buf(),
        (false, Some(_)) => path.to_path_buf(),
        (_, None) => PathBuf::from("."),
    }
}
