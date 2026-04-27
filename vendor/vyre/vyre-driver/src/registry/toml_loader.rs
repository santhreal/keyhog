//! Runtime TOML dialect loader (A-B5).
//!
//! The Rust path registers ops at link time via `inventory::submit!`.
//! Some consumers — DSL authors, CVE-rule contributors, community
//! Nuclei-template-style writers — want to drop a TOML file in a
//! directory and have the runtime pick it up without recompiling.
//!
//! This module provides that mechanism for the **metadata** part of
//! a dialect: op id, dialect name, category, signature, laws. The
//! behavioral part (`cpu_ref`, `naga_wgsl`, etc.) still comes from
//! Rust because TOML can't declaratively describe a compute kernel.
//! External dialect crates can thus ship the behavioral half as Rust
//! and the declarative half as TOML — the TOML supports community
//! contributions of new rule-like ops whose behavior is composed from
//! existing primitives.
//!
//! Load sequence:
//!
//! 1. `VYRE_DIALECT_PATH` colon-separated directories are scanned for
//!    `*.toml` files.
//! 2. Each file is parsed against the [`DialectManifest`] schema.
//! 3. Manifests are registered into an in-memory [`TomlDialectStore`].
//! 4. Consumers query the store via [`TomlDialectStore::dialect`] and
//!    [`TomlDialectStore::ops_in`].
//!
//! Runtime TOML ops are *additive* — they don't override an
//! inventory-registered OpDef with the same id. A conflict is
//! surfaced as a Diagnostic so downstream consumers can disambiguate.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::diagnostics::{Diagnostic, DiagnosticCode};

const DIALECT_PATH_ENV: &str = "VYRE_DIALECT_PATH";

/// Top-level TOML schema for a dialect manifest.
///
/// Every file in `VYRE_DIALECT_PATH` is parsed into one of these.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DialectManifest {
    /// Dialect identifier (e.g. `"community.cve_rules"`).
    pub dialect: String,
    /// Version of this dialect revision (semver string).
    pub version: String,
    /// Optional human-readable note surfaced in diagnostics.
    #[serde(default)]
    pub description: Option<String>,
    /// List of ops.
    #[serde(default)]
    pub ops: Vec<OpManifest>,
}

/// Per-op TOML entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpManifest {
    /// Fully qualified op id (`<dialect>.<name>`).
    pub id: String,
    /// Category — `"A"`, `"B"`, or `"C"`.
    pub category: String,
    /// Optional free-form summary (one line) surfaced in catalogs.
    #[serde(default)]
    pub summary: Option<String>,
    /// Declarative input list — `(name, type)` pairs.
    #[serde(default)]
    pub inputs: Vec<(String, String)>,
    /// Declarative output list — `(name, type)` pairs.
    #[serde(default)]
    pub outputs: Vec<(String, String)>,
    /// Algebraic-law tags the op claims to satisfy.
    #[serde(default)]
    pub laws: Vec<String>,
}

/// In-memory store of every TOML-loaded dialect manifest.
#[derive(Debug, Default, Clone)]
pub struct TomlDialectStore {
    manifests: BTreeMap<String, DialectManifest>,
    diagnostics: Vec<Diagnostic>,
}

impl TomlDialectStore {
    /// Build a store by scanning the directories in
    /// `VYRE_DIALECT_PATH`. Missing directories are silently
    /// ignored (the env var is optional).
    #[must_use]
    pub fn from_env() -> Self {
        let mut store = Self::default();
        if let Ok(path) = std::env::var(DIALECT_PATH_ENV) {
            for entry in path.split(':') {
                let dir = Path::new(entry);
                if dir.is_dir() {
                    store.scan_dir(dir);
                }
            }
        }
        store
    }

    /// Scan one directory for `*.toml` manifests. Invalid manifests
    /// surface as [`Diagnostic`]s attached to the store; the scan
    /// never short-circuits.
    pub fn scan_dir(&mut self, dir: &Path) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            self.load_file(&path);
        }
    }

    /// Load a single TOML file. Errors become diagnostics; the
    /// function never panics.
    pub fn load_file(&mut self, path: &Path) {
        let Ok(contents) = fs::read_to_string(path) else {
            self.diagnostics.push(
                Diagnostic::warning("W-TOML-UNREADABLE",
                    format!("TOML dialect file `{}` is unreadable", path.display()))
                    .with_fix("confirm file permissions and that VYRE_DIALECT_PATH points at an intended directory"),
            );
            return;
        };
        match toml::from_str::<DialectManifest>(&contents) {
            Ok(mut manifest) => {
                // Keep the highest-versioned manifest per dialect.
                // Duplicate loads with same dialect id are
                // informational, not fatal.
                if let Some(existing) = self.manifests.get(&manifest.dialect) {
                    if existing.version >= manifest.version {
                        return;
                    }
                    self.diagnostics.push(Diagnostic::note(
                        "N-TOML-DIALECT-SHADOWED",
                        format!(
                            "dialect `{}` has multiple manifests; keeping version {} over {}",
                            manifest.dialect, manifest.version, existing.version
                        ),
                    ));
                }
                // Sanity pass: every op id must begin with the
                // dialect prefix.
                manifest.ops.retain(|op| {
                    if op.id.starts_with(&format!("{}.", manifest.dialect)) {
                        true
                    } else {
                        self.diagnostics.push(
                            Diagnostic::warning(
                                "W-TOML-BAD-OP-ID",
                                format!(
                                    "op id `{}` does not start with dialect prefix `{}.`",
                                    op.id, manifest.dialect
                                ),
                            )
                            .with_fix("rename the op to `<dialect>.<name>`"),
                        );
                        false
                    }
                });
                self.manifests.insert(manifest.dialect.clone(), manifest);
            }
            Err(err) => {
                self.diagnostics.push(
                    Diagnostic::error(
                        "E-TOML-PARSE",
                        format!("TOML dialect file `{}` is malformed: {err}", path.display()),
                    )
                    .with_fix("validate the file against the DialectManifest schema"),
                );
            }
        }
    }

    /// Look up one dialect manifest by name.
    #[must_use]
    pub fn dialect(&self, id: &str) -> Option<&DialectManifest> {
        self.manifests.get(id)
    }

    /// List every op declared in the given dialect.
    #[must_use]
    pub fn ops_in(&self, dialect: &str) -> &[OpManifest] {
        self.manifests
            .get(dialect)
            .map(|m| m.ops.as_slice())
            .unwrap_or(&[])
    }

    /// Return every loaded dialect manifest.
    #[must_use]
    pub fn manifests(&self) -> Vec<&DialectManifest> {
        self.manifests.values().collect()
    }

    /// Diagnostics accumulated during load.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Convenience: check whether a given op id is declared by any
    /// loaded TOML manifest.
    #[must_use]
    pub fn contains_op(&self, op_id: &str) -> bool {
        self.manifests
            .values()
            .any(|m| m.ops.iter().any(|op| op.id == op_id))
    }
}

/// Stable diagnostic code family for TOML loader issues. Tooling
/// hangs rules off these codes; do not rename.
pub const CODE_PARSE: DiagnosticCode = DiagnosticCode(std::borrow::Cow::Borrowed("E-TOML-PARSE"));

/// Compute an absolute path relative to the workspace root. Handy
/// for tests that stage TOML fixtures under `tests/fixtures`.
#[must_use]
pub fn workspace_dialect_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("dialect")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(contents: &str) -> tempfile::NamedTempFile {
        // Many tests need a .toml file on disk; NamedTempFile
        // exposes its path and cleans up on drop.
        let mut file = tempfile::Builder::new()
            .suffix(".toml")
            .tempfile()
            .expect("Fix: tmp file");
        file.write_all(contents.as_bytes()).expect("Fix: write");
        file.flush().expect("Fix: flush");
        file
    }

    #[test]
    fn parses_minimal_dialect() {
        let file = write_tmp(
            r#"
dialect = "community.test"
version = "1.0.0"
ops = [
  { id = "community.test.pass", category = "A", summary = "no-op" },
]
"#,
        );
        let mut store = TomlDialectStore::default();
        store.load_file(file.path());
        assert!(store.dialect("community.test").is_some());
        assert_eq!(store.ops_in("community.test").len(), 1);
        assert!(store.contains_op("community.test.pass"));
        assert_eq!(store.diagnostics().len(), 0);
    }

    #[test]
    fn rejects_mismatched_op_prefix_with_diagnostic() {
        let file = write_tmp(
            r#"
dialect = "community.test"
version = "1.0.0"
ops = [
  { id = "other.not_my_dialect", category = "A" },
]
"#,
        );
        let mut store = TomlDialectStore::default();
        store.load_file(file.path());
        assert_eq!(store.ops_in("community.test").len(), 0);
        assert!(store
            .diagnostics()
            .iter()
            .any(|d| d.code.as_str() == "W-TOML-BAD-OP-ID"));
    }

    #[test]
    fn malformed_toml_produces_parse_error_diagnostic() {
        let file = write_tmp("not-toml-at-all =");
        let mut store = TomlDialectStore::default();
        store.load_file(file.path());
        assert!(store
            .diagnostics()
            .iter()
            .any(|d| d.code.as_str() == "E-TOML-PARSE"));
    }

    #[test]
    fn shadowed_manifest_keeps_highest_version() {
        let older = write_tmp(
            r#"
dialect = "community.versioned"
version = "1.0.0"
ops = []
"#,
        );
        let newer = write_tmp(
            r#"
dialect = "community.versioned"
version = "2.0.0"
ops = [ { id = "community.versioned.new", category = "B" } ]
"#,
        );
        let mut store = TomlDialectStore::default();
        store.load_file(older.path());
        store.load_file(newer.path());
        assert_eq!(
            store.dialect("community.versioned").unwrap().version,
            "2.0.0"
        );
        assert_eq!(store.ops_in("community.versioned").len(), 1);
    }

    #[test]
    fn env_scan_skips_missing_directories() {
        // VYRE_DIALECT_PATH points at a directory that doesn't
        // exist — must not panic, must not accumulate diagnostics.
        let saved = std::env::var(DIALECT_PATH_ENV).ok();
        std::env::set_var(DIALECT_PATH_ENV, "/no/such/dir:/also/not/real");
        let store = TomlDialectStore::from_env();
        assert!(store.manifests.is_empty());
        assert!(store.diagnostics.is_empty());
        if let Some(s) = saved {
            std::env::set_var(DIALECT_PATH_ENV, s);
        } else {
            std::env::remove_var(DIALECT_PATH_ENV);
        }
    }

    #[test]
    fn code_constants_are_stable() {
        assert_eq!(CODE_PARSE.as_str(), "E-TOML-PARSE");
    }
}
