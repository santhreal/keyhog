//! Lego-block enforcement lints for vyre.
//!
//! Source-of-truth: `SEPARATION_AUDIT_2026-05-01.md` section S0.
//!
//! Tier-3 dialect crates (`vyre-libs`) must compose Tier-2.5 primitives
//! (`vyre-primitives`); they must not reach into Tier-1 IR atoms
//! (`vyre-ir` / `vyre-foundation`) directly. Without this enforcement:
//!
//! - Two ops doing the same thing two different ways.
//! - The optimizer can't recognize either as a known shape.
//! - Egglog rule LHS patterns become brittle.
//! - Tier-2.5 primitive bug fixes don't propagate.
//!
//! This crate ships one lint today: `raw_ir_in_libs` — flags raw
//! `Node::*` and `Expr::*` *construction* sites in `vyre-libs/src/**`.
//! Pattern matching against the same enums is fine; only construction
//! is flagged. An allowlist (`vyre-lints/allowlist.toml`) lets the
//! migration land incrementally — files in the allowlist are exempt
//! during their lego-migration ticket and removed from the allowlist
//! when the ticket lands.

pub mod allowlist;
pub mod drift;
pub mod raw_ir_in_libs;

use anyhow::Result;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub kind: ViolationKind,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViolationKind {
    /// `Node::SomeVariant { .. }` or `Node::some_method(..)` outside
    /// `vyre-primitives` and outside test modules.
    RawNodeConstruction,
    /// `Expr::SomeVariant { .. }` or `Expr::some_method(..)` outside
    /// `vyre-primitives` and outside test modules.
    RawExprConstruction,
}

/// Run the `raw_ir_in_libs` lint over a directory tree.
///
/// `roots` are crate-root paths (e.g. `vyre-libs/src/`). The allowlist
/// is loaded from `allowlist_path`. Violations are returned in source
/// order (file, then line). Returns `Ok(violations)` on success;
/// `Err` only on I/O or parse failure.
pub fn run_raw_ir_in_libs(
    roots: &[&Path],
    allowlist_path: Option<&Path>,
) -> Result<Vec<Violation>> {
    let allow = match allowlist_path {
        Some(path) => allowlist::load(path)?,
        None => allowlist::Allowlist::empty(),
    };
    let mut all = Vec::new();
    for root in roots {
        all.extend(raw_ir_in_libs::scan_tree(root, &allow)?);
    }
    all.sort_by(|a, b| (a.file.clone(), a.line).cmp(&(b.file.clone(), b.line)));
    Ok(all)
}
