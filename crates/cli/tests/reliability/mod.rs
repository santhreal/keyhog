//! Product-reliability integration suite (CLAUDE.md product-integration
//! contract). The bar: a customer's experience CANNOT be bad, under any setup.
//!
//! Structure:
//! * `harness` - the hostile-env command driver + shared invariant assertions.
//! * `surface_*` - matrices fanning every subcommand across every [`Profile`].
//!   Each `(subcommand × profile)` is its OWN `#[test]` (a nested module path
//!   like `reliability::surface_help::scan::no_home::case`), so a failure names
//!   the exact subcommand and environment that broke. This is the sanctioned
//!   matrix: every axis flips a different runtime branch, every cell asserts a
//!   real invariant through the real binary.
//! * the remaining files are hand-authored deep tests for specific defect
//!   classes (installer recoverability, exit-code/doc contract, scan
//!   robustness, output-format stability).
//!
//! [`Profile`]: harness::Profile

#[macro_use]
pub mod matrix_macros;

pub mod harness;

// Subcommand × profile matrices.
pub mod determinism;
pub mod surface_badflag;
pub mod surface_help;
pub mod surface_noargs;
pub mod surface_valid;

// Hand-authored deep defect-class suites.
pub mod exit_contract;
pub mod installer_recoverability;
pub mod output_format;
pub mod scan_robustness;
pub mod update_lifecycle;
