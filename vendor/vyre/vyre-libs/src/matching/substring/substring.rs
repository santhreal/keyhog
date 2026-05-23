//! Deprecated compatibility leaf for substring search.

pub use crate::scan::substring::substring_search;

/// Canonical replacement module path for diagnostics and generated docs.
pub const CANONICAL_SUBSTRING_MODULE: &str = "vyre_libs::scan::substring";

/// Legacy module path retained for backwards-compatible imports.
pub const LEGACY_SUBSTRING_MODULE: &str = "vyre_libs::matching::substring";
