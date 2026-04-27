//! Discovery layer for community vyre-libs dialect packs.
//!
//! Foundation owns these inventory types so both the driver registry and
//! downstream consumers can share one link-time collection point without
//! introducing a package cycle.

#![forbid(unsafe_code)]

/// Metadata describing a community-registered dialect pack.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExternDialect {
    /// Dialect crate name on crates.io. Must start with `vyre-libs-`.
    pub name: &'static str,
    /// Crate version at link time. Informational.
    pub version: &'static str,
    /// Public repository URL (for diagnostics + trust).
    pub crate_repo: &'static str,
}

impl ExternDialect {
    /// Construct a dialect metadata entry.
    #[must_use]
    pub const fn new(name: &'static str, version: &'static str, crate_repo: &'static str) -> Self {
        Self {
            name,
            version,
            crate_repo,
        }
    }
}

inventory::collect!(ExternDialect);

/// Individual Cat-A op contributed by a community dialect.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExternOp {
    /// Owning dialect (matches [`ExternDialect::name`]).
    pub dialect: &'static str,
    /// Fully-qualified op id (e.g. `"vyre-libs-quant::int8::matmul"`).
    pub op_id: &'static str,
}

impl ExternOp {
    /// Construct an op registration.
    #[must_use]
    pub const fn new(dialect: &'static str, op_id: &'static str) -> Self {
        Self { dialect, op_id }
    }
}

inventory::collect!(ExternOp);

/// Every dialect registered at link time.
#[must_use]
pub fn dialects() -> Vec<&'static ExternDialect> {
    inventory::iter::<ExternDialect>().collect()
}

/// Every registered op belonging to `dialect`.
#[must_use]
pub fn ops_in_dialect(dialect: &str) -> Vec<&'static ExternOp> {
    inventory::iter::<ExternOp>()
        .filter(|op| op.dialect == dialect)
        .collect()
}

/// Every registered op across every dialect.
#[must_use]
pub fn all_ops() -> Vec<&'static ExternOp> {
    inventory::iter::<ExternOp>().collect()
}

/// Structured validation error surfaced by [`verify`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExternVerifyError {
    /// Two or more `ExternDialect` entries share the same `name`.
    #[error("duplicate dialect name `{name}`: {count} entries registered. Fix: pick a unique crates.io name for each community pack.")]
    DuplicateDialect {
        /// The offending dialect name.
        name: &'static str,
        /// Number of entries sharing this name.
        count: usize,
    },

    /// Dialect `name` does not start with the reserved `vyre-libs-` prefix.
    #[error("dialect name `{name}` does not start with `vyre-libs-`. Fix: rename the pack crate and its ExternDialect::name to begin with `vyre-libs-`.")]
    MalformedDialectName {
        /// The offending dialect name.
        name: &'static str,
    },

    /// An `ExternOp` references a `dialect` name that no
    /// `ExternDialect` entry claims.
    #[error("orphan op `{op_id}` references dialect `{dialect}`, which is not registered. Fix: make sure the dialect's crate registers an `ExternDialect` entry with this name.")]
    OrphanOp {
        /// The orphan op's dialect reference.
        dialect: &'static str,
        /// The op id whose dialect is missing.
        op_id: &'static str,
    },

    /// `ExternOp.op_id` is an empty string.
    #[error("op registered with empty op_id under dialect `{dialect}`. Fix: every op must carry a fully-qualified id like `<dialect>::<op_name>`.")]
    EmptyOpId {
        /// The dialect claiming an empty-id op.
        dialect: &'static str,
    },
}

/// Run every consistency check across every registered extern dialect and op.
///
/// # Errors
///
/// Returns every discovered validation error.
pub fn verify() -> Result<(), Vec<ExternVerifyError>> {
    let mut errors = Vec::new();

    let mut counts: std::collections::HashMap<&'static str, usize> =
        std::collections::HashMap::new();
    for dialect in inventory::iter::<ExternDialect>() {
        *counts.entry(dialect.name).or_insert(0) += 1;
    }
    for (name, count) in counts {
        if count > 1 {
            errors.push(ExternVerifyError::DuplicateDialect { name, count });
        }
    }

    for dialect in inventory::iter::<ExternDialect>() {
        if !dialect.name.starts_with("vyre-libs-") {
            errors.push(ExternVerifyError::MalformedDialectName { name: dialect.name });
        }
    }

    let known: std::collections::HashSet<&'static str> = inventory::iter::<ExternDialect>()
        .map(|dialect| dialect.name)
        .collect();
    for op in inventory::iter::<ExternOp>() {
        if op.op_id.is_empty() {
            errors.push(ExternVerifyError::EmptyOpId {
                dialect: op.dialect,
            });
        }
        if !known.contains(op.dialect) {
            errors.push(ExternVerifyError::OrphanOp {
                dialect: op.dialect,
                op_id: op.op_id,
            });
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
