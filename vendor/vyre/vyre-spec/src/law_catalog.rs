//! Frozen algebraic-law fingerprint strings used by catalog completeness tests.

/// Catalog of all algebraic-law variant fingerprints.
static LAW_CATALOG: &[&str] = &[
    "commutative",
    "associative",
    "identity",
    "left-identity",
    "right-identity",
    "self-inverse",
    "idempotent",
    "absorbing",
    "left-absorbing",
    "right-absorbing",
    "involution",
    "de-morgan",
    "monotone",
    "monotonic",
    "bounded",
    "complement",
    "distributive",
    "lattice-absorption",
    "inverse-of",
    "trichotomy",
    "zero-product",
    "custom",
];

/// Return the catalog of all algebraic-law variant fingerprints.
#[must_use]
pub fn law_catalog() -> &'static [&'static str] {
    LAW_CATALOG
}
