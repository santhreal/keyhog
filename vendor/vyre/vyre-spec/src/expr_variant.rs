//! Frozen catalog of core `Expr` variant names.

/// Canonical `Expr` variant names exposed by the stable vyre IR surface.
///
/// This is a coverage catalog, not a dynamic registry. Conformance suites use
/// it to prove that test matrices exercise every core expression shape at
/// least once.
static EXPR_VARIANTS: &[&str] = &[
    "LitU32",
    "LitI32",
    "LitF32",
    "LitBool",
    "Var",
    "Load",
    "BufLen",
    "InvocationId",
    "WorkgroupId",
    "LocalId",
    "BinOp",
    "UnOp",
    "Call",
    "Select",
    "Cast",
    "Fma",
    "Atomic",
    "SubgroupBallot",
    "SubgroupShuffle",
    "SubgroupAdd",
    "Opaque",
];

/// Return the frozen catalog of core `Expr` variant names.
#[must_use]
pub fn expr_variants() -> &'static [&'static str] {
    EXPR_VARIANTS
}
