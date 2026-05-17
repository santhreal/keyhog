//! Machine-checkable proof obligations for optimizer rewrites.
//!
//! A rewrite contract becomes useful only when it can leave the source tree as
//! a solver-consumable artifact. This module is the substrate for that: a small
//! typed SMT-LIB emitter for equivalence obligations of the form
//! `preconditions => before == after`. Solvers prove the rewrite by showing the
//! negation is `unsat`.

use rustc_hash::FxHashMap;
use std::fmt::Write as _;
use std::sync::Arc;

/// SMT sort used by a proof expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProofSort {
    /// Boolean proposition.
    Bool,
    /// Fixed-width bit-vector.
    BitVec(u32),
}

impl ProofSort {
    fn write_smt(self, out: &mut String) {
        match self {
            Self::Bool => out.push_str("Bool"),
            Self::BitVec(bits) => {
                let _ = write!(out, "(_ BitVec {bits})");
            }
        }
    }
}

/// Typed expression in a proof obligation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProofExpr {
    sort: ProofSort,
    kind: ProofExprKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ProofExprKind {
    Var(Arc<str>),
    Bool(bool),
    Bv(u64),
    Not(Box<ProofExpr>),
    And(Vec<ProofExpr>),
    Or(Vec<ProofExpr>),
    Eq(Box<ProofExpr>, Box<ProofExpr>),
    BvAdd(Box<ProofExpr>, Box<ProofExpr>),
    BvSub(Box<ProofExpr>, Box<ProofExpr>),
    BvMul(Box<ProofExpr>, Box<ProofExpr>),
}

impl ProofExpr {
    /// Create a typed variable.
    #[must_use]
    pub fn var(name: impl Into<Arc<str>>, sort: ProofSort) -> Self {
        Self {
            sort,
            kind: ProofExprKind::Var(name.into()),
        }
    }

    /// Boolean literal.
    #[must_use]
    pub const fn bool(value: bool) -> Self {
        Self {
            sort: ProofSort::Bool,
            kind: ProofExprKind::Bool(value),
        }
    }

    /// Bit-vector literal, truncated by the SMT sort width.
    #[must_use]
    pub const fn bv(value: u64, bits: u32) -> Self {
        Self {
            sort: ProofSort::BitVec(bits),
            kind: ProofExprKind::Bv(value),
        }
    }

    /// Expression sort.
    #[must_use]
    pub const fn sort(&self) -> ProofSort {
        self.sort
    }

    /// Boolean negation.
    #[must_use]
    pub fn not_(value: Self) -> Self {
        assert_sort(value.sort, ProofSort::Bool, "not");
        Self {
            sort: ProofSort::Bool,
            kind: ProofExprKind::Not(Box::new(value)),
        }
    }

    /// Boolean conjunction. Empty conjunction is true.
    #[must_use]
    pub fn and(values: impl IntoIterator<Item = Self>) -> Self {
        let values: Vec<Self> = values.into_iter().collect();
        for value in &values {
            assert_sort(value.sort, ProofSort::Bool, "and");
        }
        Self {
            sort: ProofSort::Bool,
            kind: ProofExprKind::And(values),
        }
    }

    /// Boolean disjunction. Empty disjunction is false.
    #[must_use]
    pub fn or(values: impl IntoIterator<Item = Self>) -> Self {
        let values: Vec<Self> = values.into_iter().collect();
        for value in &values {
            assert_sort(value.sort, ProofSort::Bool, "or");
        }
        Self {
            sort: ProofSort::Bool,
            kind: ProofExprKind::Or(values),
        }
    }

    /// Typed equality.
    #[must_use]
    pub fn eq(left: Self, right: Self) -> Self {
        assert_sort(right.sort, left.sort, "eq");
        Self {
            sort: ProofSort::Bool,
            kind: ProofExprKind::Eq(Box::new(left), Box::new(right)),
        }
    }

    /// Bit-vector addition.
    #[must_use]
    pub fn bvadd(left: Self, right: Self) -> Self {
        bv_bin("bvadd", left, right, ProofExprKind::BvAdd)
    }

    /// Bit-vector subtraction.
    #[must_use]
    pub fn bvsub(left: Self, right: Self) -> Self {
        bv_bin("bvsub", left, right, ProofExprKind::BvSub)
    }

    /// Bit-vector multiplication.
    #[must_use]
    pub fn bvmul(left: Self, right: Self) -> Self {
        bv_bin("bvmul", left, right, ProofExprKind::BvMul)
    }

    fn collect_vars(&self, out: &mut FxHashMap<Arc<str>, ProofSort>) {
        match &self.kind {
            ProofExprKind::Var(name) => {
                if let Some(existing) = out.insert(name.clone(), self.sort) {
                    assert_sort(existing, self.sort, "variable");
                }
            }
            ProofExprKind::Bool(_) | ProofExprKind::Bv(_) => {}
            ProofExprKind::Not(value) => value.collect_vars(out),
            ProofExprKind::And(values) | ProofExprKind::Or(values) => {
                for value in values {
                    value.collect_vars(out);
                }
            }
            ProofExprKind::Eq(left, right)
            | ProofExprKind::BvAdd(left, right)
            | ProofExprKind::BvSub(left, right)
            | ProofExprKind::BvMul(left, right) => {
                left.collect_vars(out);
                right.collect_vars(out);
            }
        }
    }

    fn write_smt(&self, out: &mut String) {
        match &self.kind {
            ProofExprKind::Var(name) => out.push_str(&escape_symbol(name)),
            ProofExprKind::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            ProofExprKind::Bv(value) => match self.sort {
                ProofSort::BitVec(bits) => {
                    let _ = write!(out, "(_ bv{value} {bits})");
                }
                ProofSort::Bool => unreachable!("bool literal handled by ProofExprKind::Bool"),
            },
            ProofExprKind::Not(value) => write_unary(out, "not", value),
            ProofExprKind::And(values) => write_nary(out, "and", values),
            ProofExprKind::Or(values) => write_nary(out, "or", values),
            ProofExprKind::Eq(left, right) => write_binary(out, "=", left, right),
            ProofExprKind::BvAdd(left, right) => write_binary(out, "bvadd", left, right),
            ProofExprKind::BvSub(left, right) => write_binary(out, "bvsub", left, right),
            ProofExprKind::BvMul(left, right) => write_binary(out, "bvmul", left, right),
        }
    }
}

/// One rewrite equivalence proof obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewriteProofObligation {
    /// Stable rewrite id.
    pub rewrite: Arc<str>,
    /// Preconditions required before the rewrite may fire.
    pub preconditions: Vec<ProofExpr>,
    /// Expression before rewrite.
    pub before: ProofExpr,
    /// Expression after rewrite.
    pub after: ProofExpr,
}

impl RewriteProofObligation {
    /// Build an equivalence obligation.
    #[must_use]
    pub fn equivalence(
        rewrite: impl Into<Arc<str>>,
        preconditions: impl IntoIterator<Item = ProofExpr>,
        before: ProofExpr,
        after: ProofExpr,
    ) -> Self {
        assert_sort(after.sort, before.sort, "rewrite equivalence");
        let preconditions: Vec<ProofExpr> = preconditions.into_iter().collect();
        for precondition in &preconditions {
            assert_sort(precondition.sort, ProofSort::Bool, "precondition");
        }
        Self {
            rewrite: rewrite.into(),
            preconditions,
            before,
            after,
        }
    }

    /// Emit a deterministic SMT-LIB v2 script. `unsat` proves the rewrite.
    #[must_use]
    pub fn to_smt2(&self) -> String {
        let mut vars = FxHashMap::default();
        for precondition in &self.preconditions {
            precondition.collect_vars(&mut vars);
        }
        self.before.collect_vars(&mut vars);
        self.after.collect_vars(&mut vars);
        let mut vars: Vec<_> = vars.into_iter().collect();
        vars.sort_by(|(left, _), (right, _)| left.cmp(right));

        let mut out = String::with_capacity(256 + vars.len() * 48);
        out.push_str("(set-logic QF_BV)\n");
        let _ = writeln!(out, "; rewrite: {}", self.rewrite);
        for (name, sort) in vars {
            out.push_str("(declare-fun ");
            out.push_str(&escape_symbol(&name));
            out.push_str(" () ");
            sort.write_smt(&mut out);
            out.push_str(")\n");
        }
        if !self.preconditions.is_empty() {
            out.push_str("(assert ");
            ProofExpr::and(self.preconditions.clone()).write_smt(&mut out);
            out.push_str(")\n");
        }
        out.push_str("(assert (not ");
        ProofExpr::eq(self.before.clone(), self.after.clone()).write_smt(&mut out);
        out.push_str("))\n(check-sat)\n");
        out
    }
}

fn bv_bin(
    op: &'static str,
    left: ProofExpr,
    right: ProofExpr,
    kind: fn(Box<ProofExpr>, Box<ProofExpr>) -> ProofExprKind,
) -> ProofExpr {
    assert_sort(right.sort, left.sort, op);
    match left.sort {
        ProofSort::BitVec(bits) => ProofExpr {
            sort: ProofSort::BitVec(bits),
            kind: kind(Box::new(left), Box::new(right)),
        },
        ProofSort::Bool => panic!("{op} requires bit-vector operands"),
    }
}

fn assert_sort(actual: ProofSort, expected: ProofSort, op: &str) {
    assert_eq!(
        actual, expected,
        "{op} proof expression sort mismatch: expected {expected:?}, got {actual:?}"
    );
}

fn escape_symbol(value: &str) -> String {
    if value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'$'))
    {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('|');
    for ch in value.chars() {
        if ch == '|' || ch == '\\' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('|');
    out
}

fn write_unary(out: &mut String, op: &str, value: &ProofExpr) {
    out.push('(');
    out.push_str(op);
    out.push(' ');
    value.write_smt(out);
    out.push(')');
}

fn write_binary(out: &mut String, op: &str, left: &ProofExpr, right: &ProofExpr) {
    out.push('(');
    out.push_str(op);
    out.push(' ');
    left.write_smt(out);
    out.push(' ');
    right.write_smt(out);
    out.push(')');
}

fn write_nary(out: &mut String, op: &str, values: &[ProofExpr]) {
    match values {
        [] if op == "and" => out.push_str("true"),
        [] if op == "or" => out.push_str("false"),
        [single] => single.write_smt(out),
        _ => {
            out.push('(');
            out.push_str(op);
            for value in values {
                out.push(' ');
                value.write_smt(out);
            }
            out.push(')');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_add_zero_equivalence_obligation() {
        let x = ProofExpr::var("x", ProofSort::BitVec(32));
        let proof = RewriteProofObligation::equivalence(
            "u32.add_zero_rhs",
            [],
            ProofExpr::bvadd(x.clone(), ProofExpr::bv(0, 32)),
            x,
        );
        let smt = proof.to_smt2();

        assert!(smt.contains("(set-logic QF_BV)"));
        assert!(smt.contains("(declare-fun x () (_ BitVec 32))"));
        assert!(smt.contains("(assert (not (= (bvadd x (_ bv0 32)) x)))"));
        assert!(smt.ends_with("(check-sat)\n"));
    }

    #[test]
    fn declarations_are_deterministic() {
        let z = ProofExpr::var("z", ProofSort::BitVec(32));
        let a = ProofExpr::var("a", ProofSort::BitVec(32));
        let proof = RewriteProofObligation::equivalence(
            "deterministic",
            [],
            ProofExpr::bvadd(z, ProofExpr::bv(0, 32)),
            a,
        );
        let smt = proof.to_smt2();
        let a_pos = smt.find("(declare-fun a").unwrap();
        let z_pos = smt.find("(declare-fun z").unwrap();

        assert!(a_pos < z_pos);
    }

    #[test]
    fn preconditions_are_asserted_before_negated_equivalence() {
        let x = ProofExpr::var("x", ProofSort::BitVec(32));
        let y = ProofExpr::var("y", ProofSort::BitVec(32));
        let pre = ProofExpr::eq(y.clone(), ProofExpr::bv(3, 32));
        let proof = RewriteProofObligation::equivalence(
            "with_pre",
            [pre],
            ProofExpr::bvadd(x.clone(), y),
            ProofExpr::bvadd(x, ProofExpr::bv(3, 32)),
        );
        let smt = proof.to_smt2();
        let pre_pos = smt.find("(assert (= y (_ bv3 32)))").unwrap();
        let proof_pos = smt.find("(assert (not").unwrap();

        assert!(pre_pos < proof_pos);
    }

    #[test]
    fn escaped_symbols_are_valid_smt_identifiers() {
        let x = ProofExpr::var("loop index", ProofSort::BitVec(32));
        let proof = RewriteProofObligation::equivalence("escape", [], x, ProofExpr::bv(0, 32));
        let smt = proof.to_smt2();

        assert!(smt.contains("(declare-fun |loop index| () (_ BitVec 32))"));
    }
}
