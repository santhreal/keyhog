//! Integration contracts for shipped optimizer rewrite proof obligations.

use vyre_foundation::optimizer::rewrite_proof_registry::shipped_obligations;

#[test]
fn registry_is_non_empty() {
    let obligations = shipped_obligations();
    assert!(
        obligations.iter().any(|o| !o.rewrite.is_empty()),
        "shipped rewrite proof registry must name at least one rewrite"
    );
}

#[test]
fn every_obligation_has_unique_name() {
    let obligations = shipped_obligations();
    let mut names: Vec<&str> = obligations
        .iter()
        .map(|obligation| &*obligation.rewrite)
        .collect();
    let original = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        names.len(),
        original,
        "rewrite-name collision in shipped_obligations"
    );
}

#[test]
fn every_obligation_emits_well_formed_smt2() {
    for obligation in shipped_obligations() {
        let smt = obligation.to_smt2();
        assert!(
            smt.contains("(set-logic QF_BV)"),
            "{} missing QF_BV header",
            obligation.rewrite
        );
        assert!(
            smt.contains("(check-sat)"),
            "{} missing check-sat",
            obligation.rewrite
        );
        assert!(
            !smt.contains("0u - 1u"),
            "{} emits malformed SMT2 token",
            obligation.rewrite
        );
    }
}

#[test]
fn add_zero_obligation_negation_is_x_plus_zero_eq_x() {
    let smt = shipped_obligations()
        .into_iter()
        .find(|obligation| &*obligation.rewrite == "identity_elim_add_zero")
        .unwrap()
        .to_smt2();
    assert!(smt.contains("bvadd"));
    assert!(smt.contains("x"));
}
