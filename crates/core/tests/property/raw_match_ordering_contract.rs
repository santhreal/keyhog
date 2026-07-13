//! Property tier for `RawMatch`'s `Ord`: the sort + capped-heap eviction order
//! that makes the per-chunk finding set REPRODUCIBLE run-to-run (`push_match`
//! eviction at `max_matches_per_chunk`; see the location-tiebreak comment on the
//! `Ord` impl). `RawMatch::Ord` uses confidence(desc) → severity(desc) →
//! detector_id → credential → offset → line as its priority prefix, followed by
//! every remaining field as deterministic identity tiebreakers. This suite locks
//! the total-order LAWS (reflexive,
//! antisymmetric, transitive), the documented key PRIORITY (confidence then
//! severity), and sort determinism/permutation-stability, so a refactor can't
//! silently break reproducible eviction (the flicker the tiebreak comment fixed).
//!
//! It also asserts the required `cmp == Equal ⇔ Eq` contract so a future
//! priority-only preorder cannot silently collapse distinct BTree keys.

use keyhog_core::{CredentialHash, MatchLocation, RawMatch, SensitiveString, Severity};
use proptest::prelude::*;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;

fn sha256(s: &str) -> CredentialHash {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    CredentialHash::from_bytes(h.finalize().into())
}

/// Severity in DECLARATION (== derived `Ord`) order, ascending: index 0 = lowest
/// (`Info`), 5 = highest (`Critical`). `RawMatch::Ord` sorts higher severity
/// first, so a larger index sorts EARLIER on a confidence tie.
fn severity_of(i: u8) -> Severity {
    match i % 6 {
        0 => Severity::Info,
        1 => Severity::ClientSafe,
        2 => Severity::Low,
        3 => Severity::Medium,
        4 => Severity::High,
        _ => Severity::Critical,
    }
}

/// `(detector_idx, credential_idx, severity_idx, confidence, offset, line)` 
/// small universes so distinct matches frequently tie on a prefix of the sort
/// key and exercise the tiebreak cascade.
type Spec = (u8, u8, u8, Option<f64>, u32, u32);

fn raw(&(det, cred, sev, conf, offset, line): &Spec) -> RawMatch {
    let credential = format!("cred-{cred}");
    RawMatch {
        detector_id: Arc::from(format!("det-{det}").as_str()),
        detector_name: Arc::from("Detector"),
        service: Arc::from("svc"),
        severity: severity_of(sev),
        credential: SensitiveString::from(credential.as_str()),
        credential_hash: sha256(&credential),
        companions: HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("f.txt")),
            line: Some(line as usize),
            offset: offset as usize,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: conf,
    }
}

fn spec() -> impl Strategy<Value = Spec> {
    (
        0u8..3,
        0u8..3,
        0u8..6,
        prop::option::of(0.0f64..1.0),
        0u32..50,
        0u32..20,
    )
}

fn le(a: &RawMatch, b: &RawMatch) -> bool {
    a.cmp(b) != Ordering::Greater
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// Reflexive + deterministic: a match compares `Equal` to itself, and two
    /// matches built from the SAME spec compare `Equal`.
    #[test]
    fn prop_reflexive_and_deterministic(a in spec()) {
        let ra = raw(&a);
        prop_assert_eq!(ra.cmp(&ra), Ordering::Equal);
        prop_assert_eq!(raw(&a).cmp(&raw(&a)), Ordering::Equal);
    }

    /// Antisymmetric: `cmp(a,b)` is the reverse of `cmp(b,a)` for all inputs.
    #[test]
    fn prop_antisymmetric(a in spec(), b in spec()) {
        prop_assert_eq!(raw(&a).cmp(&raw(&b)), raw(&b).cmp(&raw(&a)).reverse());
    }

    #[test]
    fn prop_cmp_equal_iff_eq(a in spec(), b in spec()) {
        let (ra, rb) = (raw(&a), raw(&b));
        prop_assert_eq!(ra.cmp(&rb) == Ordering::Equal, ra == rb);
    }

    /// Transitive total order: `a ≤ b ≤ c ⟹ a ≤ c` (and the mirror), for all
    /// triples (the property a broken tiebreak cascade would violate).
    #[test]
    fn prop_transitive(a in spec(), b in spec(), c in spec()) {
        let (ra, rb, rc) = (raw(&a), raw(&b), raw(&c));
        if le(&ra, &rb) && le(&rb, &rc) {
            prop_assert!(le(&ra, &rc));
        }
        if le(&rc, &rb) && le(&rb, &ra) {
            prop_assert!(le(&rc, &ra));
        }
    }

    /// Confidence is the PRIMARY key (descending): whenever two matches differ
    /// in confidence, the higher-confidence one sorts first, regardless of every
    /// other field. Distinct confidences are drawn directly (two continuous
    /// f64 collide with ~0 probability) rather than assumed, so there is no
    /// rejection storm.
    #[test]
    fn prop_confidence_is_primary_key(
        base_a in spec(),
        base_b in spec(),
        ca in 0.0f64..1.0,
        cb in 0.0f64..1.0,
    ) {
        prop_assume!(ca != cb);
        let mut a = base_a;
        a.3 = Some(ca);
        let mut b = base_b;
        b.3 = Some(cb);
        let expected = if ca > cb { Ordering::Less } else { Ordering::Greater };
        prop_assert_eq!(raw(&a).cmp(&raw(&b)), expected);
    }

    /// Severity is the SECOND key (descending): on a confidence tie with all
    /// other fields equal, the higher-severity match sorts first. `sev_b` is
    /// CONSTRUCTED distinct from `sev_a` (offset 1..=5 mod 6) so no case is
    /// rejected.
    #[test]
    fn prop_severity_breaks_confidence_tie(base in spec(), sev_a in 0u8..6, off in 1u8..6) {
        let sev_b = (sev_a + off) % 6; // off ∈ 1..=5 ⇒ always ≠ sev_a
        let mut a = base;
        a.2 = sev_a;
        let mut b = base;
        b.2 = sev_b;
        let expected = if sev_a > sev_b { Ordering::Less } else { Ordering::Greater };
        prop_assert_eq!(raw(&a).cmp(&raw(&b)), expected);
    }

    /// `sort()` yields a cmp-ordered sequence, is idempotent, and is
    /// PERMUTATION-STABLE at the ordering level: sorting the reversed input
    /// produces a sequence that is element-wise cmp-`Equal` to the original
    /// sort (the reproducible-eviction guarantee, independent of input order).
    #[test]
    fn prop_sort_is_ordered_and_permutation_stable(specs in prop::collection::vec(spec(), 0..24)) {
        let mut v: Vec<RawMatch> = specs.iter().map(raw).collect();
        v.sort();
        for w in v.windows(2) {
            prop_assert!(w[0].cmp(&w[1]) != Ordering::Greater);
        }
        let mut again = v.clone();
        again.sort();
        for i in 0..v.len() {
            prop_assert_eq!(v[i].cmp(&again[i]), Ordering::Equal);
        }
        let mut rev: Vec<RawMatch> = specs.iter().rev().map(raw).collect();
        rev.sort();
        prop_assert_eq!(v.len(), rev.len());
        for i in 0..v.len() {
            prop_assert_eq!(v[i].cmp(&rev[i]), Ordering::Equal);
        }
    }
}
