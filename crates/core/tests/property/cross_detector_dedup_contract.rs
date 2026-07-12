//! Property tier for `dedup_cross_detector` — the RECALL-SAFETY stage. When two
//! different detectors fire on the SAME credential in the SAME file, it collapses
//! them to ONE finding (the highest-confidence detector wins; the losers survive
//! as `cross_detector.*` companions on the winner — their evidence is DEMOTED,
//! never dropped). A bug here silently disappears a real secret from the report,
//! which is exactly why `DEDUP_LOST_SINGLETON` exists. The `regression_finding_*`
//! / `new_core_finding_dedup` files pin fixed decisions; this file locks the
//! RECALL biconditional over arbitrary match sets (proptest, 10k):
//!
//!   * output has EXACTLY ONE finding per distinct `(credential_hash, file)`
//!     group present in the input — no group lost, no group fabricated;
//!   * every demoted loser survives as a `cross_detector.*` companion on its
//!     group's winner (companion count == group size − 1), so no detector's
//!     evidence is dropped;
//!   * grouping is INPUT-ORDER-independent.
//!
//! Inputs are produced by the REAL `dedup_matches` pipeline (so `DedupedMatch`,
//! which lives in a private module, is constructed the production way rather than
//! named), then fed to `dedup_cross_detector` — the exact production sequence.

use keyhog_core::{
    dedup_cross_detector, dedup_matches, CredentialHash, DedupScope, MatchLocation, RawMatch,
    SensitiveString, Severity,
};
use proptest::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

fn sha256(s: &str) -> CredentialHash {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    CredentialHash::from_bytes(h.finalize().into())
}

/// `(detector_idx, credential_idx, file_idx, offset, confidence)` over small
/// universes so multiple DETECTORS land on the same `(credential, file)` and
/// actually exercise the cross-detector collapse.
type Spec = (u8, u8, u8, u32, f64);

fn build(specs: &[Spec]) -> Vec<RawMatch> {
    specs
        .iter()
        .map(|&(det, cred, file, offset, conf)| {
            let credential = format!("cred-{cred}");
            RawMatch {
                detector_id: Arc::from(format!("det-{det}").as_str()),
                detector_name: Arc::from("Detector"),
                service: Arc::from("svc"),
                severity: Severity::High,
                credential: SensitiveString::from(credential.as_str()),
                credential_hash: sha256(&credential),
                companions: HashMap::new(),
                location: MatchLocation {
                    source: Arc::from("filesystem"),
                    file_path: Some(Arc::from(format!("f{file}.txt").as_str())),
                    line: Some(1),
                    offset: offset as usize,
                    commit: None,
                    author: None,
                    date: None,
                },
                entropy: None,
                confidence: Some(conf),
            }
        })
        .collect()
}

/// The set of `(credential_hash, file)` grouping keys of a dedup result. Macro,
/// not fn, because `DedupedMatch` lives in a private module and cannot be named
/// in a signature (reached only through the value's public fields).
macro_rules! group_keys {
    ($v:expr) => {
        $v.iter()
            .map(|m| {
                (
                    m.credential_hash,
                    m.primary_location.file_path.as_ref().map(|a| a.to_string()),
                )
            })
            .collect::<HashSet<(CredentialHash, Option<String>)>>()
    };
}

fn spec_strat() -> impl Strategy<Value = Spec> {
    (0u8..3, 0u8..3, 0u8..2, 0u32..50, 0.0f64..1.0)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// One winner per distinct `(credential_hash, file)` group, and the output
    /// group set EQUALS the input group set — no finding lost, none fabricated.
    #[test]
    fn prop_preserves_every_group_exactly_once(specs in prop::collection::vec(spec_strat(), 0..24)) {
        let deduped = dedup_matches(build(&specs), &DedupScope::File);
        let expected = group_keys!(deduped);
        let out = dedup_cross_detector(deduped);
        let got = group_keys!(out);
        prop_assert_eq!(&got, &expected); // recall: no group lost, none fabricated
        prop_assert_eq!(out.len(), expected.len()); // exactly one winner per group
    }

    /// Every demoted loser survives as a `cross_detector.*` companion on its
    /// group's winner: companion count == group size − 1. Nothing is dropped,
    /// only re-attached.
    #[test]
    fn prop_losers_survive_as_companions(specs in prop::collection::vec(spec_strat(), 0..24)) {
        let deduped = dedup_matches(build(&specs), &DedupScope::File);
        let mut sizes: HashMap<(CredentialHash, Option<String>), usize> = HashMap::new();
        for m in &deduped {
            *sizes
                .entry((
                    m.credential_hash,
                    m.primary_location.file_path.as_ref().map(|a| a.to_string()),
                ))
                .or_insert(0) += 1;
        }
        let out = dedup_cross_detector(deduped);
        for m in &out {
            let key = (
                m.credential_hash,
                m.primary_location.file_path.as_ref().map(|a| a.to_string()),
            );
            let group_size = sizes[&key];
            let companions = m
                .companions
                .keys()
                .filter(|k| k.starts_with("cross_detector."))
                .count();
            prop_assert_eq!(
                companions,
                group_size - 1,
                "winner for {:?} should carry one cross_detector.* companion per demoted loser",
                key
            );
        }
    }

    /// The output grouping is INPUT-ORDER-independent (same group set + count for
    /// a permuted input).
    #[test]
    fn prop_order_independent(specs in prop::collection::vec(spec_strat(), 0..24)) {
        let deduped = dedup_matches(build(&specs), &DedupScope::File);
        let forward = dedup_cross_detector(deduped.clone());
        let mut reversed = deduped;
        reversed.reverse();
        let backward = dedup_cross_detector(reversed);
        prop_assert_eq!(group_keys!(forward), group_keys!(backward));
        prop_assert_eq!(forward.len(), backward.len());
    }
}

/// Concrete anchors: empty + singleton passthrough, and a two-detector collapse
/// that demotes the loser to a companion (the canonical cross-detector case).
#[test]
fn cross_detector_concrete_cases() {
    // Empty and singleton inputs pass through untouched.
    let empty = dedup_matches(build(&[]), &DedupScope::File);
    assert_eq!(dedup_cross_detector(empty).len(), 0);
    let one = dedup_matches(build(&[(0, 0, 0, 5, 0.9)]), &DedupScope::File);
    assert_eq!(one.len(), 1);
    assert_eq!(dedup_cross_detector(one).len(), 1);

    // Two detectors on the SAME credential+file collapse to one winner (the
    // higher-confidence det-1 at 0.9) with the loser demoted to a companion.
    let two = dedup_matches(
        build(&[(0, 0, 0, 5, 0.3), (1, 0, 0, 5, 0.9)]),
        &DedupScope::File,
    );
    assert_eq!(two.len(), 2, "two distinct detectors → two deduped matches");
    let out = dedup_cross_detector(two);
    assert_eq!(
        out.len(),
        1,
        "same credential+file collapses cross-detector"
    );
    let winner = &out[0];
    assert_eq!(
        &*winner.detector_id, "det-1",
        "higher-confidence detector wins"
    );
    let companions = winner
        .companions
        .keys()
        .filter(|k| k.starts_with("cross_detector."))
        .count();
    assert_eq!(companions, 1, "the demoted det-0 survives as a companion");
}
