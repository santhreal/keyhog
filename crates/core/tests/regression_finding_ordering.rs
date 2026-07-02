//! Regression lock for the `RawMatch` total ordering (`impl Ord for RawMatch`
//! in `keyhog_core::finding`), the sort keyed used by reporters and by the
//! capped per-chunk match heap to pick a deterministic survivor set.
//!
//! The ordering is a fixed key precedence, read directly off the source:
//!   1. confidence, DESCENDING (`other_conf.total_cmp(&self_conf)`), with an
//!      absent confidence treated as `0.0` (LAW10 recall-safe: `None` sorts as
//!      the lowest priority, never dropped);
//!   2. severity, DESCENDING (`other.severity.cmp(&self.severity)` — Critical
//!      before Info, the OPPOSITE direction of `Severity`'s own ascending Ord);
//!   3. detector_id, ASCENDING;
//!   4. credential, ASCENDING;
//!   5. location.offset ASCENDING, then location.line ASCENDING.
//!
//! `Vec::sort` places the cmp-"smallest" element first, so the highest-priority
//! finding (highest confidence, then highest severity, ...) lands at index 0.
//! detector_name is deliberately NOT a cmp key, so it is used here purely as a
//! stable per-finding TAG to assert exact sorted positions, and it also exposes
//! the (real) property that `cmp == Equal` does NOT imply `PartialEq == true`.
//!
//! Every assertion pins a CONCRETE value: an exact tag sequence, an exact
//! `Ordering` variant, or an exact index. No `is_empty()`/`len()>0`-only checks.
//! Host-independent: pure in-process API, no scanner engine, no accelerator.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;

use keyhog_core::{CredentialHash, MatchLocation, RawMatch, SensitiveString, Severity};

fn sha256(s: &str) -> CredentialHash {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    CredentialHash::from_bytes(h.finalize().into())
}

fn loc(offset: usize, line: usize) -> MatchLocation {
    MatchLocation {
        source: Arc::from("filesystem"),
        file_path: Some(Arc::from("creds.env")),
        line: Some(line),
        offset,
        commit: None,
        author: None,
        date: None,
    }
}

/// Build a `RawMatch`. `tag` is stored in the (non-cmp-key) `detector_name`
/// field so a sorted vec can be identified position-by-position.
#[allow(clippy::too_many_arguments)]
fn rm(
    det_id: &str,
    tag: &str,
    sev: Severity,
    cred: &str,
    conf: Option<f64>,
    offset: usize,
    line: usize,
) -> RawMatch {
    RawMatch {
        detector_id: Arc::from(det_id),
        detector_name: Arc::from(tag),
        service: Arc::from("svc"),
        severity: sev,
        credential: SensitiveString::from(cred),
        credential_hash: sha256(cred),
        companions: HashMap::new(),
        location: loc(offset, line),
        entropy: None,
        confidence: conf,
    }
}

/// Collect the `detector_name` tags of a slice in current order.
fn tags(v: &[RawMatch]) -> Vec<&str> {
    v.iter().map(|m| &*m.detector_name).collect()
}

// ---------------------------------------------------------------------------
// Key 1: confidence dominates everything below it.
// ---------------------------------------------------------------------------

#[test]
fn higher_confidence_sorts_before_higher_severity() {
    // A: high confidence but only Low severity. B: low confidence but Critical.
    // Confidence is the primary key, so A (0.9) MUST precede B (0.5) even though
    // B outranks A on severity.
    let mut v = vec![
        rm(
            "d",
            "critical_lowconf",
            Severity::Critical,
            "cb",
            Some(0.5),
            0,
            1,
        ),
        rm("d", "low_highconf", Severity::Low, "ca", Some(0.9), 0, 1),
    ];
    v.sort();
    assert_eq!(tags(&v), vec!["low_highconf", "critical_lowconf"]);
}

// ---------------------------------------------------------------------------
// Key 2: severity breaks a confidence tie, DESCENDING.
// ---------------------------------------------------------------------------

#[test]
fn equal_confidence_orders_by_severity_descending() {
    // Same confidence (0.7); severity decides. Critical before Info.
    let mut v = vec![
        rm("d", "info", Severity::Info, "cb", Some(0.7), 0, 1),
        rm("d", "critical", Severity::Critical, "ca", Some(0.7), 0, 1),
        rm("d", "medium", Severity::Medium, "cc", Some(0.7), 0, 1),
    ];
    v.sort();
    assert_eq!(tags(&v), vec!["critical", "medium", "info"]);
}

#[test]
fn rawmatch_severity_direction_is_flipped_vs_native_severity_ord() {
    // Native Severity Ord ranks Critical ABOVE Info (Greater). RawMatch's cmp
    // deliberately inverts it so the higher-severity finding sorts FIRST (Less).
    let crit = rm("d", "c", Severity::Critical, "x", Some(0.5), 0, 1);
    let info = rm("d", "i", Severity::Info, "y", Some(0.5), 0, 1);
    assert_eq!(Severity::Critical.cmp(&Severity::Info), Ordering::Greater);
    assert_eq!(crit.cmp(&info), Ordering::Less);
    assert_eq!(info.cmp(&crit), Ordering::Greater);
}

// ---------------------------------------------------------------------------
// Key 3: detector_id ASCENDING breaks a conf+severity tie.
// ---------------------------------------------------------------------------

#[test]
fn equal_conf_and_severity_orders_by_detector_id_ascending() {
    let mut v = vec![
        rm("zzz-det", "z", Severity::High, "cb", Some(0.4), 0, 1),
        rm("aaa-det", "a", Severity::High, "ca", Some(0.4), 0, 1),
        rm("mmm-det", "m", Severity::High, "cc", Some(0.4), 0, 1),
    ];
    v.sort();
    assert_eq!(tags(&v), vec!["a", "m", "z"]);
}

// ---------------------------------------------------------------------------
// Key 4: credential ASCENDING breaks a conf+severity+detector tie.
// ---------------------------------------------------------------------------

#[test]
fn equal_conf_severity_detector_orders_by_credential_ascending() {
    // Same detector_id, same conf/severity; credential lexicographic order wins.
    let mut v = vec![
        rm(
            "det",
            "beta",
            Severity::Medium,
            "beta-secret",
            Some(0.5),
            0,
            1,
        ),
        rm(
            "det",
            "alpha",
            Severity::Medium,
            "alpha-secret",
            Some(0.5),
            0,
            1,
        ),
    ];
    v.sort();
    assert_eq!(tags(&v), vec!["alpha", "beta"]);
}

// ---------------------------------------------------------------------------
// Key 5: offset ASCENDING, then line ASCENDING.
// ---------------------------------------------------------------------------

#[test]
fn final_tiebreak_is_offset_then_line_ascending() {
    // All keys equal except location. offset dominates line.
    let mut v = vec![
        rm("det", "off100", Severity::High, "c", Some(0.5), 100, 1),
        rm("det", "off5", Severity::High, "c", Some(0.5), 5, 9),
        rm("det", "off5_line2", Severity::High, "c", Some(0.5), 5, 2),
    ];
    v.sort();
    // offset 5 group first; within it line 2 before line 9. offset 100 last.
    assert_eq!(tags(&v), vec!["off5_line2", "off5", "off100"]);
}

// ---------------------------------------------------------------------------
// LAW10: absent confidence is treated as 0.0 (lowest), never dropped.
// ---------------------------------------------------------------------------

#[test]
fn none_confidence_sorts_last_but_is_retained() {
    let mut v = vec![
        rm("d", "none", Severity::Critical, "cb", None, 0, 1),
        rm("d", "tiny", Severity::Info, "ca", Some(0.01), 0, 1),
    ];
    v.sort();
    // Even a 0.01 confidence outranks a None (0.0), regardless of severity.
    assert_eq!(tags(&v), vec!["tiny", "none"]);
    // Retained: both findings survive the sort (recall-safe).
    assert_eq!(v.len(), 2);
}

#[test]
fn none_confidence_equals_explicit_zero_for_the_confidence_key() {
    // Some(0.0) and None both map to 0.0, so the confidence key TIES and the
    // severity key decides: the Critical finding (with None) beats the Low
    // finding (with Some(0.0)).
    let some_zero_low = rm("d", "some0_low", Severity::Low, "ca", Some(0.0), 0, 1);
    let none_crit = rm("d", "none_crit", Severity::Critical, "cb", None, 0, 1);
    assert_eq!(none_crit.cmp(&some_zero_low), Ordering::Less);
    let mut v = vec![some_zero_low, none_crit];
    v.sort();
    assert_eq!(tags(&v), vec!["none_crit", "some0_low"]);
}

// ---------------------------------------------------------------------------
// Full mixed batch: exact ordered positions across all key tiers.
// ---------------------------------------------------------------------------

#[test]
fn full_mixed_batch_sorts_to_exact_order() {
    let f1 = rm("d1", "crit_hi", Severity::Critical, "c1", Some(0.95), 0, 1);
    let f2 = rm("d2", "low_hi", Severity::Low, "c2", Some(0.95), 0, 1);
    let f3 = rm("d3", "crit_mid", Severity::Critical, "c3", Some(0.60), 0, 1);
    let f4 = rm("d4", "info_mid", Severity::Info, "c4", Some(0.60), 0, 1);
    let f5 = rm("d5", "none_crit", Severity::Critical, "c5", None, 0, 1);
    let f6 = rm("d6", "high_lo", Severity::High, "c6", Some(0.10), 0, 1);

    let mut v = vec![f1, f2, f3, f4, f5, f6];
    v.sort();
    // Primary descending confidence groups: {0.95}, {0.60}, {0.10}, {0.0=None}.
    // Within a confidence group, severity descending decides.
    assert_eq!(
        tags(&v),
        vec![
            "crit_hi",
            "low_hi",
            "crit_mid",
            "info_mid",
            "high_lo",
            "none_crit"
        ]
    );
    // Pin two individual positions explicitly.
    assert_eq!(&*v[0].detector_name, "crit_hi");
    assert_eq!(&*v[5].detector_name, "none_crit");
}

// ---------------------------------------------------------------------------
// Determinism: total order => any input permutation yields identical output.
// ---------------------------------------------------------------------------

#[test]
fn two_input_permutations_sort_identically() {
    let build = || {
        vec![
            rm("d1", "crit_hi", Severity::Critical, "c1", Some(0.95), 0, 1),
            rm("d2", "low_hi", Severity::Low, "c2", Some(0.95), 0, 1),
            rm("d3", "crit_mid", Severity::Critical, "c3", Some(0.60), 0, 1),
            rm("d6", "high_lo", Severity::High, "c6", Some(0.10), 0, 1),
        ]
    };
    let mut forward = build();
    forward.sort();

    let mut reversed = build();
    reversed.reverse();
    reversed.sort();

    let expected = vec!["crit_hi", "low_hi", "crit_mid", "high_lo"];
    assert_eq!(tags(&forward), expected);
    assert_eq!(tags(&reversed), expected);
}

// ---------------------------------------------------------------------------
// Reflexivity, antisymmetry, and PartialOrd agreement.
// ---------------------------------------------------------------------------

#[test]
fn cmp_is_reflexive_and_partial_cmp_agrees() {
    let a = rm("d", "a", Severity::High, "cred", Some(0.5), 3, 7);
    assert_eq!(a.cmp(&a), Ordering::Equal);
    assert_eq!(a.partial_cmp(&a), Some(Ordering::Equal));
}

#[test]
fn cmp_is_antisymmetric_for_ordered_pair() {
    // Higher confidence => Less (sorts first); the reverse is Greater.
    let hi = rm("d", "hi", Severity::Low, "ca", Some(0.9), 0, 1);
    let lo = rm("d", "lo", Severity::Critical, "cb", Some(0.2), 0, 1);
    assert_eq!(hi.cmp(&lo), Ordering::Less);
    assert_eq!(lo.cmp(&hi), Ordering::Greater);
    assert_eq!(hi.partial_cmp(&lo), Some(Ordering::Less));
}

// ---------------------------------------------------------------------------
// min() selects the highest-priority finding (the cmp-smallest).
// ---------------------------------------------------------------------------

#[test]
fn iter_min_selects_highest_priority_finding() {
    let v = vec![
        rm("d5", "none_crit", Severity::Critical, "c5", None, 0, 1),
        rm("d1", "crit_hi", Severity::Critical, "c1", Some(0.95), 0, 1),
        rm("d6", "high_lo", Severity::High, "c6", Some(0.10), 0, 1),
    ];
    let best = v.iter().min().expect("non-empty");
    assert_eq!(&*best.detector_name, "crit_hi");
    let worst = v.iter().max().expect("non-empty");
    assert_eq!(&*worst.detector_name, "none_crit");
}

// ---------------------------------------------------------------------------
// Adversarial: cmp==Equal does NOT imply PartialEq, and sort is STABLE so the
// tie-break preserves input order among cmp-Equal findings.
// ---------------------------------------------------------------------------

#[test]
fn cmp_equal_but_not_eq_and_stable_sort_preserves_input_order() {
    // Identical on every cmp KEY (conf, severity, detector_id, credential,
    // offset, line) but differing detector_name, which cmp ignores and
    // PartialEq compares.
    let make = |tag: &str| rm("det", tag, Severity::High, "same-cred", Some(0.5), 4, 2);
    let x = make("X");
    let y = make("Y");
    // cmp sees them as Equal ...
    assert_eq!(x.cmp(&y), Ordering::Equal);
    // ... yet PartialEq distinguishes them (detector_name differs).
    assert_ne!(x, y);

    // Stable sort keeps the original relative order of equal elements.
    let mut xy = vec![make("X"), make("Y")];
    xy.sort();
    assert_eq!(tags(&xy), vec!["X", "Y"]);

    let mut yx = vec![make("Y"), make("X")];
    yx.sort();
    assert_eq!(tags(&yx), vec!["Y", "X"]);
}
