//! Adversarial contract for the bounded per-context evidence dedup set.
//!
//! Once-per-runtime accelerator evidence is deduplicated by a `(context, slot)`
//! set. That set is process-wide and unbounded input reaches it: a long-lived
//! daemon creates a fresh profile runtime per request, so a hostile or merely
//! busy workload can drive the distinct-context count arbitrarily high. The
//! contract is that the set stops growing at `MAX_RECORDED_CONTEXTS`, counts
//! every dropped record, and never panics, re-records, or grows without bound.
//! Without this test the cap could be raised, removed, or made silent and only
//! a memory-growth incident would reveal it.

use super::{ContextClaimSet, MAX_RECORDED_CONTEXTS};

/// A fresh set claims each `(context, slot)` exactly once and rejects repeats
/// without counting them as loss: a repeat is correct dedup, not a drop.
#[test]
fn repeat_claims_are_rejected_without_being_counted_as_loss() {
    let mut claims = ContextClaimSet::new();
    assert!(claims.claim(7, 1), "first claim of a slot must succeed");
    assert!(!claims.claim(7, 1), "a repeat claim must be rejected");
    assert!(!claims.claim(7, 1), "repeats stay rejected");
    assert!(
        claims.claim(7, 2),
        "a different slot on the same context is a distinct record"
    );
    assert!(
        claims.claim(8, 1),
        "the same slot on a different context is a distinct record"
    );
    assert_eq!(claims.lost, 0, "dedup rejection is not evidence loss");
}

/// Filling the set to capacity keeps every retained key claimable exactly once,
/// and every claim past capacity is refused and counted. The exact counts here
/// are the point: an off-by-one in the capacity check would either retain one
/// record too many or under-report the loss by one.
#[test]
fn claims_past_capacity_are_refused_and_counted_exactly() {
    let mut claims = ContextClaimSet::new();
    for context in 0..MAX_RECORDED_CONTEXTS as u64 {
        assert!(
            claims.claim(context, 0),
            "context {context} is within capacity and must be retained"
        );
    }
    assert_eq!(
        claims.lost, 0,
        "filling exactly to capacity must lose nothing"
    );

    let overflow = 5_u64;
    for step in 0..overflow {
        let context = MAX_RECORDED_CONTEXTS as u64 + step;
        assert!(
            !claims.claim(context, 0),
            "context {context} is past capacity and must be refused"
        );
    }
    assert_eq!(
        claims.lost, overflow,
        "every refused-for-capacity record is counted exactly once"
    );

    // A retained key still dedups normally after overflow, and that rejection
    // must not inflate the loss count.
    assert!(!claims.claim(0, 0), "a retained key still dedups");
    assert_eq!(
        claims.lost, overflow,
        "dedup of a retained key after overflow is not additional loss"
    );
}

/// The loss counter saturates instead of wrapping. A wrapped counter would
/// report zero loss during exactly the sustained overflow it exists to expose.
#[test]
fn loss_counter_saturates_instead_of_wrapping() {
    let mut claims = ContextClaimSet::new();
    for context in 0..MAX_RECORDED_CONTEXTS as u64 {
        assert!(claims.claim(context, 0));
    }
    claims.lost = u64::MAX;
    assert!(!claims.claim(u64::MAX, 0), "still past capacity");
    assert_eq!(
        claims.lost,
        u64::MAX,
        "loss must saturate at u64::MAX, never wrap to zero"
    );
}
