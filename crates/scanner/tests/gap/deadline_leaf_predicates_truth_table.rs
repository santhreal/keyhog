//! Leaf-predicate truth tables for the deadline module (`expired`,
//! `LoopDeadline::from_deadline`, `LoopDeadline::expired`). The sibling
//! `deadline_cadence_tick_dedup` test drives these ONLY through the cadence
//! wrappers with an already-reached deadline, so the NOT-yet-reached arm (a live
//! scan still under its wall-clock budget must KEEP GOING, not abort) and the
//! `None`/no-deadline arm were unexercised. A regression flipping the `>=`
//! comparison, the `budget.is_zero()` fallback, or the `None` handling would
//! silently abort every scan at iteration one (or, inversely, never honor a
//! timeout); these pin the full truth table directly.

use keyhog_scanner::testing::{
    deadline_expired_far_future_for_test, deadline_expired_none_for_test,
    deadline_expired_now_for_test, loop_deadline_expired_far_future_for_test,
    loop_deadline_expired_reached_for_test, loop_deadline_from_none_is_none_for_test,
};

#[test]
fn expired_none_deadline_is_never_expired() {
    assert!(
        !deadline_expired_none_for_test(),
        "no configured deadline must never report expired (an unbounded scan must not abort)"
    );
}

#[test]
fn expired_reached_deadline_is_expired() {
    assert!(
        deadline_expired_now_for_test(),
        "a deadline at/before now must report expired"
    );
}

#[test]
fn expired_far_future_deadline_is_not_expired() {
    assert!(
        !deadline_expired_far_future_for_test(),
        "a deadline an hour out must NOT report expired, the live-scan-keeps-going path"
    );
}

#[test]
fn loop_deadline_from_no_deadline_is_none() {
    assert!(
        loop_deadline_from_none_is_none_for_test(),
        "no deadline must yield no LoopDeadline (the `deadline?` early return)"
    );
}

#[test]
fn loop_deadline_past_deadline_is_expired_via_zero_budget() {
    assert!(
        loop_deadline_expired_reached_for_test(),
        "a past deadline yields a ZERO budget and reports expired via the is_zero() fallback"
    );
}

#[test]
fn loop_deadline_far_future_budget_is_not_expired() {
    assert!(
        !loop_deadline_expired_far_future_for_test(),
        "a comfortably-future budget (positive, ~zero elapsed) must NOT report expired"
    );
}
