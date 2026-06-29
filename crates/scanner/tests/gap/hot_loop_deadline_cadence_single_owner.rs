//! Gap test: the hot per-iteration scan loops share ONE deadline re-check
//! cadence.
//!
//! The generic-assignment extraction loop (`phase2_generic.rs`), the two regex
//! extract loops (`extract.rs`), and the anchor scan loop (`phase2_anchor_scan.rs`)
//! each re-check the wall-clock deadline once every N iterations. That N was the
//! bare literal `64` copied across four files — a drift hazard, since the loops
//! must agree (so the timeout is honored at the same rate everywhere). It is now
//! the single `deadline::HOT_LOOP_DEADLINE_CADENCE` owner.
//!
//! Pin the exact value AND the tick behavior: driving `expired_on_cadence` /
//! `loop_expired_on_cadence` with an already-reached deadline, the result is the
//! cadence gate, which must fire exactly on the nonzero multiples of the shared
//! cadence and nowhere else. The compiled-anchored phase deliberately uses a
//! tighter cadence and is intentionally not this constant — proven distinct.

use keyhog_scanner::testing::{
    expired_on_cadence_now_for_test, hot_loop_deadline_cadence_for_test,
    loop_expired_on_cadence_now_for_test,
};

#[test]
fn hot_loop_cadence_is_exactly_64() {
    assert_eq!(
        hot_loop_deadline_cadence_for_test(),
        64,
        "the shared hot-loop deadline re-check cadence must be 64"
    );
}

#[test]
fn both_wrappers_tick_only_on_nonzero_multiples_of_the_shared_cadence() {
    let cadence = hot_loop_deadline_cadence_for_test();
    // Walk two full cadence windows plus a bit so we cover iteration 0, the
    // first boundary (64), the second boundary (128), and the off-boundary
    // iterations in between.
    for iteration in 0..=(2 * cadence + 1) {
        let on_boundary = iteration > 0 && iteration % cadence == 0;
        assert_eq!(
            expired_on_cadence_now_for_test(iteration, cadence),
            on_boundary,
            "expired_on_cadence at iteration {iteration} (cadence {cadence}) must be {on_boundary}"
        );
        assert_eq!(
            loop_expired_on_cadence_now_for_test(iteration, cadence),
            on_boundary,
            "loop_expired_on_cadence at iteration {iteration} (cadence {cadence}) must be {on_boundary}"
        );
    }
}

#[test]
fn the_two_boundaries_in_the_first_two_windows_are_64_and_128() {
    let cadence = hot_loop_deadline_cadence_for_test();
    let boundaries: Vec<usize> = (0..=(2 * cadence))
        .filter(|&i| expired_on_cadence_now_for_test(i, cadence))
        .collect();
    assert_eq!(
        boundaries,
        vec![64, 128],
        "the deadline re-check fires exactly at iterations 64 and 128 across two windows"
    );
}
