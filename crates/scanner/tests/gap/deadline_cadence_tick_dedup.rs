//! Gap test: the deadline cadence gate is one shared predicate.
//!
//! `expired_on_cadence` and `loop_expired_on_cadence` both gated on the verbatim
//! `iteration > 0 && iteration.is_multiple_of(cadence)`. That gate is now the
//! single `cadence_tick` helper both wrappers AND with their deadline check.
//! Pin the exact truth table of the helper, and, driving each wrapper with an
//! already-reached deadline so its deadline check is always true, pin that each
//! wrapper's result equals the gate (so they cannot drift from `cadence_tick`).

use keyhog_scanner::testing::{
    cadence_tick_for_test, expired_on_cadence_now_for_test, loop_expired_on_cadence_now_for_test,
};

// (iteration, cadence, expected gate)
const CASES: &[(usize, usize, bool)] = &[
    (0, 3, false), // iteration 0 never ticks
    (1, 3, false), // 1 % 3 != 0
    (2, 3, false), // 2 % 3 != 0
    (3, 3, true),  // multiple of cadence
    (6, 3, true),  // multiple of cadence
    (4, 2, true),  // multiple of cadence
    (5, 2, false), // 5 % 2 != 0
    (1, 1, true),  // every non-zero iteration ticks at cadence 1
    (0, 1, false), // iteration 0 never ticks, even at cadence 1
];

#[test]
fn cadence_tick_truth_table_is_exact() {
    for &(iteration, cadence, expected) in CASES {
        assert_eq!(
            cadence_tick_for_test(iteration, cadence),
            expected,
            "cadence_tick({iteration}, {cadence}) must be {expected}"
        );
    }
}

#[test]
fn both_cadence_wrappers_equal_the_gate_when_deadline_is_reached() {
    for &(iteration, cadence, expected) in CASES {
        // Deadline already reached => the deadline check is always true, so each
        // wrapper's result is exactly cadence_tick(iteration, cadence).
        assert_eq!(
            expired_on_cadence_now_for_test(iteration, cadence),
            expected,
            "expired_on_cadence({iteration}, {cadence}) with a reached deadline must equal the gate"
        );
        assert_eq!(
            loop_expired_on_cadence_now_for_test(iteration, cadence),
            expected,
            "loop_expired_on_cadence({iteration}, {cadence}) with a reached deadline must equal the gate"
        );
    }
}
