use std::time::{Duration, Instant};

#[inline]
pub(crate) fn expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}

/// Whether `iteration` lands on a cadence boundary worth re-checking the
/// deadline: a non-zero iteration that is a multiple of `cadence`. Single owner
/// for the gate so the `expired`/`loop_expired` cadence wrappers can't drift.
#[inline]
pub(crate) fn cadence_tick(iteration: usize, cadence: usize) -> bool {
    iteration > 0 && iteration.is_multiple_of(cadence)
}

/// Default re-check cadence for the hot per-iteration scan loops (generic
/// assignment extraction, the regex extract loops, the anchor scan). Each of
/// those loops is bounded by `MAX_INNER_LOOP_ITERS` and re-checks the wall-clock
/// deadline once every `HOT_LOOP_DEADLINE_CADENCE` iterations so the timeout is
/// honored without paying an `Instant::now()` per iteration. One owner for the
/// value so the loops cannot drift apart (the compiled-anchored phase uses its
/// own tighter cadence on purpose and is intentionally NOT this constant).
pub(crate) const HOT_LOOP_DEADLINE_CADENCE: usize = 64;

/// Re-check cadence for the compiled phase-2 per-pattern loops
/// (`phase2_compiled`, `phase2_compiled_anchored`). Each iteration runs a full
/// compiled-regex extraction, so these loops re-check the deadline four times
/// more often than the generic hot loops to keep an adversarial single-pattern
/// storm from overrunning the timeout by a wide margin. Single owner for the
/// value so the three compiled-phase call sites cannot drift apart.
pub(crate) const COMPILED_PHASE2_DEADLINE_CADENCE: usize = 16;

#[inline]
pub(crate) fn expired_on_cadence(
    deadline: Option<Instant>,
    iteration: usize,
    cadence: usize,
) -> bool {
    cadence_tick(iteration, cadence) && expired(deadline)
}

#[derive(Clone, Copy)]
pub(crate) struct LoopDeadline {
    start: Instant,
    budget: Duration,
}

impl LoopDeadline {
    #[inline]
    pub(crate) fn from_deadline(deadline: Option<Instant>) -> Option<Self> {
        let deadline = deadline?;
        let start = Instant::now();
        let budget = match deadline.checked_duration_since(start) {
            Some(budget) => budget,
            None => Duration::ZERO,
        };
        Some(Self { start, budget })
    }

    #[inline]
    pub(crate) fn expired(self) -> bool {
        self.budget.is_zero() || self.start.elapsed() >= self.budget
    }
}

#[inline]
pub(crate) fn loop_expired(deadline: Option<LoopDeadline>) -> bool {
    deadline.is_some_and(LoopDeadline::expired)
}

#[inline]
pub(crate) fn loop_expired_on_cadence(
    deadline: Option<LoopDeadline>,
    iteration: usize,
    cadence: usize,
) -> bool {
    cadence_tick(iteration, cadence) && loop_expired(deadline)
}
