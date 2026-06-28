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
