use std::time::Instant;

#[inline]
pub(crate) fn expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}

#[inline]
pub(crate) fn expired_on_cadence(
    deadline: Option<Instant>,
    iteration: usize,
    cadence: usize,
) -> bool {
    iteration > 0 && iteration.is_multiple_of(cadence) && expired(deadline)
}
