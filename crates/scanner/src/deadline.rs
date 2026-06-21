#[inline]
pub(crate) fn expired(deadline: Option<std::time::Instant>) -> bool {
    deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline)
}
