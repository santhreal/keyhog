use keyhog_core::SourceError;

pub(crate) fn collect_on_blocking_thread<T, F>(source: &'static str, f: F) -> Result<T, SourceError>
where
    T: Send,
    F: FnOnce() -> Result<T, SourceError> + Send,
{
    std::thread::scope(|scope| match scope.spawn(f).join() {
        Ok(result) => result,
        Err(_panic) => Err(SourceError::Other(format!(
            "{source} fetch thread panicked"
        ))),
    })
}
