use keyhog_core::SourceError;

pub(crate) fn collect_on_blocking_thread<T, F>(source: &'static str, f: F) -> Result<T, SourceError>
where
    T: Send,
    F: FnOnce() -> Result<T, SourceError> + Send,
{
    // Propagate the active profiling runtime (if any) onto the blocking fetch
    // thread so adapter spans and counters record there. `None` when no
    // profile is entered, which keeps the disabled path free.
    let profile_runtime = crate::profile::current_runtime();
    std::thread::scope(|scope| {
        match scope
            .spawn(move || {
                let _profile_guard = profile_runtime.as_ref().map(|runtime| runtime.enter());
                f()
            })
            .join()
        {
            Ok(result) => result,
            Err(_panic) => Err(SourceError::Other(format!(
                "{source} fetch thread panicked"
            ))),
        }
    })
}
