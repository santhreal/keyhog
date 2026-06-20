//! Shared bounded Rayon pools for remote source fetch fanout.

use keyhog_core::SourceError;

pub(crate) const CLOUD_OBJECT_FETCH_THREADS: usize = 16;
pub(crate) const REMOTE_API_FETCH_THREADS: usize = 8;

pub(crate) fn bounded_fetch_pool(
    source: &str,
    threads: usize,
) -> Result<rayon::ThreadPool, SourceError> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|error| SourceError::Other(format!("{source}: rayon pool build: {error}")))
}
