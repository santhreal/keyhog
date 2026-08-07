//! Shared concurrency limits for remote source fetch fanout.

#[cfg(any(feature = "azure", feature = "s3", feature = "gcs"))]
pub(crate) const CLOUD_OBJECT_FETCH_THREADS: usize = 16;

#[cfg(any(feature = "azure", feature = "s3", feature = "gcs"))]
pub(crate) fn bounded_fetch_pool(
    source: &str,
    threads: usize,
) -> Result<rayon::ThreadPool, keyhog_core::SourceError> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|error| {
            keyhog_core::SourceError::Other(format!("{source}: rayon pool build: {error}"))
        })
}
#[cfg(any(
    feature = "slack",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket"
))]
pub(crate) const REMOTE_API_FETCH_THREADS: usize = 8;
