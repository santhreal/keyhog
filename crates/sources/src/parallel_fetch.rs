//! Shared concurrency limits for remote source fetch fanout.

#[cfg(any(feature = "azure", feature = "s3", feature = "gcs"))]
pub(crate) const CLOUD_OBJECT_FETCH_THREADS: usize = 16;
#[cfg(any(
    feature = "slack",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket"
))]
pub(crate) const REMOTE_API_FETCH_THREADS: usize = 8;
