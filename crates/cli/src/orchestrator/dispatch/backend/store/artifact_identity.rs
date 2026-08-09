//! Exact identity of the running executable used by persisted calibration.

use std::sync::OnceLock;

pub(super) fn current_executable_sha256(
) -> Result<&'static str, Box<dyn std::error::Error + Send + Sync>> {
    static DIGEST: OnceLock<Result<String, String>> = OnceLock::new();
    DIGEST
        .get_or_init(keyhog_core::current_executable_sha256)
        .as_deref()
        .map_err(|error| error.clone().into())
}
