//! HTTPS-backed read-through cache. Feature-gated on `remote` so library
//! users who only want disk caching don't pull in `ureq`.

use super::disk::read_verified_cache_blob;
use super::fingerprint::PipelineFingerprint;
use super::store::PipelineCacheStore;

/// HTTPS-backed cache that reads pre-compiled artifacts from a
/// base URL. Feature-gated on `remote` so library users who only
/// want disk caching don't pull in `ureq`.
///
/// Writes are **no-ops** — `RemoteCache` is a read-through layer.
/// Publishing to a remote registry is a separate `vyre publish-cache`
/// xtask, not part of this runtime.
pub struct RemoteCache {
    base_url: String,
}

impl RemoteCache {
    /// Construct from a base URL. The cache fetches
    /// `<base_url>/<fp_hex>.bin` for each lookup.
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
        }
    }
}

impl PipelineCacheStore for RemoteCache {
    fn get(&self, fp: &PipelineFingerprint) -> Option<Vec<u8>> {
        let url = format!("{}/{}.bin", self.base_url.trim_end_matches('/'), fp.hex());
        let resp = ureq::get(&url).call().ok()?;
        read_verified_cache_blob(resp.into_reader())
    }

    fn put(&self, _fp: PipelineFingerprint, _artifact: Vec<u8>) {
        // Remote cache is read-through; publishing is a separate flow.
    }
}
