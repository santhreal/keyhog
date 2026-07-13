//! Bounded cache I/O and version-first decoding shared by every trust surface.

use std::io::Read;

use super::super::AUTOROUTE_CACHE_VERSION;
use super::schema::{AutorouteCache, AutorouteCacheVersionEnvelope};

pub(crate) const AUTOROUTE_CACHE_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// A version gate is evaluated before the version-specific payload so stale
/// caches produce an actionable incompatibility error rather than an opaque
/// missing-field deserialization failure.
pub(super) enum CacheParseError {
    NotJson(serde_json::Error),
    Version { found: u32 },
    Payload(serde_json::Error),
}

pub(super) fn parse_autoroute_cache(data: &[u8]) -> Result<AutorouteCache, CacheParseError> {
    let envelope: AutorouteCacheVersionEnvelope =
        serde_json::from_slice(data).map_err(CacheParseError::NotJson)?;
    if envelope.version != AUTOROUTE_CACHE_VERSION {
        return Err(CacheParseError::Version {
            found: envelope.version,
        });
    }
    serde_json::from_slice(data).map_err(CacheParseError::Payload)
}

pub(super) fn read_autoroute_cache_file(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len > AUTOROUTE_CACHE_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "autoroute cache exceeds {} byte cap; delete the cache file and rerun install calibration",
                AUTOROUTE_CACHE_FILE_BYTES
            ),
        ));
    }

    let mut data = Vec::with_capacity(len as usize);
    file.take(AUTOROUTE_CACHE_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut data)?;
    if data.len() as u64 > AUTOROUTE_CACHE_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "autoroute cache grew past {} byte cap while reading; retry after the file is stable",
                AUTOROUTE_CACHE_FILE_BYTES
            ),
        ));
    }
    Ok(data)
}
