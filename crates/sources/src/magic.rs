//! Shared byte signatures for file/container format identification.
//!
//! Keep raw magic bytes here instead of repeating literals across sources.
//! Callers still own semantics: text decode rejects these as binary input,
//! Docker layer extraction routes them to the matching decompressor.

pub(crate) const GZIP_PREFIX: &[u8] = b"\x1f\x8b";
pub(crate) const ZSTD_FRAME_MAGIC: &[u8] = b"\x28\xb5\x2f\xfd";

#[inline]
#[cfg(feature = "docker")]
pub(crate) fn starts_with_gzip(bytes: &[u8]) -> bool {
    bytes.starts_with(GZIP_PREFIX)
}

#[inline]
#[cfg(feature = "docker")]
pub(crate) fn starts_with_zstd_frame(bytes: &[u8]) -> bool {
    bytes.starts_with(ZSTD_FRAME_MAGIC)
}
