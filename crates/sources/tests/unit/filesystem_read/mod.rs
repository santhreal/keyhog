//! Organized unit tests for `crates/sources/src/filesystem/read`.
//!
//! Split by responsibility:
//!   * `decode` - binary-vs-text classification and text decoding.
//!   * `read`   - mmap, windowed mmap, and compressed-input read paths.
//!   * `boundary` - window slicing arithmetic and special-file safety.

#[cfg(unix)]
pub(crate) mod support;

pub mod boundary;
pub mod decode;
pub mod read;
