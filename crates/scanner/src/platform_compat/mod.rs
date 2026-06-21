//! Cross-platform path helpers for scanner pipeline semantics.
//!
//! Scanner paths are input data, not proof of the host OS. A Linux process can
//! scan a Windows checkout or archive, so path predicates must treat `/` and
//! `\` as separators on every platform.

mod path;

pub(crate) use path::path_component_matches;
pub(crate) use path::{path_basename, path_basename_bytes, path_has_any_component};
