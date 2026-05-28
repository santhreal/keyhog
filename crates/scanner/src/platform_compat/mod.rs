//! Cross-platform path and I/O helpers for scanner pipeline semantics.
//!
//! Windows and Unix differ in path separators and line-ending conventions;
//! these helpers centralize the cfg-gated behavior instead of scattering
//! ad-hoc `replace('\\', "/")` calls through hot paths.

mod io;
mod path;

pub use io::{count_logical_lines, line_start_offsets_for_style};
pub use path::{normalize_path_separators, path_basename, path_has_component, preferred_askpass_extension};

#[cfg(unix)]
pub fn platform_family() -> &'static str {
    "unix"
}

#[cfg(windows)]
pub fn platform_family() -> &'static str {
    "windows"
}

#[cfg(not(any(unix, windows)))]
pub fn platform_family() -> &'static str {
    "other"
}
