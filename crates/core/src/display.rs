//! Shared display-only string normalization.

/// Strip the Windows verbatim path prefix (`\\?\`) from a display string.
///
/// Windows canonical paths can carry this prefix for extended-length path
/// handling. Keyhog does not need that escape marker in operator-facing output,
/// but this helper intentionally stays allocation-free: network paths such as
/// `\\?\UNC\server\share` become `UNC\server\share`, matching the historical
/// display contract instead of rebuilding a leading `\\`.
#[must_use]
pub fn strip_windows_verbatim_prefix(path: &str) -> &str {
    path.strip_prefix(r"\\?\").unwrap_or(path) // LAW10: no verbatim prefix -> return path unchanged; display normalization only
}
