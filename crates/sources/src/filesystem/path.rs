use std::path::Path;

/// Convert a `Path` to a user-facing display string, stripping the
/// `\\?\` Windows verbatim prefix on Windows.
pub(crate) fn display_path(path: &Path) -> String {
    let raw = path.display().to_string();
    if cfg!(windows) {
        keyhog_core::strip_windows_verbatim_prefix(&raw).to_string()
    } else {
        raw
    }
}
