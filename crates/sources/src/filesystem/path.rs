use std::path::Path;
use std::sync::Arc;

/// Convert a `Path` to a user-facing display string, stripping the
/// `\\?\` Windows verbatim prefix on Windows.
pub(crate) fn display_path(path: &Path) -> String {
    if cfg!(windows) {
        if let Some(s) = path.to_str() {
            keyhog_core::strip_windows_verbatim_prefix(s).to_string()
        } else {
            let raw = path.to_string_lossy();
            keyhog_core::strip_windows_verbatim_prefix(&raw).to_string()
        }
    } else if let Some(s) = path.to_str() {
        s.to_string()
    } else {
        path.to_string_lossy().into_owned()
    }
}

/// Convert a `Path` directly to a display `Arc<str>`, stripping the
/// Windows verbatim prefix without intermediate string formatting.
pub(crate) fn display_path_arc(path: &Path) -> Arc<str> {
    if cfg!(windows) {
        if let Some(s) = path.to_str() {
            Arc::from(keyhog_core::strip_windows_verbatim_prefix(s))
        } else {
            let raw = path.to_string_lossy();
            Arc::from(keyhog_core::strip_windows_verbatim_prefix(&raw))
        }
    } else if let Some(s) = path.to_str() {
        Arc::from(s)
    } else {
        Arc::from(path.to_string_lossy().as_ref())
    }
}
