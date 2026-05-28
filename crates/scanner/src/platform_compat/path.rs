//! Path separator normalization and component checks.
use std::borrow::Cow;

/// Normalize path separators to forward slashes for internal matching.
pub fn normalize_path_separators(path: &str) -> Cow<'_, str> {
    if cfg!(windows) && path.contains('\\') {
        Cow::Owned(path.replace('\\', "/"))
    } else {
        Cow::Borrowed(path)
    }
}

/// Return the final path component, accepting both `/` and `\` separators.
pub fn path_basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// Case-insensitive path segment match used by example/test fixture gates.
pub fn path_has_component(path: &str, component: &str) -> bool {
    normalize_path_separators(path)
        .split('/')
        .any(|part| part.eq_ignore_ascii_case(component))
}

#[cfg(unix)]
pub fn preferred_askpass_extension() -> &'static str {
    ".sh"
}

#[cfg(windows)]
pub fn preferred_askpass_extension() -> &'static str {
    ".bat"
}

#[cfg(not(any(unix, windows)))]
pub fn preferred_askpass_extension() -> &'static str {
    ".sh"
}
