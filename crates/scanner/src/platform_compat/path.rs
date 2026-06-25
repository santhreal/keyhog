//! Path separator normalization and component checks.

const PATH_SEPARATORS: [char; 2] = ['/', '\\'];

/// Return the final path component, accepting both `/` and `\` separators.
pub(crate) fn path_basename(path: &str) -> &str {
    path.rsplit(PATH_SEPARATORS).next().unwrap_or(path) // LAW10: split yields >=1 element; unwrap_or is the never-taken total default, recall-safe
}

/// Byte-slice basename for hot path checks that already operate on raw bytes.
pub(crate) fn path_basename_bytes(path: &[u8]) -> &[u8] {
    path.iter()
        .rposition(|&byte| byte == b'/' || byte == b'\\')
        .map(|index| &path[index + 1..])
        .unwrap_or(path) // LAW10: search/boundary miss => whole path is the basename; recall-safe
}

/// Run a predicate over each path component, accepting both separators.
pub(crate) fn path_component_matches(path: &str, predicate: impl FnMut(&str) -> bool) -> bool {
    path.split(PATH_SEPARATORS).any(predicate)
}

/// Case-insensitive match against any exact path component.
pub(crate) fn path_has_any_component<T: AsRef<str>>(path: &str, components: &[T]) -> bool {
    path_component_matches(path, |part| {
        components
            .iter()
            .any(|component| part.eq_ignore_ascii_case(component.as_ref()))
    })
}
