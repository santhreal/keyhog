#![allow(
    missing_docs,
    dead_code,
    unused_imports,
    unused_variables,
    unreachable_patterns,
    clippy::all
)]
use crate::quick_cache::json_string_field;
use std::fs;
use std::io::{self};
use std::path::Path;

pub(crate) fn cached_outcome(path: &Path) -> Result<Option<String>, String> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(json_string_field(&content, "outcome")),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!(
            "could not read {}: {err}. Fix: remove corrupt cache file and rerun.",
            path.display()
        )),
    }
}
