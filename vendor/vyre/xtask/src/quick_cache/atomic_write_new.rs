#![allow(
    missing_docs,
    dead_code,
    unused_imports,
    unused_variables,
    unreachable_patterns,
    clippy::all
)]
use crate::quick_cache::{temp_path, write_and_commit};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

pub(crate) fn atomic_write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp_path = temp_path(path);
    let mut tmp = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)?;
    if let Err(err) = write_and_commit(&mut tmp, &tmp_path, path, bytes) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }
    Ok(())
}
