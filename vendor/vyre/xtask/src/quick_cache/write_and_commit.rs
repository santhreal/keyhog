#![allow(
    missing_docs,
    dead_code,
    unused_imports,
    unused_variables,
    unreachable_patterns,
    clippy::all
)]
use std::fs;
use std::io::{self, Write};
use std::path::Path;

pub(crate) fn write_and_commit(
    tmp: &mut fs::File,
    tmp_path: &Path,
    path: &Path,
    bytes: &[u8],
) -> io::Result<()> {
    tmp.write_all(bytes)?;
    tmp.sync_all()?;
    match fs::hard_link(tmp_path, path) {
        Ok(()) => fs::remove_file(tmp_path),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            let existing = fs::read(path)?;
            fs::remove_file(tmp_path)?;
            if existing == bytes {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "cache path already exists with different content: {}. Fix: investigate hash collision or corrupt cache file.",
                        path.display()
                    ),
                ))
            }
        }
        Err(err) => Err(err),
    }
}
