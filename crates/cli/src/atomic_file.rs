//! Same-directory atomic file replacement for CLI-owned JSON/report artifacts.

use std::io::{self, Write};
use std::path::Path;

pub(crate) fn write_bytes(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_with_file(path, |mut file| file.write_all(bytes))
}

pub(crate) fn write_with_file<F>(path: &Path, write_fn: F) -> io::Result<()>
where
    F: FnOnce(std::fs::File) -> io::Result<()>,
{
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new(".")); // LAW10: parentless output paths preserve the exact target in '.', recall-safe.
    std::fs::create_dir_all(parent)?;
    let tmp = tempfile::NamedTempFile::new_in(parent)?;
    let writer = tmp.reopen()?;
    write_fn(writer)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map(drop).map_err(|error| error.error)
}
