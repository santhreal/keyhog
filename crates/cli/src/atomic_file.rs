//! Same-directory atomic file replacement for CLI-owned JSON/report artifacts.

use std::io::{self, Write};
use std::path::Path;

#[cfg(test)]
const TEST_OBSERVE_DIR_ENV: &str = "KEYHOG_ATOMIC_FILE_TEST_OBSERVE_DIR";
#[cfg(test)]
const TEST_RELEASE_PATH_ENV: &str = "KEYHOG_ATOMIC_FILE_TEST_RELEASE_PATH";

#[cfg(test)]
fn hold_for_test_observation(tmp: &tempfile::NamedTempFile) -> io::Result<()> {
    let Some(observe_dir) = std::env::var_os(TEST_OBSERVE_DIR_ENV) else {
        return Ok(());
    };
    let release_path = std::env::var_os(TEST_RELEASE_PATH_ENV).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic-file test observation requires a release path",
        )
    })?;
    std::fs::create_dir_all(&observe_dir)?;
    std::fs::write(
        Path::new(&observe_dir).join(std::process::id().to_string()),
        tmp.path().as_os_str().as_encoded_bytes(),
    )?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !Path::new(&release_path).exists() {
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "parent did not release the observed atomic-file test publication",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    Ok(())
}

pub(crate) fn write_bytes(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_with_file(path, |mut file| file.write_all(bytes))
}

pub(crate) fn write_with_file<F>(path: &Path, write_fn: F) -> io::Result<()>
where
    F: FnOnce(std::fs::File) -> io::Result<()>,
{
    // A target that already exists and is NOT a regular file - a character
    // device (`/dev/null`, `/dev/stdout`, `/dev/stderr`), FIFO, or socket -
    // cannot be atomically replaced by rename, and its parent directory (e.g.
    // `/dev`) is typically not writable, so the temp-file step fails with a
    // confusing "Permission denied .../dev/.tmpXXXX". Write straight through to
    // such a target instead: the device accepts the bytes (discarding them for
    // `/dev/null`, forwarding them for `/dev/stdout`), which is exactly what the
    // operator asked for with `-o /dev/null`. Atomicity is meaningless for a
    // device anyway - there is no on-disk artifact to replace.
    if std::fs::metadata(path).is_ok_and(|meta| !meta.is_file()) {
        let file = std::fs::OpenOptions::new().write(true).open(path)?;
        return write_fn(file);
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new(".")); // LAW10: parentless output paths preserve the exact target in '.', recall-safe.
    std::fs::create_dir_all(parent)?;
    let tmp = tempfile::NamedTempFile::new_in(parent)?;
    let writer = tmp.reopen()?;
    write_fn(writer)?;
    tmp.as_file().sync_all()?;
    #[cfg(test)]
    hold_for_test_observation(&tmp)?;
    tmp.persist(path).map(drop).map_err(|error| error.error)
}
