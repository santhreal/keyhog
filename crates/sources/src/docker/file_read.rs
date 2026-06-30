use keyhog_core::SourceError;
use std::path::Path;

pub(super) fn read_capped_file(path: &Path, kind: &str, cap: u64) -> Result<Vec<u8>, SourceError> {
    // Route through the crate's safe-open boundary (O_NOFOLLOW + O_NONBLOCK +
    // post-open fd fstat). A malicious OCI layout can plant a blob path that is a
    // symlink (`blobs/sha256/<digest> -> /etc/shadow`); a raw `File::open` would
    // follow it and scan the off-target file. O_NOFOLLOW refuses it; the read is
    // never redirected off the layout.
    let file = crate::filesystem::open_file_safe(path).map_err(|error| {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        SourceError::Io(error)
    })?;
    let metadata = file.metadata().map_err(|error| {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        SourceError::Io(error)
    })?;
    if metadata.len() > cap {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
        return Err(SourceError::Other(format!(
            "{kind} '{}' exceeds {} bytes",
            path.display(),
            cap
        )));
    }
    let read =
        crate::capped_read::read_to_cap(file, cap, Some(metadata.len())).map_err(|error| {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            SourceError::Io(error)
        })?;
    if read.truncated {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
        return Err(SourceError::Other(format!(
            "{kind} '{}' exceeded {} bytes while reading",
            path.display(),
            cap
        )));
    }
    Ok(read.bytes)
}
