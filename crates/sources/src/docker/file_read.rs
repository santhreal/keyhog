use keyhog_core::SourceError;
use std::fs::File;
use std::path::Path;

pub(super) fn read_capped_file(path: &Path, kind: &str, cap: u64) -> Result<Vec<u8>, SourceError> {
    let file = File::open(path).map_err(|error| {
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
