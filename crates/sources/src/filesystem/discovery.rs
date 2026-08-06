use codewalk::{CodeWalker, FileEntry};
use keyhog_core::SourceError;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::ffi::OsStr;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

const BINARY_PATH_LEN_BIT: u32 = 1 << 31;
const PATH_LEN_MASK: u32 = BINARY_PATH_LEN_BIT - 1;

#[derive(Clone, Copy)]
struct EntryRow {
    size: u64,
    path_start: u32,
    path_len_and_binary: u32,
}

/// Path-sorted walk metadata without one heap allocation per discovered file.
///
/// Linux filesystem scans dominate the large-tree workload, so Unix stores
/// each path relative to the common scan root in one byte slab. Other targets
/// retain `FileEntry` values and preserve their native path representation.
pub(super) enum SortedEntries {
    #[cfg(unix)]
    Compact(CompactEntries),
    #[cfg(not(unix))]
    Native(std::vec::IntoIter<FileEntry>),
}

#[cfg(unix)]
pub(super) struct CompactEntries {
    root: PathBuf,
    path_bytes: Vec<u8>,
    rows: Vec<EntryRow>,
    order: std::vec::IntoIter<u32>,
}

impl Iterator for SortedEntries {
    type Item = FileEntry;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            #[cfg(unix)]
            Self::Compact(entries) => entries.next(),
            #[cfg(not(unix))]
            Self::Native(entries) => entries.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            #[cfg(unix)]
            Self::Compact(entries) => entries.size_hint(),
            #[cfg(not(unix))]
            Self::Native(entries) => entries.size_hint(),
        }
    }
}

#[cfg(unix)]
impl Iterator for CompactEntries {
    type Item = FileEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let row = self.rows[self.order.next()? as usize];
        let start = row.path_start as usize;
        let len = (row.path_len_and_binary & PATH_LEN_MASK) as usize;
        let relative = Path::new(OsStr::from_bytes(&self.path_bytes[start..start + len]));
        Some(FileEntry {
            path: self.root.join(relative),
            size: row.size,
            is_binary: row.path_len_and_binary & BINARY_PATH_LEN_BIT != 0,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.order.size_hint()
    }
}

/// Collect an unbounded parallel walk into compact, deterministic metadata.
///
/// File reads still start only after discovery completes, preserving the
/// path-sorted chunk order required by autoroute replay. The common-root path
/// slab removes retained absolute paths after each bounded walker-channel
/// entry is consumed.
pub(super) fn collect_unbounded_sorted(
    walker: CodeWalker,
    root: &Path,
    walk_threads: usize,
) -> (SortedEntries, Vec<SourceError>, usize, u64) {
    let _walk = crate::profile::walk_span();
    let mut errors = Vec::new();
    let mut count = 0usize;
    let mut bytes = 0u64;

    #[cfg(unix)]
    let mut builder = CompactEntriesBuilder::new(root.to_path_buf());
    #[cfg(not(unix))]
    let mut entries = Vec::new();

    for result in walker.walk_parallel(walk_threads) {
        match result {
            Ok(entry) => {
                let size = entry.size;
                #[cfg(unix)]
                if let Err(error) = builder.push(entry) {
                    let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                    errors.push(error);
                    break;
                }
                #[cfg(not(unix))]
                entries.push(entry);
                count = count.saturating_add(1);
                bytes = bytes.saturating_add(size);
            }
            Err(error) => {
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                tracing::warn!(
                    %error,
                    "skipping unreadable filesystem entry; scan continues"
                );
                errors.push(SourceError::Other(format!(
                    "failed to inspect filesystem entry: {error}; entry was not scanned"
                )));
            }
        }
    }

    #[cfg(unix)]
    let sorted = SortedEntries::Compact(builder.finish());
    #[cfg(not(unix))]
    let sorted = {
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        SortedEntries::Native(entries.into_iter())
    };

    (sorted, errors, count, bytes)
}

#[cfg(unix)]
struct CompactEntriesBuilder {
    root: PathBuf,
    path_bytes: Vec<u8>,
    rows: Vec<EntryRow>,
}

#[cfg(unix)]
impl CompactEntriesBuilder {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            path_bytes: Vec::new(),
            rows: Vec::new(),
        }
    }

    fn push(&mut self, entry: FileEntry) -> Result<(), SourceError> {
        if self.rows.len() >= u32::MAX as usize {
            return Err(metadata_limit_error());
        }
        let relative = entry.path.strip_prefix(&self.root).map_err(|_| {
            SourceError::Other(format!(
                "filesystem walker returned path '{}' outside scan root '{}'; entry and remaining tree were not scanned",
                entry.path.display(),
                self.root.display()
            ))
        })?;
        let path = relative.as_os_str().as_bytes();
        let path_end = self
            .path_bytes
            .len()
            .checked_add(path.len())
            .filter(|end| *end <= u32::MAX as usize)
            .ok_or_else(metadata_limit_error)?;
        let start = self.path_bytes.len() as u32;
        let len = u32::try_from(path.len()).map_err(|_| metadata_limit_error())?;
        if len > PATH_LEN_MASK {
            return Err(metadata_limit_error());
        }
        debug_assert_eq!(path_end, self.path_bytes.len() + path.len());
        self.path_bytes.extend_from_slice(path);
        self.rows.push(EntryRow {
            size: entry.size,
            path_start: start,
            path_len_and_binary: len
                | if entry.is_binary {
                    BINARY_PATH_LEN_BIT
                } else {
                    0
                },
        });
        Ok(())
    }

    fn finish(self) -> CompactEntries {
        let mut order = (0..self.rows.len() as u32).collect::<Vec<_>>();
        let rows = &self.rows;
        let paths = &self.path_bytes;
        order.sort_unstable_by(|left, right| {
            let left = rows[*left as usize];
            let right = rows[*right as usize];
            row_path(paths, left).cmp(row_path(paths, right))
        });
        CompactEntries {
            root: self.root,
            path_bytes: self.path_bytes,
            rows: self.rows,
            order: order.into_iter(),
        }
    }
}

#[cfg(unix)]
fn row_path(paths: &[u8], row: EntryRow) -> &[u8] {
    let start = row.path_start as usize;
    let len = (row.path_len_and_binary & PATH_LEN_MASK) as usize;
    &paths[start..start + len]
}

#[cfg(unix)]
fn metadata_limit_error() -> SourceError {
    tracing::warn!("filesystem discovery metadata exceeded compact path limits");
    SourceError::Other(
        "filesystem discovery metadata exceeded the supported 4 GiB path table; remaining files were not scanned"
            .to_owned(),
    )
}
