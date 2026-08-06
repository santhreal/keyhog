use codewalk::{CodeWalker, FileEntry};
use keyhog_core::SourceError;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::cmp::Ordering;
#[cfg(unix)]
use std::collections::BinaryHeap;
#[cfg(unix)]
use std::ffi::OsStr;
#[cfg(unix)]
use std::io::{BufWriter, Write};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

#[cfg(unix)]
const BINARY_PATH_LEN_BIT: u32 = 1 << 31;
#[cfg(unix)]
const PATH_LEN_MASK: u32 = BINARY_PATH_LEN_BIT - 1;
#[cfg(unix)]
const RUN_ROW_LIMIT: usize = 16 * 1024;
#[cfg(unix)]
const RUN_PATH_BYTE_LIMIT: usize = 1024 * 1024;
#[cfg(unix)]
const RECORD_HEADER_LEN: usize = 12;

#[cfg(unix)]
#[derive(Clone, Copy)]
struct EntryRow {
    size: u64,
    path_start: u32,
    path_len_and_binary: u32,
}

/// Path-sorted walk metadata without resident state proportional to the tree.
///
/// Unix sorts bounded native-byte path runs into a private temporary file and
/// merges them through a small heap. Other targets retain `FileEntry` values
/// and preserve their native path representation.
pub(super) enum SortedEntries {
    #[cfg(unix)]
    Compact(CompactEntries),
    #[cfg(not(unix))]
    Native(std::vec::IntoIter<FileEntry>),
}

#[cfg(unix)]
pub(super) struct CompactEntries {
    root: PathBuf,
    mmap: Option<memmap2::Mmap>,
    runs: Vec<ActiveRun>,
    pending: BinaryHeap<PendingEntry>,
    remaining: usize,
    page_size: usize,
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
        let entry = self.pending.pop()?;
        self.remaining -= 1;
        let run_index = entry.run_index;
        let (next, discard_start, discard_end) = {
            let mmap = self.mmap.as_deref()?;
            let run = self.runs.get_mut(run_index)?;
            let next = read_pending(mmap, run, run_index, &self.root);
            let discard_start = align_up(run.discarded_to, self.page_size);
            let discard_end = align_down(run.cursor, self.page_size);
            if discard_end > discard_start {
                run.discarded_to = discard_end;
            }
            (next, discard_start, discard_end)
        };
        if let Some(next) = next {
            self.pending.push(next);
        }
        if discard_end > discard_start {
            if let Some(mmap) = self.mmap.as_ref() {
                // SAFETY: both boundaries are page-aligned inside the immutable
                // mapping, and every record in this range has been copied out.
                unsafe {
                    libc::madvise(
                        mmap.as_ptr().add(discard_start).cast_mut().cast(),
                        discard_end - discard_start,
                        libc::MADV_DONTNEED,
                    );
                }
            }
        }

        Some(FileEntry {
            path: entry.path,
            size: entry.size,
            is_binary: entry.is_binary,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

/// Collect an unbounded parallel walk into bounded, deterministic metadata.
///
/// File reads still start only after discovery completes, preserving the
/// path-sorted chunk order required by autoroute replay. Unix external-merges
/// bounded native-byte runs so path metadata does not remain heap-resident.
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
    let mut builder = match CompactEntriesBuilder::new(root.to_path_buf()) {
        Ok(builder) => Some(builder),
        Err(error) => {
            errors.push(error);
            None
        }
    };
    #[cfg(not(unix))]
    let mut entries = Vec::new();
    #[cfg(unix)]
    let can_walk = builder.is_some();
    #[cfg(not(unix))]
    let can_walk = true;

    if can_walk {
        for result in walker.walk_parallel(walk_threads) {
            match result {
                Ok(entry) => {
                    let size = entry.size;
                    #[cfg(unix)]
                    {
                        let Some(active_builder) = builder.as_mut() else {
                            break;
                        };
                        if let Err(error) = active_builder.push(entry) {
                            let _event =
                                crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                            errors.push(error);
                            builder = None;
                            break;
                        }
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
    }

    #[cfg(unix)]
    let sorted = match builder.and_then(|builder| match builder.finish() {
        Ok(entries) => Some(entries),
        Err(error) => {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            errors.push(error);
            None
        }
    }) {
        Some(entries) => SortedEntries::Compact(entries),
        None => {
            count = 0;
            bytes = 0;
            SortedEntries::Compact(CompactEntries::empty(root.to_path_buf()))
        }
    };
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
    spool: BufWriter<std::fs::File>,
    spool_offset: u64,
    runs: Vec<RunDescriptor>,
    path_bytes: Vec<u8>,
    rows: Vec<EntryRow>,
    total_rows: u64,
    total_path_bytes: u64,
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct RunDescriptor {
    start: usize,
    end: usize,
    count: u32,
}

#[cfg(unix)]
struct ActiveRun {
    cursor: usize,
    end: usize,
    remaining: u32,
    discarded_to: usize,
}

#[cfg(unix)]
#[derive(Eq)]
struct PendingEntry {
    path: PathBuf,
    size: u64,
    is_binary: bool,
    run_index: usize,
}

#[cfg(unix)]
impl Ord for PendingEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .path
            .cmp(&self.path)
            .then_with(|| other.run_index.cmp(&self.run_index))
    }
}

#[cfg(unix)]
impl PartialOrd for PendingEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(unix)]
impl PartialEq for PendingEntry {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path && self.run_index == other.run_index
    }
}

#[cfg(unix)]
impl CompactEntries {
    fn empty(root: PathBuf) -> Self {
        Self {
            root,
            mmap: None,
            runs: Vec::new(),
            pending: BinaryHeap::new(),
            remaining: 0,
            page_size: page_size(),
        }
    }
}

#[cfg(unix)]
impl CompactEntriesBuilder {
    fn new(root: PathBuf) -> Result<Self, SourceError> {
        let spool = tempfile::tempfile().map_err(SourceError::Io)?;
        Ok(Self {
            root,
            spool: BufWriter::new(spool),
            spool_offset: 0,
            runs: Vec::new(),
            path_bytes: Vec::new(),
            rows: Vec::new(),
            total_rows: 0,
            total_path_bytes: 0,
        })
    }

    fn push(&mut self, entry: FileEntry) -> Result<(), SourceError> {
        if self.total_rows >= u32::MAX as u64 {
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
        let total_path_bytes = self
            .total_path_bytes
            .checked_add(path.len() as u64)
            .filter(|total| *total <= u32::MAX as u64)
            .ok_or_else(metadata_limit_error)?;
        let len = u32::try_from(path.len()).map_err(|_| metadata_limit_error())?;
        if len > PATH_LEN_MASK {
            return Err(metadata_limit_error());
        }
        if !self.rows.is_empty()
            && (self.rows.len() >= RUN_ROW_LIMIT
                || self.path_bytes.len().saturating_add(path.len()) > RUN_PATH_BYTE_LIMIT)
        {
            self.flush_run()?;
        }

        let start = self.path_bytes.len() as u32;
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
        self.total_rows += 1;
        self.total_path_bytes = total_path_bytes;
        Ok(())
    }

    fn flush_run(&mut self) -> Result<(), SourceError> {
        if self.rows.is_empty() {
            return Ok(());
        }
        let paths = &self.path_bytes;
        self.rows
            .sort_unstable_by(|left, right| row_path(paths, *left).cmp(row_path(paths, *right)));
        let start = usize::try_from(self.spool_offset).map_err(|_| metadata_limit_error())?;
        for row in &self.rows {
            let path = row_path(&self.path_bytes, *row);
            self.spool
                .write_all(&row.size.to_le_bytes())
                .and_then(|_| self.spool.write_all(&row.path_len_and_binary.to_le_bytes()))
                .and_then(|_| self.spool.write_all(path))
                .map_err(SourceError::Io)?;
            self.spool_offset = self
                .spool_offset
                .checked_add(RECORD_HEADER_LEN as u64 + path.len() as u64)
                .ok_or_else(metadata_limit_error)?;
        }
        let end = usize::try_from(self.spool_offset).map_err(|_| metadata_limit_error())?;
        self.runs.push(RunDescriptor {
            start,
            end,
            count: self.rows.len() as u32,
        });
        self.rows.clear();
        self.path_bytes.clear();
        Ok(())
    }

    fn finish(mut self) -> Result<CompactEntries, SourceError> {
        self.flush_run()?;
        self.spool.flush().map_err(SourceError::Io)?;
        if self.total_rows == 0 {
            return Ok(CompactEntries::empty(self.root));
        }
        let file = self
            .spool
            .into_inner()
            .map_err(|error| SourceError::Io(error.into_error()))?;
        // SAFETY: the tempfile is private and unlinked, all writes are flushed,
        // and no writable handle survives creation of this immutable mapping.
        let mmap = unsafe { memmap2::MmapOptions::new().map(&file) }.map_err(SourceError::Io)?;
        let expected_len =
            usize::try_from(self.spool_offset).map_err(|_| metadata_limit_error())?;
        let rows_in_runs = self
            .runs
            .iter()
            .try_fold(0_u64, |total, run| total.checked_add(run.count as u64))
            .ok_or_else(spool_corruption_error)?;
        let contiguous_runs = self
            .runs
            .windows(2)
            .all(|pair| pair[0].end == pair[1].start);
        let exact_bounds = self.runs.first().is_some_and(|run| run.start == 0)
            && self.runs.last().is_some_and(|run| run.end == expected_len);
        // The spool is private, unlinked, immutable after mapping, and every
        // record was emitted from a checked row. Its constant-size run table
        // therefore proves the generated layout without faulting every mapped
        // record into RSS before the merge consumes it.
        if mmap.len() != expected_len
            || rows_in_runs != self.total_rows
            || !contiguous_runs
            || !exact_bounds
        {
            return Err(spool_corruption_error());
        }

        let mut runs = self
            .runs
            .into_iter()
            .map(|run| ActiveRun {
                cursor: run.start,
                end: run.end,
                remaining: run.count,
                discarded_to: run.start,
            })
            .collect::<Vec<_>>();
        let mut pending = BinaryHeap::with_capacity(runs.len());
        for (run_index, run) in runs.iter_mut().enumerate() {
            if let Some(entry) = read_pending(&mmap, run, run_index, &self.root) {
                pending.push(entry);
            }
        }
        Ok(CompactEntries {
            root: self.root,
            mmap: Some(mmap),
            runs,
            pending,
            remaining: self.total_rows as usize,
            page_size: page_size(),
        })
    }
}

#[cfg(unix)]
fn read_pending(
    mmap: &[u8],
    run: &mut ActiveRun,
    run_index: usize,
    root: &Path,
) -> Option<PendingEntry> {
    if run.remaining == 0 {
        return None;
    }
    let header_end = run.cursor + RECORD_HEADER_LEN;
    let size = read_u64_le(mmap, run.cursor);
    let path_len_and_binary = read_u32_le(mmap, run.cursor + 8);
    let path_end = header_end + (path_len_and_binary & PATH_LEN_MASK) as usize;
    let relative = Path::new(OsStr::from_bytes(&mmap[header_end..path_end]));
    let path = if relative.as_os_str().is_empty() {
        root.to_path_buf()
    } else {
        root.join(relative)
    };
    run.cursor = path_end;
    run.remaining -= 1;
    debug_assert!(run.cursor <= run.end);
    Some(PendingEntry {
        path,
        size,
        is_binary: path_len_and_binary & BINARY_PATH_LEN_BIT != 0,
        run_index,
    })
}

#[cfg(unix)]
fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(unix)]
fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(unix)]
fn row_path(paths: &[u8], row: EntryRow) -> &[u8] {
    let start = row.path_start as usize;
    let len = (row.path_len_and_binary & PATH_LEN_MASK) as usize;
    &paths[start..start + len]
}

#[cfg(unix)]
fn align_up(value: usize, alignment: usize) -> usize {
    value.saturating_add(alignment - 1) / alignment * alignment
}

#[cfg(unix)]
fn align_down(value: usize, alignment: usize) -> usize {
    value / alignment * alignment
}

#[cfg(unix)]
fn page_size() -> usize {
    // SAFETY: `sysconf` has no pointer arguments or side effects.
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(value)
        .ok()
        .filter(|size| *size > 0)
        .unwrap_or(4096)
}

#[cfg(unix)]
fn spool_corruption_error() -> SourceError {
    SourceError::Other(
        "filesystem discovery spool was internally inconsistent; files were not scanned".to_owned(),
    )
}

#[cfg(unix)]
fn metadata_limit_error() -> SourceError {
    tracing::warn!("filesystem discovery metadata exceeded compact path limits");
    SourceError::Other(
        "filesystem discovery metadata exceeded the supported 4 GiB path table; remaining files were not scanned"
            .to_owned(),
    )
}
