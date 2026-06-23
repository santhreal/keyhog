use super::extract::process_entry;
use keyhog_core::MerkleIndex;
use keyhog_core::{Chunk, SourceError};
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

/// Default source-level window size for the large-file scanning path.
///
/// Keep this aligned with the scanner's 1 MiB max chunk size so a multi-MiB
/// source file enters the scanner as many independent chunks instead of one
/// worker serially re-windowing the entire file. The overlap below preserves
/// boundary-spanning secrets.
pub(super) const DEFAULT_WINDOW_SIZE: usize = 1024 * 1024;

/// Default overlap between consecutive source windows. 128 KiB matches the
/// scanner's own window overlap and covers PEM-sized and multiline secrets
/// that straddle a source cut.
pub(super) const DEFAULT_WINDOW_OVERLAP: usize = 128 * 1024;

/// Hard ceiling on the dedicated file-reader crew. The crew is sized as a
/// small fraction of the host's cores, not as a fraction of the scan pool.
const MAX_READER_THREADS: usize = 4;

type EntryBatch = (usize, Vec<Result<Chunk, SourceError>>);
type EntryBatchSender = std::sync::mpsc::SyncSender<EntryBatch>;

struct ReaderCursor {
    next_seq: usize,
    entries: Box<dyn Iterator<Item = codewalk::FileEntry> + Send>,
    closed: bool,
}

enum CursorItem {
    Entry(usize, codewalk::FileEntry),
    Error(usize, SourceError),
    End,
}

/// Number of dedicated file-reader threads to run alongside a scan pool of
/// `scanner_threads`.
pub(super) fn reader_thread_count(
    scanner_threads: usize,
    configured: Option<NonZeroUsize>,
) -> usize {
    if let Some(configured) = configured {
        return configured.get().min(scanner_threads.max(1));
    }
    reader_thread_default(scanner_threads)
}

fn reader_thread_default(scanner_threads: usize) -> usize {
    let crew = (scanner_threads / 4).clamp(2, MAX_READER_THREADS);
    crew.min(scanner_threads.max(1))
}

pub(super) fn spawn_chunk_producer(
    entries: Box<dyn Iterator<Item = codewalk::FileEntry> + Send>,
    merkle: Option<Arc<MerkleIndex>>,
    skipped: Arc<AtomicUsize>,
    default_exclude_root: std::path::PathBuf,
    max_size: u64,
    window_size: usize,
    window_overlap: usize,
    respect_default_excludes: bool,
    reader_threads: Option<NonZeroUsize>,
) -> std::sync::mpsc::Receiver<Result<Chunk, SourceError>> {
    let (tx, rx) = std::sync::mpsc::sync_channel::<Result<Chunk, SourceError>>(64);
    let (entry_tx, entry_rx) = std::sync::mpsc::sync_channel::<EntryBatch>(64);
    let cursor = Arc::new(Mutex::new(ReaderCursor {
        next_seq: 0,
        entries,
        closed: false,
    }));
    let reader_count = reader_thread_count(rayon::current_num_threads(), reader_threads);

    std::thread::spawn(move || {
        let mut next_seq = 0usize;
        let mut pending: BTreeMap<usize, Vec<Result<Chunk, SourceError>>> = BTreeMap::new();
        for (seq, chunks) in entry_rx {
            pending.insert(seq, chunks);
            while let Some(chunks) = pending.remove(&next_seq) {
                for chunk in chunks {
                    if tx.send(chunk).is_err() {
                        return;
                    }
                }
                next_seq += 1;
            }
        }
    });

    let run_reader = move |cursor: Arc<Mutex<ReaderCursor>>,
                           tx: EntryBatchSender,
                           merkle: Option<Arc<MerkleIndex>>,
                           skipped: Arc<AtomicUsize>| {
        loop {
            let item = {
                let guard = match cursor.lock() {
                    Ok(g) => Ok(g),
                    Err(poisoned) => {
                        tracing::warn!(
                                "filesystem reader cursor mutex was poisoned; surfacing partial scan error"
                            );
                        cursor_poison_item(poisoned.into_inner())
                    }
                };
                match guard {
                    Ok(guard) => next_cursor_item(guard),
                    Err(item) => item,
                }
            };
            let (seq, entry) = match item {
                CursorItem::Entry(seq, entry) => (seq, entry),
                CursorItem::Error(seq, error) => {
                    let _ = tx.send((seq, vec![Err(error)]));
                    return;
                }
                CursorItem::End => return,
            };

            let mut chunks = Vec::new();
            let mut emit = |chunk: Result<Chunk, SourceError>| {
                chunks.push(chunk);
                true
            };
            let entry_path = entry.path.clone();
            if let Err(payload) = catch_unwind(AssertUnwindSafe(|| {
                process_entry(
                    entry,
                    &merkle,
                    &skipped,
                    &default_exclude_root,
                    max_size,
                    window_size,
                    window_overlap,
                    respect_default_excludes,
                    &mut emit,
                );
            })) {
                chunks.push(Err(process_entry_panic_error(seq, &entry_path, payload)));
            }
            if tx.send((seq, chunks)).is_err() {
                return;
            }
        }
    };

    let mut spawned = 0usize;
    for i in 0..reader_count {
        let cursor = Arc::clone(&cursor);
        let tx = entry_tx.clone();
        let merkle = merkle.clone();
        let skipped = skipped.clone();
        let run_reader = run_reader.clone();
        match std::thread::Builder::new()
            .name(format!("keyhog-reader-{i}"))
            .spawn(move || run_reader(cursor, tx, merkle, skipped))
        {
            Ok(_) => spawned += 1,
            Err(error) => {
                tracing::warn!(
                    %error,
                    reader = i,
                    "failed to spawn file-reader thread; continuing with fewer readers"
                );
            }
        }
    }

    if spawned == 0 {
        let cursor_fb = Arc::clone(&cursor);
        let tx_fb = entry_tx.clone();
        let merkle_fb = merkle.clone();
        let skipped_fb = skipped.clone();
        let run_reader_fb = run_reader.clone();
        if std::thread::Builder::new()
            .name("keyhog-reader-fallback".to_string())
            .spawn(move || run_reader_fb(cursor_fb, tx_fb, merkle_fb, skipped_fb))
            .is_err()
        {
            let _ = entry_tx.send((
                0,
                vec![Err(SourceError::Other(
                    "failed to spawn any filesystem reader thread; no files were scanned"
                        .to_string(),
                ))],
            ));
        }
    }

    drop(entry_tx);
    rx
}

fn next_cursor_item(mut cursor: std::sync::MutexGuard<'_, ReaderCursor>) -> CursorItem {
    if cursor.closed {
        return CursorItem::End;
    }
    let seq = cursor.next_seq;
    match catch_unwind(AssertUnwindSafe(|| cursor.entries.next())) {
        Ok(Some(entry)) => {
            cursor.next_seq = cursor.next_seq.saturating_add(1);
            CursorItem::Entry(seq, entry)
        }
        Ok(None) => {
            cursor.closed = true;
            CursorItem::End
        }
        Err(payload) => {
            cursor.closed = true;
            cursor.next_seq = cursor.next_seq.saturating_add(1);
            let message = panic_payload_message(payload);
            CursorItem::Error(
                seq,
                SourceError::Other(format!(
                    "filesystem file-walk iterator panicked before entry {seq}; remaining files were not scanned: {message}"
                )),
            )
        }
    }
}

fn cursor_poison_item(
    mut cursor: std::sync::MutexGuard<'_, ReaderCursor>,
) -> Result<std::sync::MutexGuard<'_, ReaderCursor>, CursorItem> {
    if cursor.closed {
        return Err(CursorItem::End);
    }
    let seq = cursor.next_seq;
    cursor.closed = true;
    cursor.next_seq = cursor.next_seq.saturating_add(1);
    Err(CursorItem::Error(
        seq,
        SourceError::Other(format!(
            "filesystem reader cursor mutex was poisoned before entry {seq}; remaining files were not scanned"
        )),
    ))
}

fn process_entry_panic_error(
    seq: usize,
    path: &std::path::Path,
    payload: Box<dyn std::any::Any + Send>,
) -> SourceError {
    SourceError::Other(format!(
        "filesystem file extraction panicked for entry {seq} at '{}'; remaining content for that entry was not scanned: {}",
        path.display(),
        panic_payload_message(payload)
    ))
}

pub(super) fn process_entry_panic_rows_for_test() -> Vec<Result<Chunk, SourceError>> {
    let payload = match catch_unwind(AssertUnwindSafe(|| panic!("extractor exploded"))) {
        Ok(()) => {
            return vec![Err(SourceError::Other(
                "test panic injector did not panic".to_string(),
            ))];
        }
        Err(payload) => payload,
    };
    vec![Err(process_entry_panic_error(
        7,
        std::path::Path::new("panic.zip"),
        payload,
    ))]
}

fn panic_payload_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic payload".to_string()
    }
}
