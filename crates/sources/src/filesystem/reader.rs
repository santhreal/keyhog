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
pub(super) const DEFAULT_WINDOW_SIZE: usize = keyhog_core::DEFAULT_WINDOW_SIZE_BYTES;

/// Default overlap between consecutive source windows. 128 KiB matches the
/// scanner's own window overlap and covers PEM-sized and multiline secrets
/// that straddle a source cut.
pub(super) const DEFAULT_WINDOW_OVERLAP: usize = keyhog_core::DEFAULT_WINDOW_OVERLAP_BYTES;

/// Flush threshold, in bytes of chunk text, for one streamed slice of a single
/// walk entry. A large file enters the scanner as hundreds of `window_size`
/// windows; at 1 MiB this makes every full-size window its own part, so a
/// window reaches the scan pool as soon as it is decoded instead of after the
/// whole file has been read. Small files stay a single part (one send per
/// entry, exactly as before) because their total text is far below this.
const READER_PART_FLUSH_BYTES: usize = 1024 * 1024;

/// Flush threshold, in chunk count, for one streamed slice. Sixty-four rows
/// amortize tiny-file handoff without retaining a full scanner batch in every
/// reader; the byte threshold independently limits large/adversarial chunks.
const READER_PART_FLUSH_CHUNKS: usize = 64;
/// Rendezvous boundary between the reader crew and scanner. A blocked sender
/// may overlap one decoded window with the active scan, but no additional
/// 1 MiB window remains queued and resident.
const READER_QUEUE_DEPTH: usize = 0;

/// One ordered slice of a single walk entry's chunks:
/// `(seq, part, is_last, chunks)`.
///
/// `seq` orders entries against each other (the walk order) and `part` orders
/// slices within one entry, so the reorder thread reconstructs exactly the
/// chunk order a single-threaded walk would have produced. `is_last` marks the
/// final part of an entry and is what lets the reorder thread know it may
/// advance to `seq + 1`; it is sent even when the trailing part is empty.
type EntryBatch = (usize, usize, bool, Vec<Result<Chunk, SourceError>>);
type EntryBatchSender = std::sync::mpsc::SyncSender<Vec<EntryBatch>>;

pub(super) struct ChunkReceiver {
    receiver: std::sync::mpsc::Receiver<Vec<Result<Chunk, SourceError>>>,
    pending: std::vec::IntoIter<Result<Chunk, SourceError>>,
}

impl Iterator for ChunkReceiver {
    type Item = Result<Chunk, SourceError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(row) = self.pending.next() {
                return Some(row);
            }
            self.pending = self.receiver.recv().ok()?.into_iter(); // LAW10: channel closure is the iterator EOF after all producer senders are gone; pending rows are drained first.
        }
    }
}

fn send_chunk_batch(
    sender: &std::sync::mpsc::SyncSender<Vec<Result<Chunk, SourceError>>>,
    chunks: &mut Vec<Result<Chunk, SourceError>>,
    bytes: &mut usize,
) -> bool {
    if chunks.is_empty() {
        return true;
    }
    let batch = std::mem::take(chunks);
    *bytes = 0;
    let _queue_wait = crate::profile::queue_wait_span();
    sender.send(batch).is_ok()
}

struct EntryBatchBuffer {
    sender: EntryBatchSender,
    pending: Vec<EntryBatch>,
    chunk_count: usize,
    bytes: usize,
}

impl EntryBatchBuffer {
    fn new(sender: EntryBatchSender) -> Self {
        Self {
            sender,
            pending: Vec::with_capacity(READER_PART_FLUSH_CHUNKS),
            chunk_count: 0,
            bytes: 0,
        }
    }

    fn push(&mut self, batch: EntryBatch) -> bool {
        self.chunk_count = self.chunk_count.saturating_add(batch.3.len());
        self.bytes = self.bytes.saturating_add(
            batch
                .3
                .iter()
                .filter_map(|row| row.as_ref().ok()) // LAW10: errors are excluded only from byte accounting; every original row remains queued in the batch.
                .map(|chunk| chunk.data.len())
                .sum::<usize>(),
        );
        self.pending.push(batch);
        if self.bytes >= READER_PART_FLUSH_BYTES
            || self.chunk_count >= READER_PART_FLUSH_CHUNKS
            || self.pending.len() >= READER_PART_FLUSH_CHUNKS
        {
            return self.flush();
        }
        true
    }

    fn flush(&mut self) -> bool {
        if self.pending.is_empty() {
            return true;
        }
        let batches = std::mem::take(&mut self.pending);
        self.chunk_count = 0;
        self.bytes = 0;
        let _queue_wait = crate::profile::queue_wait_span();
        self.sender.send(batches).is_ok()
    }
}

enum ReaderBatchOutput {
    Ordered(EntryBatchBuffer),
    Direct {
        sender: std::sync::mpsc::SyncSender<Vec<Result<Chunk, SourceError>>>,
        chunks: Vec<Result<Chunk, SourceError>>,
        bytes: usize,
    },
}

impl ReaderBatchOutput {
    fn ordered(sender: EntryBatchSender) -> Self {
        Self::Ordered(EntryBatchBuffer::new(sender))
    }

    fn direct(sender: std::sync::mpsc::SyncSender<Vec<Result<Chunk, SourceError>>>) -> Self {
        Self::Direct {
            sender,
            chunks: Vec::with_capacity(READER_PART_FLUSH_CHUNKS),
            bytes: 0,
        }
    }

    fn push(&mut self, batch: EntryBatch) -> bool {
        match self {
            Self::Ordered(output) => output.push(batch),
            Self::Direct {
                sender,
                chunks,
                bytes,
            } => {
                for chunk in batch.3 {
                    *bytes = bytes.saturating_add(match &chunk {
                        Ok(chunk) => chunk.data.len(),
                        Err(_) => 0,
                    });
                    chunks.push(chunk);
                    if (*bytes >= READER_PART_FLUSH_BYTES
                        || chunks.len() >= READER_PART_FLUSH_CHUNKS)
                        && !send_chunk_batch(sender, chunks, bytes)
                    {
                        return false;
                    }
                }
                true
            }
        }
    }

    fn flush(&mut self) -> bool {
        match self {
            Self::Ordered(output) => output.flush(),
            Self::Direct {
                sender,
                chunks,
                bytes,
            } => send_chunk_batch(sender, chunks, bytes),
        }
    }
}

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

fn reader_thread_default(_scanner_threads: usize) -> usize {
    1
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
    // This scan's counter-isolation lease. Every reader thread holds a clone
    // for its whole lifetime because `process_entry` records skip events from
    // these threads, and the crew outlives the returned `Receiver` whenever a
    // consumer stops early. Without the clone those increments land after the
    // scan is considered finished and pollute the next counter-asserting test
    // (KH-1587). Inert in production, where nothing ever takes the exclusive
    // scope.
    scan_lease: crate::skip::ScanReadLease,
) -> ChunkReceiver {
    let (tx, rx) =
        std::sync::mpsc::sync_channel::<Vec<Result<Chunk, SourceError>>>(READER_QUEUE_DEPTH);
    let (entry_tx, entry_rx) = std::sync::mpsc::sync_channel::<Vec<EntryBatch>>(READER_QUEUE_DEPTH);
    let cursor = Arc::new(Mutex::new(ReaderCursor {
        next_seq: 0,
        entries,
        closed: false,
    }));
    let reader_count = reader_thread_count(rayon::current_num_threads(), reader_threads);
    if reader_count > 1 {
        let profile_runtime = crate::profile::current_runtime();
        let reorder_tx = tx.clone();
        std::thread::spawn(move || {
            let _profile_guard = profile_runtime.as_ref().map(|runtime| runtime.enter());
            let mut next_seq = 0usize;
            let mut next_part = 0usize;
            // Keyed by `(seq, part)` so a large entry can be forwarded slice by
            // slice as its parts arrive, while entries that finished out of order
            // still wait their turn. Holding a whole entry here was what made the
            // reorder buffer grow with the largest file in the walk.
            let mut pending: BTreeMap<(usize, usize), (bool, Vec<Result<Chunk, SourceError>>)> =
                BTreeMap::new();
            let mut outbound_chunks = Vec::with_capacity(READER_PART_FLUSH_CHUNKS);
            let mut outbound_bytes = 0usize;
            for batches in entry_rx {
                for (seq, part, is_last, chunks) in batches {
                    pending.insert((seq, part), (is_last, chunks));
                    while let Some((is_last, chunks)) = pending.remove(&(next_seq, next_part)) {
                        for chunk in chunks {
                            outbound_bytes = outbound_bytes.saturating_add(match &chunk {
                                Ok(chunk) => chunk.data.len(),
                                Err(_) => 0,
                            });
                            outbound_chunks.push(chunk);
                            if (outbound_bytes >= READER_PART_FLUSH_BYTES
                                || outbound_chunks.len() >= READER_PART_FLUSH_CHUNKS)
                                && !send_chunk_batch(
                                    &reorder_tx,
                                    &mut outbound_chunks,
                                    &mut outbound_bytes,
                                )
                            {
                                return;
                            }
                        }
                        if is_last {
                            next_seq += 1;
                            next_part = 0;
                        } else {
                            next_part += 1;
                        }
                    }
                }
            }
            let _ = send_chunk_batch(&reorder_tx, &mut outbound_chunks, &mut outbound_bytes);
        });
    } else {
        drop(entry_rx);
    }

    let profile_runtime = crate::profile::current_runtime();
    let run_reader = move |cursor: Arc<Mutex<ReaderCursor>>,
                           mut tx: ReaderBatchOutput,
                           merkle: Option<Arc<MerkleIndex>>,
                           skipped: Arc<AtomicUsize>,
                           scan_lease: crate::skip::ScanReadLease| {
        // Held for the whole thread body: every `return` below (cursor end,
        // consumer gone, send failure) drops it, and the scan stops counting as
        // in-flight only once the last reader thread has done so.
        let scan_lease = scan_lease;
        // `process_entry` records skip events from THIS thread, so it must be
        // attributed to the scan or the gate would treat it as an unattributed
        // leftover and make it wait out a counter-asserting test.
        let _attributed = scan_lease.enter();
        let _profile_guard = profile_runtime.as_ref().map(|runtime| runtime.enter());
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
                    let _ = tx.push((seq, 0, true, vec![Err(error)])); // LAW10: push failure means the downstream reorder consumer is closed; no recipient remains for this source error.
                    let _ = tx.flush(); // LAW10: flush failure means the downstream reorder consumer is already closed; no recipient remains.
                    return;
                }
                CursorItem::End => {
                    let _ = tx.flush(); // LAW10: end-of-stream flush failure means the downstream reorder consumer is already closed; no recipient remains.
                    return;
                }
            };

            // Stream this entry's chunks to the reorder thread in bounded
            // parts instead of collecting the entire entry first. Collecting
            // meant a 300 MiB file materialised all ~343 of its 1 MiB windows
            // into one `Vec` before a single chunk was sent: peak RSS grew with
            // the file size (a large enough file simply OOMs), and the whole
            // scan pool sat idle through the read because the fused consumer
            // had nothing to take. Parts are keyed `(seq, part)`, so the chunk
            // order the consumer observes is byte-for-byte the old order.
            let mut part = 0usize;
            let mut part_bytes = 0usize;
            let mut chunks: Vec<Result<Chunk, SourceError>> = Vec::new();
            let mut consumer_gone = false;
            let mut emit = |chunk: Result<Chunk, SourceError>| {
                part_bytes = part_bytes.saturating_add(match &chunk {
                    Ok(chunk) => chunk.data.len(),
                    Err(_) => 0, // LAW10: error rows contribute zero payload bytes to batching only; the SourceError remains in chunks.
                });
                chunks.push(chunk);
                if part_bytes < READER_PART_FLUSH_BYTES && chunks.len() < READER_PART_FLUSH_CHUNKS {
                    return true;
                }
                let send_result = tx.push((seq, part, false, std::mem::take(&mut chunks)));
                part += 1;
                part_bytes = 0;
                // Returning false stops `process_entry` mid-file once the
                // consumer is gone. The old always-true closure kept reading
                // and decoding an entire large file into a `Vec` nobody would
                // ever receive.
                if !send_result {
                    consumer_gone = true;
                    return false;
                }
                true
            };
            let entry_path = entry.path.clone();
            if let Err(payload) = catch_unwind(AssertUnwindSafe(|| {
                let _read = crate::profile::read_span();
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
            if consumer_gone {
                return;
            }
            // Always send the closing part, even empty: `is_last` is what
            // releases the reorder thread to move on to `seq + 1`.
            let send_result = tx.push((seq, part, true, chunks));
            if !send_result {
                return;
            }
        }
    };

    let mut spawned = 0usize;
    let mut spawn_failures = 0usize;
    for i in 0..reader_count {
        let cursor = Arc::clone(&cursor);
        let output = if reader_count == 1 {
            ReaderBatchOutput::direct(tx.clone())
        } else {
            ReaderBatchOutput::ordered(entry_tx.clone())
        };
        let merkle = merkle.clone();
        let skipped = skipped.clone();
        let scan_lease = scan_lease.clone();
        let run_reader = run_reader.clone();
        match std::thread::Builder::new()
            .name(format!("keyhog-reader-{i}"))
            .spawn(move || run_reader(cursor, output, merkle, skipped, scan_lease))
        {
            Ok(_) => spawned += 1,
            Err(error) => {
                spawn_failures = spawn_failures.saturating_add(1);
                // KH-1430: tracing::warn alone is silent without RUST_LOG.
                // Surface on stderr so a partial crew is operator-visible.
                eprintln!(
                    "keyhog: WARN failed to spawn file-reader thread {i}/{reader_count} \
                     ({error}); continuing with fewer readers"
                );
                tracing::warn!(
                    %error,
                    reader = i,
                    "failed to spawn file-reader thread; continuing with fewer readers"
                );
            }
        }
    }
    if spawn_failures > 0 && spawned > 0 {
        eprintln!(
            "keyhog: WARN filesystem reader pool degraded: {spawned}/{reader_count} threads \
             spawned ({spawn_failures} spawn failures); scan continues slower (KH-1430)"
        );
    }

    if spawned == 0 {
        let cursor_fb = Arc::clone(&cursor);
        let output_fb = if reader_count == 1 {
            ReaderBatchOutput::direct(tx.clone())
        } else {
            ReaderBatchOutput::ordered(entry_tx.clone())
        };
        let merkle_fb = merkle.clone();
        let skipped_fb = skipped.clone();
        let scan_lease_fb = scan_lease.clone();
        let run_reader_fb = run_reader.clone();
        if std::thread::Builder::new()
            .name("keyhog-reader-fallback".to_string())
            .spawn(move || {
                run_reader_fb(cursor_fb, output_fb, merkle_fb, skipped_fb, scan_lease_fb)
            })
            .is_err()
        {
            eprintln!(
                "keyhog: ERROR failed to spawn any filesystem reader thread; no files were scanned"
            );
            let error = Err(SourceError::Other(
                "failed to spawn any filesystem reader thread; no files were scanned".to_string(),
            ));
            if reader_count == 1 {
                let _send_result = tx.send(vec![error]);
            } else {
                let _send_result = entry_tx.send(vec![(0, 0, true, vec![error])]);
            }
        } else {
            eprintln!(
                "keyhog: WARN filesystem reader pool fell back to a single thread after \
                 all primary spawns failed (KH-1430)"
            );
        }
    }

    drop(entry_tx);
    drop(tx);
    ChunkReceiver {
        receiver: rx,
        pending: Vec::new().into_iter(),
    }
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
