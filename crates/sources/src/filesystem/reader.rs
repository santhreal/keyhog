use super::extract::process_entry;
use keyhog_core::merkle_index::MerkleIndex;
use keyhog_core::{Chunk, SourceError};
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

/// Number of dedicated file-reader threads to run alongside a scan pool of
/// `scanner_threads`.
pub(super) fn reader_thread_count(scanner_threads: usize) -> usize {
    if std::env::var_os("KEYHOG_READER_THREADS").is_some() {
        let requested = keyhog_core::env_config::usize_at_least_or_default(
            "KEYHOG_READER_THREADS",
            1,
            reader_thread_default(scanner_threads),
        );
        return requested.min(scanner_threads.max(1));
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
) -> std::sync::mpsc::Receiver<Result<Chunk, SourceError>> {
    let (tx, rx) = std::sync::mpsc::sync_channel::<Result<Chunk, SourceError>>(64);
    let cursor: Arc<Mutex<Box<dyn Iterator<Item = codewalk::FileEntry> + Send>>> =
        Arc::new(Mutex::new(entries));
    let reader_count = reader_thread_count(rayon::current_num_threads());

    let run_reader =
        move |cursor: Arc<Mutex<Box<dyn Iterator<Item = codewalk::FileEntry> + Send>>>,
              tx: std::sync::mpsc::SyncSender<Result<Chunk, SourceError>>,
              merkle: Option<Arc<MerkleIndex>>,
              skipped: Arc<AtomicUsize>| {
            loop {
                let entry = {
                    let mut guard = match cursor.lock() {
                        Ok(g) => g,
                        Err(error) => {
                            tracing::warn!(
                                %error,
                                "filesystem reader cursor poisoned; stopping this reader"
                            );
                            return;
                        }
                    };
                    guard.next()
                };
                let Some(entry) = entry else {
                    return;
                };

                let mut sender_alive = true;
                let mut emit = |chunk: Result<Chunk, SourceError>| {
                    let ok = tx.send(chunk).is_ok();
                    sender_alive = ok;
                    ok
                };
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
                if !sender_alive {
                    return;
                }
            }
        };

    let mut spawned = 0usize;
    for i in 0..reader_count {
        let cursor = Arc::clone(&cursor);
        let tx = tx.clone();
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
        let tx_fb = tx.clone();
        let merkle_fb = merkle.clone();
        let skipped_fb = skipped.clone();
        let run_reader_fb = run_reader.clone();
        if std::thread::Builder::new()
            .name("keyhog-reader-fallback".to_string())
            .spawn(move || run_reader_fb(cursor_fb, tx_fb, merkle_fb, skipped_fb))
            .is_err()
        {
            run_reader(cursor, tx.clone(), merkle.clone(), skipped.clone());
        }
    }

    drop(tx);
    rx
}
