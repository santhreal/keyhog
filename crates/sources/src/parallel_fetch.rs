//! Shared concurrency limits for remote source fetch fanout.

use keyhog_core::{Chunk, SourceError};

pub(crate) struct RemoteChunkStream {
    receiver: Option<std::sync::mpsc::Receiver<Result<Chunk, SourceError>>>,
    worker: Option<std::thread::JoinHandle<()>>,
    label: &'static str,
}

impl RemoteChunkStream {
    pub(crate) fn spawn(
        thread_name: &'static str,
        label: &'static str,
        lease: crate::skip::ScanReadLease,
        work: impl FnOnce(
                std::sync::mpsc::SyncSender<Result<Chunk, SourceError>>,
                crate::skip::ScanReadLease,
            ) + Send
            + 'static,
    ) -> Result<Self, SourceError> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name(thread_name.to_string())
            .spawn(move || work(sender, lease))
            .map_err(|error| {
                SourceError::Other(format!("{label}: failed to spawn stream worker: {error}"))
            })?;
        Ok(Self {
            receiver: Some(receiver),
            worker: Some(worker),
            label,
        })
    }
}

impl Iterator for RemoteChunkStream {
    type Item = Result<Chunk, SourceError>;

    fn next(&mut self) -> Option<Self::Item> {
        let received = self.receiver.as_ref()?.recv();
        match received {
            Ok(row) => Some(row),
            Err(_) => {
                self.receiver.take();
                let worker = self.worker.take()?;
                match worker.join() {
                    Ok(()) => None,
                    Err(_) => Some(Err(SourceError::Other(format!(
                        "{} stream worker panicked",
                        self.label
                    )))),
                }
            }
        }
    }
}

impl Drop for RemoteChunkStream {
    fn drop(&mut self) {
        self.receiver.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(any(feature = "azure", feature = "s3", feature = "gcs", feature = "slack"))]
pub(crate) fn stream_ordered_fetch<T, R>(
    items: &[T],
    worker_limit: usize,
    scan_lease: &crate::skip::ScanReadLease,
    fetch: impl Fn(&T) -> R + Sync,
    mut emit: impl FnMut(R) -> bool,
) -> bool
where
    T: Sync,
    R: Send,
{
    let worker_count = worker_limit.min(items.len());
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    let profile_runtime = crate::profile::current_runtime();
    let (jobs, pending_jobs) = crossbeam_channel::unbounded();
    let (release_slot, available_slots) = crossbeam_channel::bounded::<()>(worker_count.max(1));
    for _ in 0..worker_count {
        let _ = release_slot.send(());
    }
    let mut receivers = Vec::with_capacity(items.len());
    for item in items {
        let (output, receiver) = std::sync::mpsc::sync_channel(1);
        let _ = jobs.send((item, output));
        receivers.push(receiver);
    }
    drop(jobs);

    std::thread::scope(|scope| {
        for _ in 0..worker_count {
            let pending_jobs = pending_jobs.clone();
            let worker_lease = (*scan_lease).clone();
            let profile_runtime = profile_runtime.clone();
            let cancelled = &cancelled;
            let fetch = &fetch;
            let available_slots = available_slots.clone();
            scope.spawn(move || {
                let _attributed = worker_lease.enter();
                let _profile_guard = profile_runtime.as_ref().map(|runtime| runtime.enter());
                while !cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                    if available_slots.recv().is_err() {
                        break;
                    }
                    if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    let Ok((item, output)) = pending_jobs.recv() else {
                        break;
                    };
                    if output.send(fetch(item)).is_err() {
                        break;
                    }
                }
            });
        }
        drop(pending_jobs);

        let mut accepting = true;
        for receiver in receivers {
            let Ok(result) = receiver.recv() else {
                continue;
            };
            if !emit(result) {
                accepting = false;
                cancelled.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            let _ = release_slot.send(());
            if !accepting {
                break;
            }
        }
        drop(release_slot);
        accepting
    })
}

#[cfg(all(
    test,
    any(feature = "azure", feature = "s3", feature = "gcs", feature = "slack")
))]
mod ordered_fetch_tests {
    #[test]
    fn slow_first_item_bounds_completed_results_to_worker_limit() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let items = (0usize..32).collect::<Vec<_>>();
        let started = AtomicUsize::new(0);
        let mut emitted = Vec::new();
        let scan_lease = crate::acquire_scan_read_lease();
        let accepted = super::stream_ordered_fetch(
            &items,
            4,
            &scan_lease,
            |item| {
                started.fetch_add(1, Ordering::Relaxed);
                if *item == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                *item
            },
            |item| {
                if emitted.is_empty() {
                    assert!(
                        started.load(Ordering::Relaxed) <= 4,
                        "workers fetched beyond the bounded result window before item 0 retired"
                    );
                }
                emitted.push(item);
                true
            },
        );

        assert!(accepted);
        assert_eq!(emitted, items);
    }

    #[test]
    fn cancellation_stops_without_draining_unstarted_items() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let items = (0usize..32).collect::<Vec<_>>();
        let started = AtomicUsize::new(0);
        let scan_lease = crate::acquire_scan_read_lease();
        let accepted = super::stream_ordered_fetch(
            &items,
            4,
            &scan_lease,
            |item| {
                started.fetch_add(1, Ordering::Relaxed);
                *item
            },
            |_item| false,
        );

        assert!(!accepted);
        assert!(
            started.load(Ordering::Relaxed) <= 4,
            "cancellation fetched beyond the bounded result window"
        );
    }
}

#[cfg(any(feature = "azure", feature = "s3", feature = "gcs"))]
pub(crate) const CLOUD_OBJECT_FETCH_THREADS: usize = 16;

#[cfg(any(
    feature = "slack",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket"
))]
pub(crate) const REMOTE_API_FETCH_THREADS: usize = 8;
