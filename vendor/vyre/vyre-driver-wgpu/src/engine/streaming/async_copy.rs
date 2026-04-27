//! Host-side async copy stream scheduling.
//!
//! wgpu command submission already lets copies and compute live in one GPU
//! queue. This module models the higher-level stream contract exposed by
//! `Node::AsyncLoad { tag }` and `Node::AsyncWait { tag }`: copy staging work
//! is started on a separate host worker and joined only when the matching wait
//! is reached, so CPU memcpy/staging can overlap compute preparation.
//!
//! Backing thread policy: uses `std::thread::spawn` when no tokio runtime is
//! detected; uses `tokio::task::spawn_blocking` when one is. The tokio path
//! is important at internet scale — `std::thread::spawn` per AsyncLoad tag
//! is an OS-thread-per-copy pattern that thrashes the scheduler under heavy
//! streaming workloads (thousands of concurrent tags). `spawn_blocking`
//! amortizes across tokio's bounded blocking-thread pool (default 512
//! threads; configurable) so N copies in flight cost at most N × task-switch,
//! not N × thread-creation.
//!
//! A third option — a pre-built `rayon::ThreadPool` bounded at CPU-parallelism
//! — was considered and rejected because most vyre callers already run under
//! tokio and pulling rayon in for this one concern adds a second global pool.

use std::collections::HashMap;

use vyre_driver::BackendError;

/// Handle to the work backing an in-flight tag. Stored in the scheduler
/// until the matching `async_wait` call. Allows the scheduler to sit on
/// top of either `std::thread` (when tokio is absent) or
/// `tokio::task::spawn_blocking` (when a runtime is active) without
/// forcing every caller into async code.
enum InFlight {
    Thread(std::thread::JoinHandle<Result<(), BackendError>>),
    TokioBlocking(tokio::task::JoinHandle<Result<(), BackendError>>),
}

/// Async copy scheduler keyed by IR stream tags.
#[derive(Default)]
pub struct AsyncCopyStreams {
    in_flight: HashMap<String, InFlight>,
}

impl AsyncCopyStreams {
    /// Create an empty stream scheduler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Start copy work associated with `tag`.
    ///
    /// If a tokio runtime handle is available on the current thread the
    /// closure is dispatched to `tokio::task::spawn_blocking` so the
    /// runtime's blocking-thread pool amortizes scheduling cost. Otherwise
    /// a fresh OS thread is spawned — the behavior before 0.6, preserved
    /// for non-tokio callers and for unit tests.
    ///
    /// # Errors
    ///
    /// Returns a backend error if the tag is already in flight.
    pub fn async_load<F>(&mut self, tag: impl Into<String>, copy: F) -> Result<(), BackendError>
    where
        F: FnOnce() -> Result<(), BackendError> + Send + 'static,
    {
        let tag = tag.into();
        if self.in_flight.contains_key(&tag) {
            return Err(BackendError::new(format!(
                "async copy tag `{tag}` is already in flight. Fix: wait before reusing a stream tag."
            )));
        }
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(rt) => InFlight::TokioBlocking(rt.spawn_blocking(copy)),
            Err(_) => InFlight::Thread(std::thread::spawn(copy)),
        };
        self.in_flight.insert(tag, handle);
        Ok(())
    }

    /// Wait for a copy previously started by [`Self::async_load`].
    ///
    /// # Errors
    ///
    /// Returns a backend error if the tag is unknown, the worker panicked, or
    /// the copy closure returned an error.
    pub fn async_wait(&mut self, tag: &str) -> Result<(), BackendError> {
        let handle = self.in_flight.remove(tag).ok_or_else(|| {
            BackendError::new(format!(
                "async copy tag `{tag}` has no matching AsyncLoad. Fix: emit AsyncLoad before AsyncWait."
            ))
        })?;
        match handle {
            InFlight::Thread(join) => join.join().map_err(|_| {
                BackendError::new(format!(
                    "async copy worker for `{tag}` panicked. Fix: inspect staging buffer ownership and copy closure invariants."
                ))
            })?,
            InFlight::TokioBlocking(join) => {
                let result = if let Ok(rt) = tokio::runtime::Handle::try_current() {
                    // Safe blocking join from inside an async context: use
                    // `block_in_place` so we do not starve the runtime.
                    tokio::task::block_in_place(|| rt.block_on(join))
                } else {
                    // Spin up a single-threaded runtime just long enough to
                    // join. Rare path (the task was spawned while a runtime
                    // was present and we lost it since); documented so the
                    // fallback is explicit rather than silently returning
                    // an error.
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| {
                            BackendError::new(format!(
                                "failed to build fallback tokio runtime for async-copy join: {e}. Fix: keep a tokio runtime alive while AsyncWait is pending."
                            ))
                        })?;
                    rt.block_on(join)
                };
                result.map_err(|e| {
                    BackendError::new(format!(
                        "async copy worker for `{tag}` failed: {e}. Fix: inspect staging buffer ownership and copy closure invariants."
                    ))
                })?
            }
        }
    }

    /// Start copy work, run compute work, then wait for the copy tag.
    ///
    /// # Errors
    ///
    /// Propagates copy or compute failures with their original context.
    pub fn overlap_copy_compute<C, G>(
        &mut self,
        tag: impl Into<String>,
        copy: C,
        compute: G,
    ) -> Result<(), BackendError>
    where
        C: FnOnce() -> Result<(), BackendError> + Send + 'static,
        G: FnOnce() -> Result<(), BackendError>,
    {
        let tag = tag.into();
        self.async_load(tag.clone(), copy)?;
        compute()?;
        self.async_wait(&tag)
    }
}

impl Drop for AsyncCopyStreams {
    fn drop(&mut self) {
        for (_, handle) in self.in_flight.drain() {
            match handle {
                InFlight::Thread(join) => {
                    if let Err(payload) = join.join() {
                        tracing::error!(
                            panic = %panic_payload(&payload),
                            "async copy worker panicked while AsyncCopyStreams was being dropped"
                        );
                    }
                }
                InFlight::TokioBlocking(join) => {
                    // tokio::task::JoinHandle drops clean when the task has
                    // already finished; aborting guarantees outstanding
                    // tasks do not keep holding staging buffers after the
                    // scheduler itself is gone.
                    join.abort();
                }
            }
        }
    }
}

fn panic_payload<'a>(payload: &'a (dyn std::any::Any + Send + 'static)) -> &'a str {
    payload
        .downcast_ref::<&'static str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("<non-string panic payload>")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn async_copy_overlaps_compute() {
        let copy_time = Duration::from_millis(70);
        let compute_time = Duration::from_millis(70);

        let sequential_start = Instant::now();
        std::thread::sleep(copy_time);
        std::thread::sleep(compute_time);
        let sequential = sequential_start.elapsed();

        let mut streams = AsyncCopyStreams::new();
        let overlap_start = Instant::now();
        streams
            .overlap_copy_compute(
                "stage-0",
                move || {
                    std::thread::sleep(copy_time);
                    Ok(())
                },
                move || {
                    std::thread::sleep(compute_time);
                    Ok(())
                },
            )
            .expect("Fix: async copy and compute should complete");
        let overlapped = overlap_start.elapsed();

        assert!(
            overlapped + Duration::from_millis(25) < sequential,
            "copy and compute did not overlap enough: sequential={sequential:?}, overlapped={overlapped:?}"
        );
    }
}
