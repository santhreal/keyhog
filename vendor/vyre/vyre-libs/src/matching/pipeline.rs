//! Generic engine plus post-process pipeline.
//!
//! Pairs any [`MatchScan`] engine with the canonical CPU
//! [`post_process::try_post_process_cpu`] output.
//!
//! The pipeline is intentionally `Pipeline<E>` rather than a trait —
//! every consumer wants the *same* post-processing semantics, so
//! parameterising over the engine while pinning the post-processor
//! preserves byte-for-byte cross-consumer equivalence.

use crate::matching::engine::MatchScan;
use crate::matching::post_process::{try_post_process_cpu, PostProcessError, PostProcessedMatch};
use vyre::{BackendError, VyreBackend};
use vyre_foundation::match_result::Match;

/// Function pointer for the post-processing stage. Stored as an `fn`
/// (not `Box<dyn Fn>`) to keep `Pipeline<E>` `Copy + Sync` and avoid
/// indirection in the hot path.
pub type PostProcessFn = fn(&[Match], &[u8]) -> Result<Vec<PostProcessedMatch>, PostProcessError>;

/// Engine plus post-processor pair. Construct via [`Pipeline::new`] for the
/// default CPU reference post-process, or [`Pipeline::with_post_process`] to
/// inject a custom one.
pub struct Pipeline<E> {
    /// Underlying scan engine. Anything that implements `MatchScan`
    /// composes — `GpuLiteralSet`, `RulePipeline`, future custom
    /// scanners.
    pub engine: E,
    /// Post-processing function. Defaults to `try_post_process_cpu`.
    pub post_process: PostProcessFn,
}

impl<E: MatchScan> Pipeline<E> {
    /// Wrap an engine with the default CPU post-processor.
    #[must_use]
    pub const fn new(engine: E) -> Self {
        Self {
            engine,
            post_process: try_post_process_cpu,
        }
    }

    /// Wrap an engine with a caller-supplied post-processor. Use when
    /// downstream consumers need different scoring (e.g. surgec's
    /// taint-flow reduction, or a benchmark harness that wants
    /// passthrough).
    #[must_use]
    pub const fn with_post_process(engine: E, post_process: PostProcessFn) -> Self {
        Self {
            engine,
            post_process,
        }
    }

    /// CPU reference one-shot: scan + post-process.
    #[must_use]
    pub fn scan_cpu_processed(&self, haystack: &[u8]) -> Vec<PostProcessedMatch> {
        let raw = self.engine.scan_cpu(haystack);
        (self.post_process)(&raw, haystack)
            .expect("scan_cpu_processed received corrupt match ranges from the CPU reference")
    }

    /// CPU reference one-shot that surfaces post-processing contract errors.
    ///
    /// # Errors
    ///
    /// Returns a [`PostProcessError`] when a scan engine reports a match range
    /// outside the scanned haystack.
    pub fn try_scan_cpu_processed(
        &self,
        haystack: &[u8],
    ) -> Result<Vec<PostProcessedMatch>, PostProcessError> {
        let raw = self.engine.scan_cpu(haystack);
        (self.post_process)(&raw, haystack)
    }

    /// Full GPU dispatch + post-process. Mirrors `MatchScan::scan` and
    /// then runs the post-processor on the host before returning.
    ///
    /// # Errors
    /// Returns the `MatchScan::scan` error verbatim, or wraps a
    /// post-processing contract violation in [`BackendError`].
    pub fn scan_processed(
        &self,
        backend: &dyn VyreBackend,
        haystack: &[u8],
        max_matches: u32,
    ) -> Result<Vec<PostProcessedMatch>, BackendError> {
        let raw = self.engine.scan(backend, haystack, max_matches)?;
        (self.post_process)(&raw, haystack).map_err(|error| BackendError::new(error.to_string()))
    }
}

impl<E: Clone> Clone for Pipeline<E> {
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
            post_process: self.post_process,
        }
    }
}

impl<E: std::fmt::Debug> std::fmt::Debug for Pipeline<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pipeline")
            .field("engine", &self.engine)
            .field("post_process", &"fn(_, _) -> Vec<_>")
            .finish()
    }
}
