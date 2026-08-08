//! Uniform profiler instrumentation for source adapters.
//!
//! Every helper forwards to `keyhog_profile`. When no profiling runtime is
//! entered on the calling thread, `span` is a single relaxed atomic load and
//! the counter helpers are a relaxed load plus an early return, so hot paths
//! stay allocation-free and record nothing. Adapters call these helpers at
//! their acquisition, enumeration, and read boundaries instead of scattering
//! ad-hoc timers.

use keyhog_profile::{AnnotationId, Runtime, Span, Stage};

/// Top-level acquisition of one source (open repo, list bucket, fetch page,
/// export image). Wrap each adapter's entry acquisition in this span.
#[inline]
pub(crate) fn acquire_span() -> Span {
    keyhog_profile::span(Stage::SourceAcquire)
}

/// Enumeration and filtering work (directory walk, bucket listing, layer or
/// blob traversal, archive member enumeration).
#[inline]
pub(crate) fn walk_span() -> Span {
    keyhog_profile::span(Stage::SourceWalk)
}

/// Opening and reading one input unit (file, blob, object, response body).
#[inline]
pub(crate) fn read_span() -> Span {
    keyhog_profile::span(Stage::SourceRead)
}

/// Blocking handoff into a bounded queue (stdin chunk channel, reader pool
/// backpressure).
#[inline]
pub(crate) fn queue_wait_span() -> Span {
    keyhog_profile::span(Stage::SourceQueueWait)
}

/// Extraction or decompression that derives new scannable content (archive
/// members, documents, structured files, binary sections).
#[inline]
pub(crate) fn decode_span() -> Span {
    keyhog_profile::span(Stage::Decode)
}

/// Record real input bytes at the adapter acquisition boundary.
#[inline]
pub(crate) fn add_input_bytes(bytes: u64) {
    keyhog_profile::add_input_bytes(bytes);
}

/// Record real input units (files, objects, blobs, responses, chunks) at the
/// adapter acquisition boundary.
#[inline]
pub(crate) fn add_input_units(units: u64) {
    keyhog_profile::add_input_units(units);
}

/// Record bytes produced by accepted extraction or decompression work.
#[inline]
pub(crate) fn add_derived_bytes(bytes: u64) {
    keyhog_profile::add_derived_decoder_bytes(bytes);
}

/// Record one retry attempt. No dedicated retry `EventId` exists yet, so the
/// typed `RetryAttempt` annotation carries the 1-based attempt number.
// Only the github-gated adapters (org listing, collaboration API) retry today.
#[cfg_attr(not(feature = "github"), allow(dead_code))]
#[inline]
pub(crate) fn record_retry(attempt: u64) {
    keyhog_profile::record_annotation(AnnotationId::RetryAttempt, attempt);
}

/// Clone the runtime current on this thread so a source that fans work out
/// to its own worker threads can keep recording there.
#[inline]
pub(crate) fn current_runtime() -> Option<Runtime> {
    keyhog_profile::current_runtime()
}

/// Record one chunk emitted by an adapter as one input unit plus its byte
/// length. Used by streaming adapters (git, web, slack, binary,
/// collaboration) whose real acquired counts are only known as chunks are
/// produced. Cloud object storage records the same counters in its ordered
/// streaming fetch coordinator.
// Only feature-gated streaming adapters emit through this helper.
#[cfg_attr(
    not(any(
        feature = "git",
        feature = "web",
        feature = "slack",
        feature = "binary",
        feature = "github"
    )),
    allow(dead_code)
)]
#[inline]
pub(crate) fn record_emitted_chunk(row: &Result<keyhog_core::Chunk, keyhog_core::SourceError>) {
    if let Ok(chunk) = row {
        // LAW10: this branch updates success-only profile counters; the caller still propagates every SourceError unchanged.
        add_input_units(1);
        add_input_bytes(chunk.data.len() as u64);
    }
}
