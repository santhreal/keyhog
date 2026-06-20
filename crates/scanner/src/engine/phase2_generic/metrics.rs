//! Generic assignment bridge profile counters.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Instant;

static GENERIC_PREFILTER_NS: AtomicU64 = AtomicU64::new(0);
static GENERIC_EXTRACT_NS: AtomicU64 = AtomicU64::new(0);
static GENERIC_PREFILTER_CALLS: AtomicU64 = AtomicU64::new(0);
static GENERIC_KEYWORD_LINES: AtomicU64 = AtomicU64::new(0);
static GENERIC_REGEX_CAPTURES: AtomicU64 = AtomicU64::new(0);
static GENERIC_EMITS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn generic_profile_dump() {
    let prefilter_ns = GENERIC_PREFILTER_NS.swap(0, Relaxed);
    let extract_ns = GENERIC_EXTRACT_NS.swap(0, Relaxed);
    let calls = GENERIC_PREFILTER_CALLS.swap(0, Relaxed);
    let keyword_lines = GENERIC_KEYWORD_LINES.swap(0, Relaxed);
    let captures = GENERIC_REGEX_CAPTURES.swap(0, Relaxed);
    let emits = GENERIC_EMITS.swap(0, Relaxed);
    if prefilter_ns == 0 && extract_ns == 0 && calls == 0 {
        return;
    }
    let prefilter_ms = prefilter_ns as f64 / 1e6;
    let extract_ms = extract_ns as f64 / 1e6;
    eprintln!(
        "=== GENERIC bridge profile === prefilter={prefilter_ms:.1}ms extract={extract_ms:.1}ms \
         calls={calls} keyword_lines={keyword_lines} regex_captures={captures} emits={emits}"
    );
}

pub(crate) fn generic_profile_reset() {
    GENERIC_PREFILTER_NS.store(0, Relaxed);
    GENERIC_EXTRACT_NS.store(0, Relaxed);
    GENERIC_PREFILTER_CALLS.store(0, Relaxed);
    GENERIC_KEYWORD_LINES.store(0, Relaxed);
    GENERIC_REGEX_CAPTURES.store(0, Relaxed);
    GENERIC_EMITS.store(0, Relaxed);
}

pub(super) fn record_prefilter_ns(start: Option<Instant>) {
    record_elapsed(&GENERIC_PREFILTER_NS, start);
}

pub(super) fn record_extract_ns(start: Option<Instant>) {
    record_elapsed(&GENERIC_EXTRACT_NS, start);
}

pub(super) fn record_prefilter_call(keyword_lines: usize) {
    GENERIC_PREFILTER_CALLS.fetch_add(1, Relaxed);
    GENERIC_KEYWORD_LINES.fetch_add(keyword_lines as u64, Relaxed);
}

pub(super) fn record_regex_capture() {
    GENERIC_REGEX_CAPTURES.fetch_add(1, Relaxed);
}

pub(super) fn record_emit() {
    GENERIC_EMITS.fetch_add(1, Relaxed);
}

#[inline]
fn record_elapsed(slot: &AtomicU64, start: Option<Instant>) {
    if let Some(start) = start {
        slot.fetch_add(start.elapsed().as_nanos() as u64, Relaxed);
    }
}
