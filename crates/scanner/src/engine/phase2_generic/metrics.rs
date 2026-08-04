//! Generic assignment bridge profile counters.
//!
//! The keyhog-profile runtime owns every figure: the counts are typed counters
//! and the prefilter/extract wall times are typed nanosecond sums (they nest
//! inside the `GenericDetection` stage span, so spans would double-count the
//! stage total). Recording is a no-op when no profile runtime is active; the
//! `Instant` gates at the call sites key off `keyhog_profile::enabled()`. The
//! unified profiler drains the batch once per dump and renders the line via
//! [`format_generic_profile`].

use std::time::Instant;

/// All six generic-bridge figures drained from one typed-metric batch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct GenericProfile {
    pub prefilter_ns: u64,
    pub extract_ns: u64,
    pub prefilter_calls: u64,
    pub keyword_lines: u64,
    pub regex_captures: u64,
    pub emits: u64,
}

impl GenericProfile {
    /// True when nothing was recorded; the caller stays silent then, matching
    /// the old dump's early-return.
    pub(crate) fn any_recorded(&self) -> bool {
        *self != Self::default()
    }
}

/// Render the generic-bridge profile line the unified profiler prints. Pure
/// (no I/O) so the formatting is unit-testable.
pub(crate) fn format_generic_profile(p: &GenericProfile) -> String {
    let prefilter_ms = p.prefilter_ns as f64 / 1e6;
    let extract_ms = p.extract_ns as f64 / 1e6;
    format!(
        "=== GENERIC bridge profile === prefilter={prefilter_ms:.1}ms extract={extract_ms:.1}ms \
         calls={} keyword_lines={} regex_captures={} emits={}",
        p.prefilter_calls, p.keyword_lines, p.regex_captures, p.emits
    )
}

/// Build the generic-bridge figures from one drained typed-metric batch
/// (`keyhog_profile::take_typed_metrics`). Missing counters read as zero.
pub(crate) fn generic_profile_from_typed(
    metrics: &[keyhog_profile::TypedMetricRecordV2],
) -> GenericProfile {
    let value = |counter: keyhog_profile::CounterId| {
        metrics
            .iter()
            .find(|record| record.metric_id == counter.metric_id())
            .map_or(0, |record| record.value)
    };
    use keyhog_profile::CounterId;
    GenericProfile {
        prefilter_ns: value(CounterId::GenericPrefilterNs),
        extract_ns: value(CounterId::GenericExtractNs),
        prefilter_calls: value(CounterId::GenericPrefilterCalls),
        keyword_lines: value(CounterId::GenericKeywordLines),
        regex_captures: value(CounterId::GenericRegexCaptures),
        emits: value(CounterId::GenericEmits),
    }
}

pub(super) fn record_prefilter_ns(start: Option<Instant>) {
    record_elapsed(keyhog_profile::CounterId::GenericPrefilterNs, start);
}

pub(super) fn record_extract_ns(start: Option<Instant>) {
    record_elapsed(keyhog_profile::CounterId::GenericExtractNs, start);
}

pub(super) fn record_prefilter_call(keyword_lines: usize) {
    keyhog_profile::add_counter(keyhog_profile::CounterId::GenericPrefilterCalls, 1);
    keyhog_profile::add_counter(
        keyhog_profile::CounterId::GenericKeywordLines,
        keyword_lines as u64,
    );
}

pub(super) fn record_regex_capture() {
    keyhog_profile::add_counter(keyhog_profile::CounterId::GenericRegexCaptures, 1);
}

pub(super) fn record_emit() {
    keyhog_profile::add_counter(keyhog_profile::CounterId::GenericEmits, 1);
}

#[inline]
fn record_elapsed(counter: keyhog_profile::CounterId, start: Option<Instant>) {
    if let Some(start) = start {
        keyhog_profile::add_counter(counter, start.elapsed().as_nanos() as u64);
    }
}
