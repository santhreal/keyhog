//! Per-callsite WARN rate limiting with an end-of-run summary.
//!
//! A pathological input class can make one warning fire thousands of times in
//! a single scan (the canonical case: 5,227 identical "Jupyter notebook JSON
//! parse failed" WARNs on a corpus of non-JSON `.ipynb` snippets). Flooding
//! stderr buries real findings and other diagnostics. This layer shows the
//! first [`WARN_REPEATS_SHOWN`] occurrences of each WARN *callsite* and
//! suppresses the rest — but NEVER silently (Law 10): every suppressed repeat
//! is counted, and [`WarnDedupSummaryGuard`] prints a per-callsite
//! "repeated N more times" summary to stderr when the run ends, so the
//! operator sees the true magnitude, just not 5,000 copies of it.
//!
//! Scope is WARN exactly: ERROR is never suppressed (each one can be a
//! distinct operator-actionable failure), and INFO/DEBUG/TRACE are opt-in
//! verbosity where repetition is expected.

use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::Mutex;
use tracing::callsite::Identifier;
use tracing::{Level, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Filter};

/// How many occurrences of each WARN callsite are printed before suppression.
/// Three is enough to show the pattern (path varies per event) without flood.
const WARN_REPEATS_SHOWN: u64 = 3;

#[derive(Default)]
struct WarnRepeatState {
    /// Per-callsite occurrence counts, keyed by callsite identity (one entry
    /// per `tracing::warn!` source location, not per formatted message).
    counts: HashMap<Identifier, CallsiteCount>,
}

struct CallsiteCount {
    seen: u64,
    /// `file:line` of the warn callsite, for the summary line.
    location: String,
}

static WARN_REPEATS: LazyLock<Mutex<WarnRepeatState>> =
    LazyLock::new(|| Mutex::new(WarnRepeatState::default()));

/// A `tracing_subscriber` per-layer filter that admits the first
/// [`WARN_REPEATS_SHOWN`] events of each WARN callsite and counts the rest.
pub(crate) struct WarnRepeatLimit;

impl<S: Subscriber> Filter<S> for WarnRepeatLimit {
    fn enabled(&self, meta: &Metadata<'_>, _cx: &Context<'_, S>) -> bool {
        if !meta.is_event() || *meta.level() != Level::WARN {
            return true;
        }
        let mut state = WARN_REPEATS.lock().unwrap_or_else(|e| e.into_inner());
        let entry = state
            .counts
            .entry(meta.callsite())
            .or_insert_with(|| CallsiteCount {
                seen: 0,
                location: match (meta.file(), meta.line()) {
                    (Some(file), Some(line)) => format!("{file}:{line}"),
                    _ => meta.target().to_string(),
                },
            });
        entry.seen += 1;
        entry.seen <= WARN_REPEATS_SHOWN
    }
}

/// Drop guard that reports every suppressed WARN callsite once, loudly, at the
/// end of the run — the Law-10 half of the rate limit: the repeats are hidden
/// from the stream, never from the operator.
pub(crate) struct WarnDedupSummaryGuard;

impl Drop for WarnDedupSummaryGuard {
    fn drop(&mut self) {
        let state = WARN_REPEATS.lock().unwrap_or_else(|e| e.into_inner());
        for count in state.counts.values() {
            if count.seen > WARN_REPEATS_SHOWN {
                eprintln!(
                    "keyhog: warning at {} repeated {} more times (first {} shown)",
                    count.location,
                    count.seen - WARN_REPEATS_SHOWN,
                    WARN_REPEATS_SHOWN,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests;
