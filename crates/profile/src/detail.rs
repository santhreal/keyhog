//! The one switch that decides whether performance measurement runs.
//!
//! Every crate in the workspace asks this module, and only this module, whether
//! to measure. Before this existed the scanner kept two private process-wide
//! atomics (`DETAILED_ENABLED` and `PERF_TRACE_ENABLED`), the CLI kept two
//! config booleans (`scanner.profile` and `scanner.perf_trace`), and each
//! subsystem decided for itself which one to read. They were always written
//! from the same source, so they were one decision wearing four hats.
//!
//! ```
//! use keyhog_profile::{detail, set_detail, Detail};
//!
//! set_detail(Detail::Diagnostic);
//! assert!(detail().is_diagnostic());
//! assert!(detail().records_stages());
//!
//! set_detail(Detail::Off);
//! assert!(!detail().records_stages());
//! ```
//!
//! # Levels are ordered
//!
//! `Off < Stages < Diagnostic`. A caller that wants stage timing asks
//! [`Detail::records_stages`]. A caller that wants the expensive per-pattern and
//! per-backend decomposition asks [`Detail::is_diagnostic`]. Nothing else is a
//! valid question, because nothing else is a level.
//!
//! # Cost when off
//!
//! [`detail`] is one relaxed load of a `u8` and no clock read. The hot-path
//! pattern is `if detail().is_diagnostic()` guarding the timed region, so a
//! disabled build takes a predictable never-taken branch and never constructs an
//! `Instant`.
//!
//! # Relationship to the runtime switch
//!
//! [`set_detail`] also drives [`crate::set_enabled`], so turning measurement on
//! is a single call. [`crate::enabled`] stays the per-thread question ("is a
//! profile runtime current here"), which is what a span guard needs.
//! [`detail`] is the process-wide question ("was measurement requested at all"),
//! which is what a caller needs before paying to construct a measurement.
//! A [`crate::Session`] raises [`crate::enabled`] without raising [`detail`], so
//! an operator `--profile` run records stages without paying diagnostic cost.

use std::sync::atomic::{AtomicU8, Ordering::Relaxed};

use serde::{Deserialize, Serialize};

/// How much performance measurement this process performs.
#[derive(
    Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize, Deserialize,
)]
#[repr(u8)]
#[serde(rename_all = "lowercase")]
pub enum Detail {
    /// Measure nothing. No clock is read on any hot path.
    #[default]
    Off = 0,
    /// Record fixed stage spans, typed counters, and the causal record.
    Stages = 1,
    /// Everything in [`Detail::Stages`], plus the per-pattern, per-decoder and
    /// per-backend decomposition that costs measurable hot-path time.
    Diagnostic = 2,
}

impl Detail {
    /// Stable text label used by human reports and config echoes.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Stages => "stages",
            Self::Diagnostic => "diagnostic",
        }
    }

    /// True when stage spans and typed counters should be recorded.
    #[inline]
    pub const fn records_stages(self) -> bool {
        (self as u8) >= (Self::Stages as u8)
    }

    /// True when the expensive per-pattern and per-backend decomposition
    /// should be recorded.
    #[inline]
    pub const fn is_diagnostic(self) -> bool {
        (self as u8) >= (Self::Diagnostic as u8)
    }
}

static DETAIL: AtomicU8 = AtomicU8::new(Detail::Off as u8);

/// Return the measurement level requested for this process.
///
/// One relaxed atomic load. Safe to call on any hot path.
#[inline]
pub fn detail() -> Detail {
    match DETAIL.load(Relaxed) {
        1 => Detail::Stages,
        2 => Detail::Diagnostic,
        _ => Detail::Off,
    }
}

/// Set the measurement level for this process and enable or disable the
/// calling thread's standalone profiling runtime to match.
///
/// This is the only supported way for a caller outside this crate to turn
/// measurement on.
pub fn set_detail(detail: Detail) {
    DETAIL.store(detail as u8, Relaxed);
    crate::runtime::set_enabled(detail.records_stages());
}

#[cfg(test)]
mod tests {
    use super::{detail, set_detail, Detail};

    /// The levels answer their two questions consistently, so a caller never
    /// has to compare discriminants by hand.
    #[test]
    fn level_predicates_are_ordered() {
        assert!(!Detail::Off.records_stages());
        assert!(!Detail::Off.is_diagnostic());
        assert!(Detail::Stages.records_stages());
        assert!(!Detail::Stages.is_diagnostic());
        assert!(Detail::Diagnostic.records_stages());
        assert!(Detail::Diagnostic.is_diagnostic());
        assert!(Detail::Off < Detail::Stages);
        assert!(Detail::Stages < Detail::Diagnostic);
    }

    /// Setting the level also arms the runtime, so one call turns measurement
    /// on. This is the property that lets every other crate delete its private
    /// enable flag.
    #[test]
    fn setting_detail_arms_the_runtime() {
        set_detail(Detail::Diagnostic);
        assert_eq!(detail(), Detail::Diagnostic);
        assert!(crate::enabled());

        set_detail(Detail::Stages);
        assert_eq!(detail(), Detail::Stages);
        assert!(crate::enabled());

        set_detail(Detail::Off);
        assert_eq!(detail(), Detail::Off);
        assert!(!crate::enabled());
    }
}
