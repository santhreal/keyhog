//! Scan pipeline: context windows, scan-loop helpers, and post-match processing.

mod context_window;
mod postprocess;
mod scan_loop;

pub use context_window::compute_line_offsets;
#[cfg(test)]
pub(crate) use context_window::line_window_offsets;
#[cfg(any(feature = "ml", test))]
pub(crate) use context_window::local_context_window;
#[cfg(test)]
pub(crate) use context_window::normalize_scannable_chunk;
pub(crate) use context_window::{find_companion, match_line_number};
pub(crate) use postprocess::build_raw_match;
#[cfg(test)]
pub(crate) use postprocess::should_suppress_known_example_credential_with_source;
pub(crate) use postprocess::{detector_weak_anchor, should_suppress_named_detector_finding_weak};
#[cfg(test)]
pub(crate) use postprocess::{
    should_suppress_known_example_credential, should_suppress_named_detector_finding,
};
pub(crate) use scan_loop::{is_within_hex_context, match_entropy};
