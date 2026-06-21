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
#[cfg(any(feature = "entropy", feature = "simdsieve", test))]
pub(crate) use postprocess::should_suppress_known_example_credential_with_source;
#[cfg(feature = "entropy")]
pub(crate) use postprocess::{contains_uuid_v4_substring, looks_like_email_address};
pub(crate) use postprocess::{detector_weak_anchor, should_suppress_named_detector_finding_weak};
pub(crate) use postprocess::{
    looks_like_punctuation_decorated_identifier, looks_like_pure_identifier,
    looks_like_regex_literal_tail, looks_like_scheme_prefixed_uri,
    looks_like_source_code_expression, looks_like_url_or_path_segment,
    looks_like_vendored_minified_path, looks_like_word_separated_identifier,
};
#[cfg(test)]
pub(crate) use postprocess::{
    should_suppress_known_example_credential, should_suppress_named_detector_finding,
};
// Only the simdsieve hot-pattern fast path imports this through `pipeline::`.
// The suppression path goes direct (`suppression::path_filter::...`), so
// without `simdsieve` the re-export has no consumer and clippy/rustc flag
// it as an unused import. Gate the alias on the same feature.
#[cfg(feature = "simdsieve")]
pub(crate) use postprocess::looks_like_secret_scanner_source;
pub(crate) use scan_loop::{is_within_hex_context, match_entropy};
