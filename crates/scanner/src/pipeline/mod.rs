//! Scan pipeline: context windows, scan-loop helpers, and post-match processing.

mod context_window;
mod postprocess;
mod scan_loop;

pub use context_window::{
    compute_line_offsets, find_companion, line_window_offsets, local_context_window,
    match_line_number, normalize_scannable_chunk,
};
pub use postprocess::{
    build_raw_match, is_weakly_anchored_named_detector, should_suppress_known_example_credential,
    should_suppress_known_example_credential_with_source, should_suppress_named_detector_finding,
};
pub(crate) use postprocess::{
    contains_uuid_v4_substring, looks_like_email_address,
    looks_like_punctuation_decorated_identifier, looks_like_pure_identifier,
    looks_like_regex_literal_tail, looks_like_scheme_prefixed_uri,
    looks_like_secret_scanner_source, looks_like_url_or_path_segment,
    looks_like_vendored_minified_path, looks_like_word_separated_identifier,
};
pub use scan_loop::{is_within_hex_context, match_entropy};
