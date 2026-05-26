//! Scan pipeline: context windows, scan-loop helpers, and post-match processing.

mod context_window;
mod postprocess;
mod scan_loop;

pub use context_window::{
    compute_line_offsets, find_companion, line_window_offsets, local_context_window,
    match_line_number, normalize_scannable_chunk,
};
pub use postprocess::{
    build_raw_match, should_suppress_known_example_credential,
    should_suppress_known_example_credential_with_source, should_suppress_named_detector_finding,
};
pub(crate) use postprocess::{
    is_uuid_v4_shape, looks_like_dashed_serial_key, looks_like_hash_digest,
    looks_like_pure_hash_digest_or_uuid,
};
pub use scan_loop::{is_within_hex_context, match_entropy};
