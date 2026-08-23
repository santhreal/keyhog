//! Scan pipeline: context windows, scan-loop helpers, and post-match processing.

mod context_window;
mod partition;
mod postprocess;
mod scan_loop;

pub use context_window::compute_line_offsets;
pub(crate) use context_window::find_companion;
#[cfg(feature = "multiline")]
pub(crate) use context_window::line_window_offsets;
pub(crate) use context_window::local_context_window;
pub(crate) use context_window::local_context_window_from_offsets;
#[cfg(feature = "multiline")]
pub(crate) use context_window::match_line_number;
pub(crate) use context_window::normalize_scannable_chunk;
pub use partition::{
    deduplicate_partition_matches, partition_chunk, partition_chunk_for_workers,
    scan_chunk_partitioned, DEFAULT_MIN_PARTITION_CHUNK_BYTES, DEFAULT_PARTITION_OVERLAP_BYTES,
};
#[cfg(feature = "ml")]
pub(crate) use postprocess::{build_pending_raw_match, build_pending_synthetic_raw_match};
pub(crate) use postprocess::{build_raw_match, build_synthetic_raw_match};
pub(crate) use scan_loop::{is_within_hex_context, match_entropy};
