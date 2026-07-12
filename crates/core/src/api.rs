//! Curated public re-export surface for `keyhog-core`.
//!
//! `lib.rs` owns the module map; this file owns the compatibility surface so
//! root exports do not sprawl across the module declarations.

pub use crate::allowlist::*;
pub use crate::ascii_ci::{
    contains_bytes_ignore_ascii_case, contains_ignore_ascii_case, ends_with_ignore_ascii_case,
    starts_with_ignore_ascii_case,
};
pub use crate::aws::{
    finding_metadata, key_id_canary_status, parse_canary_account_ids, set_extra_canary_accounts,
    validate_canary_accounts,
};
pub use crate::calibration::{
    calibration_default_cache_path, BetaCounters, Calibration, CalibrationLoadError,
};
pub use crate::config::*;
pub use crate::credential::{Credential, SensitiveString};
pub use crate::dedup::*;
pub use crate::display::strip_windows_verbatim_prefix;
pub use crate::encoding::decode_standard_base64;
pub use crate::finding::*;
pub use crate::hardening::{
    apply_protections, apply_protections_with_persistence_paths, HardeningReport,
};
pub use crate::hyperscan_cache::{
    hyperscan_cache_filename, hyperscan_cache_header_is_valid, write_hyperscan_cache_header,
    HYPERSCAN_CACHE_FILE_BYTES, HYPERSCAN_CACHE_HEADER_LEN, HYPERSCAN_CACHE_MAGIC,
    HYPERSCAN_CACHE_VERSION,
};
pub use crate::merkle_index::{
    merkle_default_cache_path, MerkleIndex, MerkleLoadReport, MerkleLoadStatus,
};
pub use crate::merkle_spec_hash::compute_spec_hash;
pub use crate::report::*;
pub use crate::rule_filter::{RuleSuppressor, RuleSuppressorError};
pub use crate::safe_bin::{resolve_safe_bin, set_extra_trusted_dirs};
pub use crate::source::*;
pub use crate::spec::*;
