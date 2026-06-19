//! Curated public re-export surface for `keyhog-core`.
//!
//! `lib.rs` owns the module map; this file owns the compatibility surface so
//! root exports do not sprawl across the module declarations.

pub use crate::allowlist::*;
pub use crate::aws::{
    finding_metadata, key_id_canary_status, parse_canary_account_ids, set_extra_canary_accounts,
    validate_canary_accounts,
};
pub use crate::calibration::{
    default_cache_path as calibration_default_cache_path, BetaCounters, Calibration,
    CalibrationLoadError,
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
pub use crate::merkle_index::MerkleIndex;
pub use crate::merkle_spec_hash::compute_spec_hash;
pub use crate::report::*;
pub use crate::rule_filter::{RuleSuppressor, RuleSuppressorError};
#[allow(deprecated)]
pub use crate::safe_bin::resolve_or_fallback;
pub use crate::safe_bin::{resolve_safe_bin, set_extra_trusted_dirs};
pub use crate::source::*;
pub use crate::spec::*;
