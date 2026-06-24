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
    BetaCounters, Calibration, CalibrationLoadError, calibration_default_cache_path,
};
pub use crate::config::*;
pub use crate::credential::{Credential, SensitiveString};
pub use crate::dedup::*;
pub use crate::display::strip_windows_verbatim_prefix;
pub use crate::encoding::decode_standard_base64;
pub use crate::finding::*;
pub use crate::hardening::{
    HardeningReport, apply_protections, apply_protections_with_persistence_paths,
};
pub use crate::merkle_index::{
    MerkleIndex, MerkleLoadReport, MerkleLoadStatus, merkle_default_cache_path,
};
pub use crate::merkle_spec_hash::compute_spec_hash;
pub use crate::report::*;
pub use crate::rule_filter::{RuleSuppressor, RuleSuppressorError};
pub use crate::safe_bin::{resolve_safe_bin, set_extra_trusted_dirs};
pub use crate::source::*;
pub use crate::spec::*;
