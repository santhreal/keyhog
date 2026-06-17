//! Curated public re-export surface for `keyhog-core`.
//!
//! `lib.rs` owns the module map; this file owns the compatibility surface so
//! root exports do not sprawl across the module declarations.

pub use crate::allowlist::*;
pub use crate::config::*;
pub use crate::credential::{Credential, SensitiveString};
pub use crate::dedup::*;
pub use crate::display::strip_windows_verbatim_prefix;
pub use crate::finding::*;
pub use crate::merkle_spec_hash::compute_spec_hash;
pub use crate::report::*;
pub use crate::rule_filter::{RuleSuppressor, RuleSuppressorError};
pub use crate::source::*;
pub use crate::spec::*;
