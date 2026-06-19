//! Curated public re-export surface for `keyhog-scanner`.
//!
//! `lib.rs` declares the scanner subsystems; this module keeps the root
//! compatibility exports in one place.

pub use crate::engine::{
    megascan_input_len, profile_dump, profile_reset, scan_inner_profile_dump,
    set_perf_trace_enabled, set_profile_enabled, CompiledScanner, CompiledScannerRuntime,
    GpuInitPolicy,
};
pub use crate::error::{Result, ScanError};
pub use crate::hw_probe::{probe_hardware, select_backend, HardwareCaps, ScanBackend};
pub use crate::types::{set_regex_dfa_limit, ScannerConfig, ScannerTuningConfig};
