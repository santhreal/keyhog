//! Curated public re-export surface for `keyhog-scanner`.
//!
//! `lib.rs` declares the scanner subsystems; this module keeps the root
//! compatibility exports in one place.

pub use crate::bigram_bloom::{
    BigramPrefilterCorpusStatus, BigramPrefilterState, BigramPrefilterStatus,
};
pub use crate::compiled_scanner::{
    CompiledDetectorEvidenceRelation, CompiledEvidencePlan, CompiledEvidenceRelation,
    CompiledScannerRuntime, GpuBackendAvailability, GpuBackendCandidateStatus, GpuInitPolicy,
};
pub use crate::engine::{
    BackendRecoveryReceipt, CoalescedScanOutcome, CompiledScanner, Phase1AdmissionPlan,
    Phase1AdmissionSummary, Phase2KeywordTriggerSummary, RecoveredInputRange,
};
pub use crate::error::{Result, ScanError};
pub use crate::gpu_input_budget::{
    gpu_batch_input_limit, gpu_batch_input_limit_bounds, set_gpu_batch_input_limit,
};
pub use crate::gpu_literal_artifacts::{
    compile_gpu_literal_artifacts, compile_gpu_literal_artifacts_default,
    gpu_literal_artifact_cache_dir, gpu_literal_plan_compiler_invocations,
    install_compiled_gpu_literal_invocations, runtime_gpu_literal_compiler_invocations,
    GpuLiteralArtifact, GpuLiteralArtifacts,
};
pub use crate::hw_probe::{probe_hardware, select_backend, HardwareCaps, ScanBackend};
pub use crate::matcher_artifact_cache::{
    compile_shared_with_matcher_artifact_cache, configured_matcher_artifact_cache_dir,
    default_matcher_artifact_cache_dir, default_matcher_artifact_cache_dir_from_base,
    execution_pack_backend_for_scan_backend, load_matcher_artifact, load_matcher_artifact_with_ir,
    matcher_backend_for_gpu_policy, store_matcher_artifact, LoadedMatcherArtifact,
    MatcherArtifactCacheOutcome, MatcherArtifactIdentity, MATCHER_ARTIFACT_FILE_BYTES,
    MATCHER_ARTIFACT_MAGIC, MATCHER_ARTIFACT_SUFFIX, MATCHER_ARTIFACT_VERSION,
};
// The measurement switch is the profiler's, re-exported so a `keyhog-scanner`
// consumer never has to reach past the scanner for it, and never gets a second
// scanner-owned switch that can disagree with it.
pub use crate::scan_profile::{dump as profile_dump, reset as profile_reset};
pub use crate::types::{
    regex_dfa_limit_default, set_regex_dfa_limit, ScanExecutionRoute, ScannerConfig,
    ScannerTuningConfig,
};
pub use crate::util_hash::{FNV_OFFSET_BASIS, FNV_PRIME};
pub use keyhog_profile::{detail as profile_detail, set_detail as set_profile_detail, Detail};
