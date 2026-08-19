//! Main scan run loop: hardening, sources, baseline, reporting, exit codes.

use super::allowlist::{load_allowlist, load_rule_suppressor};
use super::reporting::{
    dump_dogfood_trace, report_autoroute_cache_summary, report_compiled_cache_summary,
    report_completion_summary, report_scanner_materialization_summary, report_skip_summary,
    TickerGuard,
};
use super::ScanOrchestrator;
use crate::baseline::Baseline;
use crate::exit_codes::{
    EXIT_FINDINGS, EXIT_LIVE_CREDENTIALS, EXIT_REQUIRE_GPU_UNMET, EXIT_SCANNER_PANIC,
    EXIT_SOURCE_FAILED, EXIT_SUCCESS, EXIT_SYSTEM_ERROR,
};
use crate::style;
use anyhow::Result;
use keyhog_core::{VerificationResult, VerifiedFinding};
use sha2::{Digest, Sha256};
use std::io::{IsTerminal, Read};
use std::time::Instant;

#[cfg(feature = "mimalloc")]
pub(super) fn release_current_allocator_arena() {
    extern "C" {
        fn mi_collect(force: bool);
    }

    // Referencing the Rust allocator crate keeps its native link metadata in
    // library-test binaries too; the production binary already references this
    // type through its global allocator declaration.
    let allocator_link = mimalloc::MiMalloc;
    std::hint::black_box(&allocator_link);
    // SAFETY: the mimalloc feature links the process allocator that exports
    // `mi_collect`; the function has no pointer arguments or preconditions.
    unsafe { mi_collect(true) };
}

#[cfg(feature = "mimalloc")]
pub(super) fn release_allocator_arenas_after_construction() {
    // Regex and matcher compilation runs on Rayon workers. Collect each
    // thread-local mimalloc heap, then the caller heap, so compiler pages do
    // not remain resident throughout a tiny scan.
    rayon::broadcast(|_| release_current_allocator_arena());
    release_current_allocator_arena();
}

#[cfg(all(not(feature = "mimalloc"), target_os = "linux", target_env = "gnu"))]
pub(super) fn release_current_allocator_arena() {
    // SAFETY: glibc's process-wide trim takes no pointers and tolerates
    // concurrent allocator users.
    let _ = unsafe { libc::malloc_trim(0) }; // LAW10: allocator trimming is a best-effort memory optimization with no effect on scan findings or error semantics.
}

#[cfg(all(not(feature = "mimalloc"), target_os = "linux", target_env = "gnu"))]
pub(super) fn release_allocator_arenas_after_construction() {
    release_current_allocator_arena();
}

#[cfg(not(any(feature = "mimalloc", all(target_os = "linux", target_env = "gnu"))))]
pub(super) fn release_current_allocator_arena() {}

#[cfg(not(any(feature = "mimalloc", all(target_os = "linux", target_env = "gnu"))))]
pub(super) fn release_allocator_arenas_after_construction() {}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct ScanOutcome {
    pub(super) autoroute_calibration: bool,
    pub(super) scanner_panicked: bool,
    pub(super) has_live_credentials: bool,
    pub(super) has_blocking_findings: bool,
    pub(super) incremental_cache_failed: bool,
    pub(super) source_coverage_incomplete: bool,
    /// A requested source produced ZERO chunks and errored: not a gap in the
    /// coverage of input we read, but input we never read at all. Tracked
    /// separately from `source_coverage_incomplete` so the exit code cannot
    /// depend on whether that total failure also happened to raise a
    /// FAIL-class coverage gap.
    pub(super) total_source_failure: bool,
    /// The autoroute decision cache could not be written. Never discards
    /// findings; it exists so `--autoroute-calibrate` cannot report success
    /// when persisting that decision WAS the requested operation.
    pub(super) autoroute_persist_failed: bool,
}

/// Resolve scan terminal state with reliability failures ahead of findings.
///
/// A panic outranks everything: the run's state is unreliable. Then findings,
/// because the caller has actionable credential evidence to preserve, and that
/// includes a CALIBRATING run. Calibration is a side effect of a scan, not a
/// different operation, so it must not mask the scan's verdict. It used to
/// return success unconditionally, which made
/// `keyhog scan --autoroute-calibrate <tree> && echo clean` print "clean" on a
/// tree with leaks: the report named the credential and the exit code said
/// nothing was wrong. That is the documented first-run command in our own
/// installers, so the one scan most likely to be wired into a gate was the one
/// that could not fail it.
///
/// Below findings, calibration is still allowed to report success on an
/// incomplete sample, because its workload is a deliberately partial
/// measurement rather than a claim about the tree. What it may NOT do is
/// report success when persisting the decision failed, since that was the
/// requested operation.
pub(super) fn resolve_scan_exit(outcome: ScanOutcome) -> u8 {
    if outcome.scanner_panicked {
        EXIT_SCANNER_PANIC
    } else if outcome.has_live_credentials {
        EXIT_LIVE_CREDENTIALS
    } else if outcome.has_blocking_findings {
        EXIT_FINDINGS
    } else if outcome.autoroute_calibration {
        if outcome.autoroute_persist_failed {
            EXIT_SYSTEM_ERROR
        } else {
            EXIT_SUCCESS
        }
    } else if outcome.incremental_cache_failed || outcome.autoroute_persist_failed {
        EXIT_SYSTEM_ERROR
    } else if outcome.source_coverage_incomplete || outcome.total_source_failure {
        EXIT_SOURCE_FAILED
    } else {
        EXIT_SUCCESS
    }
}

pub(super) fn profiler_build_identity() -> keyhog_profile::BuildIdentityV2 {
    let mut features = Vec::new();
    for (enabled, name) in [
        (cfg!(feature = "mimalloc"), "mimalloc"),
        (cfg!(feature = "allocation-profile"), "allocation-profile"),
        (cfg!(feature = "ci-lean"), "ci-lean"),
        (cfg!(feature = "portable"), "portable"),
        (cfg!(feature = "full"), "full"),
        (cfg!(feature = "ci"), "ci"),
        (cfg!(feature = "git"), "git"),
        (cfg!(feature = "github"), "github"),
        (cfg!(feature = "gitlab"), "gitlab"),
        (cfg!(feature = "bitbucket"), "bitbucket"),
        (cfg!(feature = "azure"), "azure"),
        (cfg!(feature = "gcs"), "gcs"),
        (cfg!(feature = "s3"), "s3"),
        (cfg!(feature = "docker"), "docker"),
        (cfg!(feature = "binary"), "binary"),
        (cfg!(feature = "web"), "web"),
        (cfg!(feature = "slack"), "slack"),
        (cfg!(feature = "verify"), "verify"),
        (cfg!(feature = "gpu"), "gpu"),
        (cfg!(feature = "simd"), "simd"),
        (cfg!(feature = "static-hyperscan"), "static-hyperscan"),
    ] {
        if enabled {
            features.push(name);
        }
    }
    let hyperscan = keyhog_scanner::hw_probe::hyperscan_runtime_identity();
    let mut backends = vec![("scalar", "builtin")];
    if let Some(version) = hyperscan.as_deref() {
        backends.push(("hyperscan", version));
    }
    keyhog_profile::BuildIdentityV2::capture(keyhog_profile::BuildIdentityInput {
        binary_version: env!("CARGO_PKG_VERSION"),
        enabled_features: &features,
        allocator: if cfg!(feature = "mimalloc") {
            "mimalloc"
        } else {
            "system"
        },
        linked_backends: &backends,
    })
}

fn profiler_detector_identity(
    orchestrator: &ScanOrchestrator,
) -> keyhog_profile::DetectorIdentityV2 {
    fn field(hasher: &mut Sha256, tag: &[u8], value: &[u8]) {
        hasher.update((tag.len() as u64).to_le_bytes());
        hasher.update(tag);
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value);
    }

    let provenance = &orchestrator.detector_corpus_provenance;
    let mut provenance_hasher = Sha256::new();
    field(
        &mut provenance_hasher,
        b"domain",
        b"keyhog-profile-detector-provenance-v1",
    );
    field(&mut provenance_hasher, b"mode", provenance.mode.as_bytes());
    field(
        &mut provenance_hasher,
        b"source",
        provenance.source.as_bytes(),
    );
    field(
        &mut provenance_hasher,
        b"embedded_count",
        &(provenance.embedded_count as u64).to_le_bytes(),
    );
    field(
        &mut provenance_hasher,
        b"custom_count",
        &(provenance.custom_count as u64).to_le_bytes(),
    );
    let provenance_digest = format!("{:x}", provenance_hasher.finalize());
    let enabled_detector_digest = keyhog_core::hex_encode(&orchestrator.detector_spec_hash);
    let compiled_plan_digest =
        keyhog_core::hex_encode(&orchestrator.scanner.runtime_status().compiled_plan_digest);

    keyhog_profile::DetectorIdentityV2::capture(keyhog_profile::DetectorIdentityInput {
        corpus_digest: &orchestrator.detector_corpus_digest,
        compiled_plan_digest: Some(&compiled_plan_digest),
        enabled_detector_digest: Some(&enabled_detector_digest),
        backend_database_digest: None,
        external_provenance_digest: Some(&provenance_digest),
    })
}

fn profiler_config_identity(
    orchestrator: &ScanOrchestrator,
    protection_state: &str,
) -> keyhog_profile::ConfigIdentityV2 {
    let resolved_digest = keyhog_core::hex_encode(
        &crate::orchestrator_config::profiling_resolved_config_digest(
            &orchestrator.effective_config,
        ),
    );
    let policy_digest = keyhog_core::hex_encode(
        &crate::orchestrator_config::profiling_policy_digest(&orchestrator.effective_config),
    );
    let preset = if orchestrator.args.precision {
        "precision"
    } else if orchestrator.args.deep {
        "deep"
    } else if orchestrator.args.fast {
        "fast"
    } else {
        "default"
    };

    keyhog_profile::ConfigIdentityV2::capture(keyhog_profile::ConfigIdentityInput {
        resolved_config_digest: &resolved_digest,
        policy_digest: Some(&policy_digest),
        preset: Some(preset),
        protection_state: Some(protection_state),
    })
}

fn unavailable_cache_evidence(
    reason: keyhog_profile::EvidenceGap,
) -> keyhog_profile::Evidence<String> {
    keyhog_profile::Evidence::unavailable(reason)
}

fn cache_file_digest(path: &std::path::Path) -> keyhog_profile::Evidence<String> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) => {
            let reason = if error.kind() == std::io::ErrorKind::PermissionDenied {
                keyhog_profile::EvidenceGap::PermissionDenied
            } else {
                keyhog_profile::EvidenceGap::Unavailable
            };
            return unavailable_cache_evidence(reason);
        }
    };
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => {
                return keyhog_profile::Evidence::recorded(hasher.finalize().to_hex().to_string())
            }
            Ok(read) => hasher.update(&buffer[..read]),
            Err(error) => {
                let reason = if error.kind() == std::io::ErrorKind::PermissionDenied {
                    keyhog_profile::EvidenceGap::PermissionDenied
                } else {
                    keyhog_profile::EvidenceGap::Unavailable
                };
                return unavailable_cache_evidence(reason);
            }
        };
    }
}

fn profiler_cache_identities(
    orchestrator: &ScanOrchestrator,
    merkle_status: Option<&keyhog_core::MerkleLoadStatus>,
) -> Vec<keyhog_profile::CacheLayerV2> {
    use keyhog_profile::{CacheLayerKindV2, CacheLayerV2, CacheState, Evidence, EvidenceGap};

    let compiled_plan =
        keyhog_core::hex_encode(&orchestrator.scanner.runtime_status().compiled_plan_digest);
    let detector = CacheLayerV2 {
        version: 1,
        layer: CacheLayerKindV2::Detector,
        state: CacheState::Warm,
        generation: Evidence::recorded(compiled_plan),
        digest: Evidence::recorded(orchestrator.detector_corpus_digest.clone()),
    };

    let merkle_enabled = merkle_status.is_some();
    // A failed load carries full evidence (path plus failure kind) and the
    // run rebuilds the cache, so it is a cold start, never `unknown`.
    let merkle_state = match merkle_status {
        None => CacheState::Disabled,
        Some(keyhog_core::MerkleLoadStatus::Missing { .. }) => CacheState::Cold,
        Some(keyhog_core::MerkleLoadStatus::Loaded { .. }) => CacheState::Warm,
        Some(_) => CacheState::Cold,
    };
    let merkle_digest = match merkle_status {
        Some(keyhog_core::MerkleLoadStatus::Loaded { path, .. }) => cache_file_digest(path),
        Some(
            keyhog_core::MerkleLoadStatus::ReadFailed { path, .. }
            | keyhog_core::MerkleLoadStatus::ParseFailed { path, .. }
            | keyhog_core::MerkleLoadStatus::SchemaMismatch { path, .. }
            | keyhog_core::MerkleLoadStatus::SpecChanged { path }
            | keyhog_core::MerkleLoadStatus::InvalidEntryHash { path, .. },
        ) => cache_file_digest(path),
        _ => unavailable_cache_evidence(if merkle_enabled {
            EvidenceGap::Unavailable
        } else {
            EvidenceGap::CollectorDisabled
        }),
    };
    let merkle = CacheLayerV2 {
        version: 1,
        layer: CacheLayerKindV2::Merkle,
        state: merkle_state,
        generation: if merkle_enabled {
            Evidence::recorded(keyhog_core::hex_encode(&orchestrator.detector_spec_hash))
        } else {
            unavailable_cache_evidence(EvidenceGap::CollectorDisabled)
        },
        digest: merkle_digest,
    };

    let autoroute_path = orchestrator
        .effective_config
        .autoroute_cache_path
        .as_deref();
    let autoroute_state = match autoroute_path {
        None => CacheState::Disabled,
        Some(path) if path.exists() => CacheState::Warm,
        Some(_) => CacheState::Cold,
    };
    let autoroute = CacheLayerV2 {
        version: 1,
        layer: CacheLayerKindV2::Autoroute,
        state: autoroute_state,
        generation: autoroute_path.map_or_else(
            || unavailable_cache_evidence(EvidenceGap::CollectorDisabled),
            |_| Evidence::recorded(super::dispatch::autoroute_engine_identity()),
        ),
        digest: autoroute_path.map_or_else(
            || unavailable_cache_evidence(EvidenceGap::CollectorDisabled),
            |path| {
                if path.exists() {
                    cache_file_digest(path)
                } else {
                    unavailable_cache_evidence(EvidenceGap::Unavailable)
                }
            },
        ),
    };

    let verifier_enabled = orchestrator.effective_config.report.verify;
    let verifier = CacheLayerV2 {
        version: 1,
        layer: CacheLayerKindV2::Verifier,
        state: if verifier_enabled {
            CacheState::Cold
        } else {
            CacheState::Disabled
        },
        generation: if verifier_enabled {
            Evidence::recorded(keyhog_core::hex_encode(
                &crate::orchestrator_config::profiling_policy_digest(
                    &orchestrator.effective_config,
                ),
            ))
        } else {
            unavailable_cache_evidence(EvidenceGap::CollectorDisabled)
        },
        digest: unavailable_cache_evidence(if verifier_enabled {
            EvidenceGap::Unavailable
        } else {
            EvidenceGap::CollectorDisabled
        }),
    };

    let fallback_hyperscan_dir = dirs::cache_dir().map(|b| b.join("keyhog"));
    let hyperscan_path = orchestrator
        .effective_config
        .hyperscan_cache_dir
        .as_deref()
        .or(fallback_hyperscan_dir.as_deref());
    let hyperscan_state = match hyperscan_path {
        None => CacheState::Disabled,
        Some(path) if path.exists() => CacheState::Warm,
        Some(_) => CacheState::Cold,
    };
    let hyperscan = CacheLayerV2 {
        version: 1,
        layer: CacheLayerKindV2::HyperscanShards,
        state: hyperscan_state,
        generation: hyperscan_path.map_or_else(
            || unavailable_cache_evidence(EvidenceGap::CollectorDisabled),
            |_| Evidence::recorded("hyperscan-shards".to_string()),
        ),
        digest: hyperscan_path.map_or_else(
            || unavailable_cache_evidence(EvidenceGap::CollectorDisabled),
            |path| {
                if path.exists() {
                    cache_file_digest(path)
                } else {
                    unavailable_cache_evidence(EvidenceGap::Unavailable)
                }
            },
        ),
    };

    let matcher_state = match &orchestrator.scanner_materialization {
        Some(super::ScannerMaterialization::Compiled { matcher_outcome }) => {
            match matcher_outcome {
                keyhog_scanner::MatcherArtifactCacheOutcome::Hit => CacheState::Warm,
                keyhog_scanner::MatcherArtifactCacheOutcome::Miss => CacheState::Cold,
                keyhog_scanner::MatcherArtifactCacheOutcome::Invalidated { .. } => CacheState::Cold,
                keyhog_scanner::MatcherArtifactCacheOutcome::Disabled { .. } => {
                    CacheState::Disabled
                }
            }
        }
        _ => CacheState::Disabled,
    };
    let matcher_artifacts = CacheLayerV2 {
        version: 1,
        layer: CacheLayerKindV2::MatcherArtifacts,
        state: matcher_state,
        generation: Evidence::recorded("matcher-artifacts".to_string()),
        digest: unavailable_cache_evidence(EvidenceGap::Unavailable),
    };

    vec![
        detector,
        merkle,
        autoroute,
        verifier,
        hyperscan,
        matcher_artifacts,
        CacheLayerV2 {
            version: 1,
            layer: CacheLayerKindV2::GpuPrograms,
            state: CacheState::Cold,
            generation: unavailable_cache_evidence(EvidenceGap::Unavailable),
            digest: unavailable_cache_evidence(EvidenceGap::Unavailable),
        },
        CacheLayerV2 {
            version: 1,
            layer: CacheLayerKindV2::LockFiles,
            state: CacheState::Warm,
            generation: unavailable_cache_evidence(EvidenceGap::Unavailable),
            digest: unavailable_cache_evidence(EvidenceGap::Unavailable),
        },
        CacheLayerV2 {
            version: 1,
            layer: CacheLayerKindV2::Daemon,
            state: CacheState::Disabled,
            generation: unavailable_cache_evidence(EvidenceGap::CollectorDisabled),
            digest: unavailable_cache_evidence(EvidenceGap::CollectorDisabled),
        },
        CacheLayerV2 {
            version: 1,
            layer: CacheLayerKindV2::PageCache,
            state: CacheState::Unknown,
            generation: unavailable_cache_evidence(EvidenceGap::Unsupported),
            digest: unavailable_cache_evidence(EvidenceGap::Unsupported),
        },
    ]
}

/// Explicit per-layer cache-state transitions derived from the exact load
/// evidence captured this run. The Merkle warm load and the verifier layer
/// are refined at finish time with skip/scan and cache-hit counters.
fn profiler_cache_transitions(
    orchestrator: &ScanOrchestrator,
    merkle_status: Option<&keyhog_core::MerkleLoadStatus>,
) -> Vec<super::workflow_state::CacheTransitionRecord> {
    let matcher_outcome = match &orchestrator.scanner_materialization {
        Some(super::ScannerMaterialization::Compiled { matcher_outcome }) => Some(matcher_outcome),
        _ => None,
    };
    vec![
        super::workflow_state::detector_transition(),
        super::workflow_state::merkle_load_transition(merkle_status),
        super::workflow_state::autoroute_transition(
            orchestrator
                .effective_config
                .autoroute_cache_path
                .as_deref(),
        ),
        super::workflow_state::verifier_transition(orchestrator.effective_config.report.verify, 0),
        super::workflow_state::hyperscan_shard_transition(
            orchestrator.effective_config.hyperscan_cache_dir.as_deref(),
            0,
            0,
        ),
        super::workflow_state::matcher_artifact_transition(matcher_outcome),
        super::workflow_state::gpu_program_transition(0, 0),
        super::workflow_state::lock_file_transition(),
        super::workflow_state::daemon_transition(),
    ]
}

fn profiler_findings_digest(findings: &[VerifiedFinding]) -> keyhog_profile::Evidence<String> {
    match serde_json::to_vec(findings) {
        Ok(bytes) => keyhog_profile::Evidence::recorded(blake3::hash(&bytes).to_hex().to_string()),
        Err(_) => keyhog_profile::Evidence::unavailable(keyhog_profile::EvidenceGap::Unavailable), // LAW10: profile serialization failure is explicitly recorded as unavailable evidence; scan output remains authoritative.
    }
}

fn profiler_outcome_identity(
    exit_code: u8,
    findings: &[VerifiedFinding],
    report_path: Option<&std::path::Path>,
    scanner_panicked: bool,
    incremental_cache_errors: usize,
    coverage: &crate::reporting::CoverageCounts,
) -> keyhog_profile::OutcomeIdentityV2 {
    let fail_gaps = coverage.fail_class_total();
    let all_gaps = crate::reporting::coverage_gap_summary(coverage)
        .into_iter()
        .map(|(_, count)| count)
        .sum::<usize>();
    let coverage_state = if exit_code == crate::exit_codes::EXIT_INTERRUPTED {
        keyhog_profile::CoverageStateV2::Cancelled
    } else if fail_gaps > 0 || scanner_panicked {
        keyhog_profile::CoverageStateV2::Failed
    } else if all_gaps > 0 || incremental_cache_errors > 0 {
        keyhog_profile::CoverageStateV2::Partial
    } else {
        keyhog_profile::CoverageStateV2::Complete
    };
    let error_count = fail_gaps
        .saturating_add(incremental_cache_errors)
        .saturating_add(usize::from(scanner_panicked));
    let status = if matches!(
        coverage_state,
        keyhog_profile::CoverageStateV2::Failed | keyhog_profile::CoverageStateV2::Cancelled
    ) || incremental_cache_errors > 0
    {
        keyhog_profile::RunState::Failed
    } else {
        keyhog_profile::RunState::Completed
    };
    let report_digest = report_path.map_or_else(
        || keyhog_profile::Evidence::unavailable(keyhog_profile::EvidenceGap::Unsupported),
        cache_file_digest,
    );
    keyhog_profile::OutcomeIdentityV2::recorded(
        status,
        coverage_state,
        u64::try_from(error_count).unwrap_or(u64::MAX), // LAW10: the profile-only error count saturates when usize exceeds u64; every source error remains in the result stream.
        i32::from(exit_code),
        profiler_findings_digest(findings),
        report_digest,
    )
}

fn write_profile_artifact(causal: &keyhog_profile::CausalProfileV2, path: &std::path::Path) {
    let result = (|| -> std::io::Result<()> {
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(format!(".tmp-{}", std::process::id()));
        let tmp = std::path::PathBuf::from(tmp);
        let bytes = serde_json::to_vec_pretty(causal)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    match result {
        Ok(()) => eprintln!("profile artifact={}", path.display()),
        Err(error) => eprintln!(
            "error: failed to write profile artifact {}: {error}. Pick a writable --profile-out path.",
            path.display()
        ),
    }
}

fn build_evidence_text(evidence: &keyhog_profile::Evidence<String>) -> &str {
    match evidence {
        keyhog_profile::Evidence::Recorded { value } => value,
        keyhog_profile::Evidence::Unavailable { reason } => match reason {
            keyhog_profile::EvidenceGap::LegacyV1NotRecorded => "unavailable:legacy-v1",
            keyhog_profile::EvidenceGap::CollectorDisabled => "unavailable:disabled",
            keyhog_profile::EvidenceGap::PermissionDenied => "unavailable:permission-denied",
            keyhog_profile::EvidenceGap::Unsupported => "unavailable:unsupported",
            keyhog_profile::EvidenceGap::Unavailable => "unavailable",
        },
    }
}
fn workload_evidence_text(evidence: &keyhog_profile::Evidence<u64>) -> String {
    match evidence {
        keyhog_profile::Evidence::Recorded { value } => value.to_string(),
        keyhog_profile::Evidence::Unavailable { reason } => match reason {
            keyhog_profile::EvidenceGap::LegacyV1NotRecorded => "unavailable:legacy-v1".to_owned(),
            keyhog_profile::EvidenceGap::CollectorDisabled => "unavailable:disabled".to_owned(),
            keyhog_profile::EvidenceGap::PermissionDenied => {
                "unavailable:permission-denied".to_owned()
            }
            keyhog_profile::EvidenceGap::Unsupported => "unavailable:unsupported".to_owned(),
            keyhog_profile::EvidenceGap::Unavailable => "unavailable".to_owned(),
        },
    }
}

fn cache_layer_text(layer: keyhog_profile::CacheLayerKindV2) -> &'static str {
    match layer {
        keyhog_profile::CacheLayerKindV2::LegacyAggregate => "legacy-aggregate",
        keyhog_profile::CacheLayerKindV2::Detector => "detector",
        keyhog_profile::CacheLayerKindV2::Merkle => "merkle",
        keyhog_profile::CacheLayerKindV2::Autoroute => "autoroute",
        keyhog_profile::CacheLayerKindV2::Verifier => "verifier",
        keyhog_profile::CacheLayerKindV2::Daemon => "daemon",
        keyhog_profile::CacheLayerKindV2::PageCache => "page-cache",
        keyhog_profile::CacheLayerKindV2::HyperscanShards => "hyperscan-shards",
        keyhog_profile::CacheLayerKindV2::MatcherArtifacts => "matcher-artifacts",
        keyhog_profile::CacheLayerKindV2::GpuPrograms => "gpu-programs",
        keyhog_profile::CacheLayerKindV2::LockFiles => "lock-files",
    }
}

fn cache_state_text(state: keyhog_profile::CacheState) -> &'static str {
    match state {
        keyhog_profile::CacheState::Unknown => "unknown",
        keyhog_profile::CacheState::Disabled => "disabled",
        keyhog_profile::CacheState::Cold => "cold",
        keyhog_profile::CacheState::Warm => "warm",
    }
}

fn coverage_state_text(state: keyhog_profile::CoverageStateV2) -> &'static str {
    match state {
        keyhog_profile::CoverageStateV2::Complete => "complete",
        keyhog_profile::CoverageStateV2::Partial => "partial",
        keyhog_profile::CoverageStateV2::Failed => "failed",
        keyhog_profile::CoverageStateV2::Cancelled => "cancelled",
        keyhog_profile::CoverageStateV2::Unknown => "unknown",
    }
}

fn exit_evidence_text(evidence: &keyhog_profile::Evidence<i32>) -> String {
    match evidence {
        keyhog_profile::Evidence::Recorded { value } => value.to_string(),
        keyhog_profile::Evidence::Unavailable { reason } => {
            build_evidence_text(&keyhog_profile::Evidence::<String>::unavailable(*reason))
                .to_owned()
        }
    }
}

struct OperatorProfile {
    session: Option<keyhog_profile::Session>,
    build: Option<keyhog_profile::BuildIdentityV2>,
    detectors: Option<keyhog_profile::DetectorIdentityV2>,
    config: Option<keyhog_profile::ConfigIdentityV2>,
    source: Option<keyhog_profile::SourceIdentityV2>,
    caches: Option<Vec<keyhog_profile::CacheLayerV2>>,
    cache_transitions: Vec<super::workflow_state::CacheTransitionRecord>,
    verification: Option<super::workflow_state::VerificationAggregate>,
    outcome: Option<keyhog_profile::OutcomeIdentityV2>,
    artifact_path: Option<std::path::PathBuf>,
}

impl OperatorProfile {
    fn start(
        enabled: bool,
        mut early_session: Option<keyhog_profile::Session>,
        early_build: Option<std::thread::JoinHandle<keyhog_profile::BuildIdentityV2>>,
        identity: keyhog_profile::RunIdentity,
        detectors: Option<keyhog_profile::DetectorIdentityV2>,
        config: Option<keyhog_profile::ConfigIdentityV2>,
        source: Option<keyhog_profile::SourceIdentityV2>,
        artifact_path: Option<std::path::PathBuf>,
    ) -> Result<Self> {
        let build = enabled.then(|| {
            early_build
                .and_then(|capture| capture.join().ok()) // LAW10: a profiler-only capture panic yields regenerated build metadata; scan execution and errors are unaffected.
                .unwrap_or_else(profiler_build_identity) // LAW10: absent profiler capture is replaced with current build identity; this does not select a scan backend or suppress findings.
        });
        let session = if enabled {
            if let Some(session) = early_session.as_mut() {
                *session.identity_mut() = identity;
                early_session
            } else {
                Some(keyhog_profile::Session::start(identity).map_err(anyhow::Error::new)?)
            }
        } else {
            None
        };
        crate::set_operator_profile_active(session.is_some());
        Ok(Self {
            session,
            build,
            detectors,
            config,
            source,
            caches: None,
            cache_transitions: Vec::new(),
            verification: None,
            outcome: None,
            artifact_path,
        })
    }

    fn transition(&mut self, state: keyhog_profile::RunState) {
        if let Some(session) = self.session.as_mut() {
            session.transition(state);
        }
    }

    fn set_source_identity(&mut self, source: keyhog_profile::SourceIdentityV2) {
        if self.session.is_some() {
            self.source = Some(source);
        }
    }

    fn set_cache_identities(
        &mut self,
        caches: Vec<keyhog_profile::CacheLayerV2>,
        transitions: Vec<super::workflow_state::CacheTransitionRecord>,
    ) {
        if self.session.is_some() {
            self.caches = Some(caches);
            self.cache_transitions = transitions;
        }
    }

    fn set_outcome(&mut self, outcome: keyhog_profile::OutcomeIdentityV2) {
        if self.session.is_some() {
            self.outcome = Some(outcome);
        }
    }

    fn set_verification(&mut self, verify_enabled: bool, findings: &[VerifiedFinding]) {
        if self.session.is_some() {
            // Cache-hit evidence is only visible in the span forest, which is
            // drained in `finish`; it is merged into this aggregate there.
            self.verification = Some(super::workflow_state::aggregate_verification_findings(
                verify_enabled,
                findings,
            ));
        }
    }
    fn identity_mut(&mut self) -> Option<&mut keyhog_profile::RunIdentity> {
        self.session
            .as_mut()
            .map(keyhog_profile::Session::identity_mut)
    }

    fn finish_recorded(
        &mut self,
        exit_code: u8,
        findings: &[VerifiedFinding],
        report_path: Option<&std::path::Path>,
        scanner_panicked: bool,
        force_failure: bool,
        verify_enabled: bool,
    ) {
        let coverage = crate::reporting::CoverageCounts::current();
        let mut outcome = profiler_outcome_identity(
            exit_code,
            findings,
            report_path,
            scanner_panicked,
            crate::INCREMENTAL_CACHE_ERRORS.load(std::sync::atomic::Ordering::Relaxed),
            &coverage,
        );
        if force_failure {
            outcome.status = keyhog_profile::RunState::Failed;
            outcome.coverage = keyhog_profile::CoverageStateV2::Failed;
            if matches!(
                outcome.error_count,
                keyhog_profile::Evidence::Recorded { value: 0 }
            ) {
                outcome.error_count = keyhog_profile::Evidence::recorded(1);
            }
        }
        let status = outcome.status;
        self.set_outcome(outcome);
        self.set_verification(verify_enabled, findings);
        self.finish(status);
    }

    fn finish(&mut self, state: keyhog_profile::RunState) {
        if let Some(session) = self.session.take() {
            let runtime = session.runtime();
            let batch_routes = runtime.take_session_batch_routes();
            let (spans, dropped_events) = runtime.take_session_span_records();
            let latency_distributions = runtime.take_session_latency_distributions();
            let (point_events, annotations, event_loss) = runtime.take_session_typed_events();
            // These five read the same per-worker shards `session.finish`
            // drains, so they must run while the session is still alive.
            let stage_concurrency = runtime.take_session_stage_concurrency();
            let worker_occupancy = runtime.take_session_worker_occupancy();
            let queue_depths = runtime.take_session_queue_depths();
            let blocked_waits = runtime.take_session_blocked_waits();
            let cache_effectiveness = runtime.take_session_cache_effectiveness();
            let indexed_counters = runtime.take_session_indexed_counters();
            let retries = runtime.take_session_retries();
            // Verifier cache hits are only observable as IncrementalLookup
            // spans nested under LiveVerification; count them before the
            // forest moves into the event stream.
            let verifier_cache_hits = super::workflow_state::count_verifier_cache_hits(&spans);
            // Residual input records not yet drained by a per-partition take
            // (e.g. a late async adapter record). Must be drained while the
            // session context is still entered; `session.finish` drops it.
            let (unattributed_bytes, unattributed_units) = keyhog_profile::take_input_totals();
            let profile = session.finish(state);
            let typed_metrics = runtime.take_session_typed_metrics();
            let emit_text = self.artifact_path.is_none();
            let report = emit_text.then(|| profile.render_text());
            // Rendering a profile must never be able to end a scan. The build
            // identity is captured when profiling is enabled, so the absent
            // case is unreachable; recapturing it is still cheaper than a
            // panic and keeps the report complete.
            let build = self.build.take().unwrap_or_else(profiler_build_identity); // LAW10: missing profiler metadata is regenerated only for the causal report; scan findings and errors are already complete.
            let requested_backend = profile.identity.backend_requested.clone();
            let mut causal = keyhog_profile::CausalProfileV2::from_v1_with_build(profile, build);
            causal.typed_metrics = typed_metrics;
            causal.latency_distributions = latency_distributions;
            causal.stage_concurrency = stage_concurrency;
            causal.worker_occupancy = Some(worker_occupancy);
            causal.queue_depths = queue_depths;
            causal.blocked_waits = blocked_waits;
            causal.caches = cache_effectiveness;
            causal.indexed_counters = indexed_counters;
            causal.retries = retries;
            causal.events = keyhog_profile::EventStreamV2 {
                version: keyhog_profile::EVENT_SCHEMA_VERSION,
                availability: keyhog_profile::Evidence::recorded(true),
                dropped_events: dropped_events.saturating_add(event_loss.capacity_drops()),
                dropped_span_events: dropped_events,
                dropped_point_events: event_loss.point_events,
                dropped_annotations: event_loss.annotations,
                sampled_out_events: event_loss.sampled_out_events,
                spans,
                point_events,
                annotations,
            };
            causal.identity.route = keyhog_profile::RouteIdentityV2::from_recorded_batches(
                requested_backend,
                batch_routes,
            );
            // These three enrich the identity the v1 conversion already filled
            // with explicit legacy gaps. When an enrichment is missing, that
            // honest gap is the right answer, not a crash.
            if let Some(detectors) = self.detectors.take() {
                causal.identity.detectors = detectors;
            }
            if let Some(config) = self.config.take() {
                causal.identity.config = config;
            }
            if let Some(source) = self.source.take() {
                causal.identity.source = source;
            }
            // Lead with the conclusion. The span-by-span report below is the
            // evidence for it, and an operator who only reads the first line
            // still learns what limited the run.
            let insight = keyhog_profile::RunInsightV2::derive(&causal);
            if emit_text {
                eprint!("{}", insight.render_summary());
            }
            causal.insight = Some(insight);
            if let Some(report) = report {
                eprint!("{report}");
            }
            // Workflow-state identity: the in-process orchestrator only runs
            // with the daemon route off (daemon-routed scans are served by
            // `run_via_daemon` and surface daemon request profiles instead),
            // so the off state is exact and the daemon-scoped fields are
            // reported as disabled rather than left as legacy-v1 gaps.
            causal.identity.daemon = keyhog_profile::DaemonIdentityV2 {
                version: 1,
                state: keyhog_profile::DaemonState::Off,
                generation: keyhog_profile::Evidence::unavailable(
                    keyhog_profile::EvidenceGap::CollectorDisabled,
                ),
                request_id: keyhog_profile::Evidence::unavailable(
                    keyhog_profile::EvidenceGap::CollectorDisabled,
                ),
                parent_request_id: keyhog_profile::Evidence::unavailable(
                    keyhog_profile::EvidenceGap::CollectorDisabled,
                ),
                ready_age_ns: keyhog_profile::Evidence::unavailable(
                    keyhog_profile::EvidenceGap::CollectorDisabled,
                ),
            };
            // Refine the evidence-derived transitions with run-terminal
            // counters: a warm Merkle load that served every chunk is a
            // steady-state repeat, and recorded verifier cache hits warm the
            // otherwise process-cold verifier layer.
            let skipped_unchanged = super::workflow_state::merkle_skipped_unchanged();
            let scanned_chunks = crate::SCANNED_CHUNKS
                .load(std::sync::atomic::Ordering::Relaxed)
                .min(u64::MAX as usize) as u64;
            for transition in &mut self.cache_transitions {
                transition.transition = match transition.layer {
                    keyhog_profile::CacheLayerKindV2::Merkle => {
                        super::workflow_state::refine_merkle_warmth(
                            transition.transition,
                            skipped_unchanged,
                            scanned_chunks,
                        )
                    }
                    keyhog_profile::CacheLayerKindV2::Verifier => {
                        if matches!(
                            transition.transition,
                            super::workflow_state::CacheTransition::Disabled
                        ) {
                            transition.transition
                        } else {
                            super::workflow_state::verifier_transition(true, verifier_cache_hits)
                                .transition
                        }
                    }
                    _ => transition.transition,
                };
            }
            if let Some(caches) = self.caches.take() {
                let mut caches = caches;
                if verifier_cache_hits > 0 {
                    for layer in &mut caches {
                        if layer.layer == keyhog_profile::CacheLayerKindV2::Verifier
                            && layer.state == keyhog_profile::CacheState::Cold
                        {
                            layer.state = keyhog_profile::CacheState::Warm;
                        }
                    }
                }
                causal.identity.caches = caches;
            }
            if let Some(verification) = &mut self.verification {
                verification.cached = verifier_cache_hits;
            }
            if let Some(outcome) = self.outcome.take() {
                causal.identity.outcome = outcome;
            }
            let (partitions, dropped_partitions) = super::workflow_state::take_source_partitions();
            if let Some(path) = self.artifact_path.take() {
                write_profile_artifact(&causal, &path);
            }
            if !emit_text {
                crate::set_operator_profile_active(false);
                return;
            }
            eprintln!(
                "build binary_sha256={} feature_sha256={} target={} profile={} compiler={} allocator={} backends_sha256={}",
                build_evidence_text(&causal.identity.build.binary_digest),
                build_evidence_text(&causal.identity.build.feature_digest),
                build_evidence_text(&causal.identity.build.target_triple),
                build_evidence_text(&causal.identity.build.build_profile),
                build_evidence_text(&causal.identity.build.compiler_identity),
                build_evidence_text(&causal.identity.build.allocator_identity),
                build_evidence_text(&causal.identity.build.linked_backend_digest),
            );
            eprintln!(
                "detectors corpus_sha256={} compiled_plan_blake3={} enabled_detector_blake3={} backend_database={} external_provenance_sha256={}",
                causal.identity.detectors.corpus_digest,
                build_evidence_text(&causal.identity.detectors.compiled_plan_digest),
                build_evidence_text(&causal.identity.detectors.enabled_detector_digest),
                build_evidence_text(&causal.identity.detectors.backend_database_digest),
                build_evidence_text(&causal.identity.detectors.external_provenance_digest),
            );
            eprintln!(
                "config resolved_blake3={} policy_blake3={} preset={} protection={}",
                causal.identity.config.resolved_config_digest,
                build_evidence_text(&causal.identity.config.policy_digest),
                build_evidence_text(&causal.identity.config.preset),
                build_evidence_text(&causal.identity.config.protection_state),
            );
            eprintln!(
                "source adapters={} target_blake3={} partition_blake3={}",
                causal.identity.source.adapters.join(","),
                build_evidence_text(&causal.identity.source.target_digest),
                build_evidence_text(&causal.identity.source.partition_digest),
            );
            eprintln!(
                "workload class={} raw_source_bytes={} source_units={} container_bytes={} expanded_payload_bytes={} derived_decoder_bytes={} backend_dispatched_bytes={} size_bucket={} fanout_bucket={}",
                causal.identity.workload.class,
                causal.identity.workload.raw_source_bytes,
                causal.identity.workload.source_units,
                workload_evidence_text(&causal.identity.workload.container_bytes),
                workload_evidence_text(&causal.identity.workload.expanded_payload_bytes),
                workload_evidence_text(&causal.identity.workload.derived_decoder_bytes),
                workload_evidence_text(&causal.identity.workload.backend_dispatched_bytes),
                build_evidence_text(&causal.identity.workload.size_bucket),
                build_evidence_text(&causal.identity.workload.fanout_bucket),
            );
            let recovered_batches = causal
                .identity
                .route
                .batches
                .iter()
                .filter(|batch| {
                    matches!(
                        batch.recovered_from_backend,
                        keyhog_profile::Evidence::Recorded { .. }
                    )
                })
                .count();
            eprintln!(
                "route mode={} requested={} selected={} completed={} batches={} recovered_batches={} autoroute_decision_blake3={}",
                causal.identity.route.request_mode,
                causal.identity.route.requested_backend,
                build_evidence_text(&causal.identity.route.selected_backend),
                build_evidence_text(&causal.identity.route.completed_backend),
                causal.identity.route.batches.len(),
                recovered_batches,
                build_evidence_text(&causal.identity.route.autoroute_decision_digest),
            );
            for metric in &causal.typed_metrics {
                let kind = match metric.kind {
                    keyhog_profile::MetricKind::Counter => "counter",
                    keyhog_profile::MetricKind::Gauge => "gauge",
                    keyhog_profile::MetricKind::Duration => "duration",
                    keyhog_profile::MetricKind::Distribution => "distribution",
                };
                eprintln!(
                    "metric id={} kind={} value={}",
                    metric.metric_id.descriptor().name,
                    kind,
                    metric.value,
                );
            }
            for latency in &causal.latency_distributions {
                eprintln!(
                    "latency micro={} macro={} calls={} min_ns={} p50_ns={} p90_ns={} p95_ns={} p99_ns={} max_ns={}",
                    latency.metric_id.descriptor().name,
                    latency.macro_stage_id.as_str(),
                    latency.call_count,
                    latency.minimum_ns,
                    latency.p50_ns,
                    latency.p90_ns,
                    latency.p95_ns,
                    latency.p99_ns,
                    latency.maximum_ns,
                );
            }
            let root_spans = causal
                .events
                .spans
                .iter()
                .filter(|span| {
                    matches!(
                        span.parent_span_id,
                        keyhog_profile::Evidence::Unavailable { .. }
                    )
                })
                .count();
            let total_inclusive_ns = causal
                .events
                .spans
                .iter()
                .fold(0_u64, |total, span| total.saturating_add(span.inclusive_ns));
            let total_exclusive_ns = causal
                .events
                .spans
                .iter()
                .fold(0_u64, |total, span| total.saturating_add(span.exclusive_ns));
            eprintln!(
                "events spans={} roots={} points={} annotations={} dropped={} sampled_out={} inclusive_ns={} exclusive_ns={}",
                causal.events.spans.len(),
                root_spans,
                causal.events.point_events.len(),
                causal.events.annotations.len(),
                causal.events.dropped_events,
                causal.events.sampled_out_events,
                total_inclusive_ns,
                total_exclusive_ns,
            );
            eprintln!(
                "outcome status={} coverage={} errors={} exit={} findings_blake3={} report_blake3={}",
                match causal.identity.outcome.status {
                    keyhog_profile::RunState::Completed => "completed",
                    keyhog_profile::RunState::Failed => "failed",
                    _ => "incomplete",
                },
                coverage_state_text(causal.identity.outcome.coverage),
                workload_evidence_text(&causal.identity.outcome.error_count),
                exit_evidence_text(&causal.identity.outcome.exit_code),
                build_evidence_text(&causal.identity.outcome.findings_digest),
                build_evidence_text(&causal.identity.outcome.report_digest),
            );
            for cache in &causal.identity.caches {
                eprintln!(
                    "cache layer={} state={} generation={} digest={}",
                    cache_layer_text(cache.layer),
                    cache_state_text(cache.state),
                    build_evidence_text(&cache.generation),
                    build_evidence_text(&cache.digest),
                );
            }
            for transition in &self.cache_transitions {
                eprintln!(
                    "cache-transition layer={} evidence={} transition={}",
                    cache_layer_text(transition.layer),
                    transition.evidence,
                    transition.transition.as_str(),
                );
            }
            if let Some(verification) = &self.verification {
                eprintln!(
                    "verification policy={} state={} queued={} network={} cached={} unverifiable={} skipped={}",
                    if verification.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    },
                    verification.state_label(),
                    verification.queued,
                    verification.network,
                    verification.cached,
                    verification.unverifiable,
                    verification.skipped,
                );
            }
            // Multi-source partition causality: per-source measured
            // contributions recorded at the production seam, then the merge
            // line proving the partitions plus any unattributed remainder
            // sum back to the session aggregate.
            let mut partition_units = 0_u64;
            let mut partition_bytes = 0_u64;
            for partition in &partitions {
                partition_units = partition_units.saturating_add(partition.units);
                partition_bytes = partition_bytes.saturating_add(partition.bytes);
                eprintln!(
                    "partition index={} kind={} units={} bytes={}",
                    partition.index, partition.kind, partition.units, partition.bytes,
                );
            }
            eprintln!(
                "partition-merge partitions={} units={} bytes={} unattributed_units={} unattributed_bytes={} aggregate_units={} aggregate_bytes={} seam=result-merge dropped_partitions={}",
                partitions.len(),
                partition_units,
                partition_bytes,
                unattributed_units,
                unattributed_bytes,
                causal.identity.workload.source_units,
                causal.identity.workload.raw_source_bytes,
                dropped_partitions,
            );
            eprintln!(
                "daemon state={} generation={} request={} ready_age={}",
                match causal.identity.daemon.state {
                    keyhog_profile::DaemonState::Off => "off",
                    keyhog_profile::DaemonState::Client => "client",
                    keyhog_profile::DaemonState::Worker => "worker",
                    keyhog_profile::DaemonState::Mass => "mass",
                },
                build_evidence_text(&causal.identity.daemon.generation),
                build_evidence_text(&causal.identity.daemon.request_id),
                workload_evidence_text(&causal.identity.daemon.ready_age_ns),
            );
            crate::set_operator_profile_active(false);
        }
    }
}

/// Operator-visible rendering of one daemon-served request profile. Lives on
/// the same stderr profile surface as the in-process `--profile` report so a
/// `keyhog scan --daemon --profile` run stays observable end to end: the
/// daemon measured the request inside its own isolated profiling runtime and
/// the client replays the bounded payload verbatim. Loss counters always
/// print, so bounded-storage drops are never silent.
#[cfg(unix)]
pub(crate) fn render_daemon_request_profile(profile: &crate::daemon::protocol::RequestProfile) {
    eprintln!(
        "daemon request profile id={} wall_time_ns={}",
        profile.request_id, profile.wall_time_ns
    );
    // The server assigns request ids as `{daemon_generation}-{sequence}` and
    // only serves scan requests once the Hello handshake proved the warm
    // route ready, so a returned profile is exact evidence of the daemon
    // generation, the warm readiness, and the resident warm backend that
    // measured the request.
    match super::workflow_state::parse_daemon_request_identity(&profile.request_id) {
        Some(identity) => eprintln!(
            "daemon request identity generation={} sequence={} warm_route=ready warm_backend=resident",
            identity.generation, identity.sequence,
        ),
        None => eprintln!(
            "daemon request identity generation=unavailable sequence=unavailable warm_route=ready warm_backend=resident"
        ),
    }
    for stage in &profile.stages {
        eprintln!(
            "daemon request stage {} calls={} elapsed_ns={}",
            stage.stage, stage.calls, stage.elapsed_ns
        );
    }
    eprintln!(
        "daemon request profile loss dropped_span_events={} dropped_point_events={} dropped_annotations={} sampled_out_events={}",
        profile.dropped_span_events,
        profile.dropped_point_events,
        profile.dropped_annotations,
        profile.sampled_out_events
    );
}

impl Drop for OperatorProfile {
    fn drop(&mut self) {
        self.finish(keyhog_profile::RunState::Failed);
    }
}

impl ScanOrchestrator {
    pub async fn run(mut self) -> Result<std::process::ExitCode> {
        crate::reset_scan_runtime_state();
        super::workflow_state::reset_workflow_state();
        // `--no-default-excludes` disables EVERY default exclusion, not just the
        // walker's. The vendored/minified path suppression used to survive the
        // flag, so the walker read `app.min.js` and reported its bytes as
        // scanned while the scanner threw away the `sk_live_` key inside it. The
        // flag now means what it says. This must run after
        // `reset_scan_runtime_state`, which restores the default.
        keyhog_scanner::telemetry::set_vendored_path_suppression(!self.args.no_default_excludes);
        let start = Instant::now();
        let wall_start = chrono::Utc::now();
        let stderr_is_tty = std::io::stderr().is_terminal();
        // `--no-color` forces plain output everywhere in the scan path; it
        // rides the same `NO_COLOR` convention the palette helpers already read
        // so a single env set covers the report formatter, the ticker, and the
        // diagnostic palette without threading a flag through every call.
        if self.args.no_color {
            std::env::set_var("NO_COLOR", "1");
        }
        let no_color = self.args.no_color || crate::style::no_color_requested();
        // Fold the `NO_COLOR` env convention into the flag so the stdout report
        // formatter (which honors `args.no_color`) also drops color on a TTY
        // when the operator set `NO_COLOR`, matching the ticker/palette.
        self.args.no_color = no_color;
        // `--quiet` suppresses the interactive chrome (banner / ticker /
        // completion summary) while leaving coverage FAIL/WARN and fatal errors
        // intact, so a quiet scan is never mistaken for a clean one.
        let show_progress = !self.args.quiet && (self.args.progress || stderr_is_tty);
        let progress_ansi = stderr_is_tty && !no_color;

        if self.args.dogfood {
            keyhog_scanner::telemetry::enable_dogfood();
        }

        let hardening = keyhog_core::apply_protections(false);
        let mut protection_state = if hardening.failures.is_empty() {
            "default-applied"
        } else {
            "default-degraded"
        };
        if !hardening.failures.is_empty() {
            tracing::warn!(
                failures = ?hardening.failures,
                "default hardening protections did not fully apply"
            );
        }

        if self.args.lockdown {
            #[cfg(feature = "verify")]
            if self.effective_config.report.verify {
                anyhow::bail!(
                    "lockdown mode forbids --verify (would send credentials \
                     to outbound HTTPS endpoints). Drop --verify or drop --lockdown."
                );
            }

            if self.effective_config.report.show_secrets {
                anyhow::bail!(
                    "lockdown mode forbids --show-secrets (would print plaintext credentials \
                     to stdout/stderr). Drop --show-secrets or drop --lockdown."
                );
            }

            let lockdown = keyhog_core::apply_protections_with_persistence_paths(
                true,
                self.lockdown_persistence_cache_paths(),
            );
            if !lockdown.failures.is_empty() {
                anyhow::bail!(
                    "lockdown mode requested but protections failed to apply: {:?}",
                    lockdown.failures
                );
            }
            tracing::info!(
                mlocked = lockdown.mlocked,
                "lockdown mode active: mlocked + coredump-blocked + cache-free"
            );
            protection_state = "lockdown-applied";
            let palette = style::for_stderr();
            eprintln!(
                "{} LOCKDOWN MODE: no findings cache on disk, mlocked, no live verifier",
                style::info("INFO", &palette)
            );

            if self.args.no_default_excludes {
                anyhow::bail!(
                    "lockdown mode forbids --no-default-excludes (would scan untrusted \
                     lock files / minified bundles / vendor dirs that are common \
                     credential-leak vectors)."
                );
            }
            if self.args.no_unicode_norm {
                anyhow::bail!(
                    "lockdown mode forbids --no-unicode-norm (would let homoglyph \
                     attackers hide secrets behind visually identical Unicode)."
                );
            }
            if self.args.no_decode {
                anyhow::bail!(
                    "lockdown mode forbids --no-decode (encoded secrets like \
                     base64('AKIA…') would slip through entirely)."
                );
            }
            if self.args.no_entropy {
                anyhow::bail!(
                    "lockdown mode forbids --no-entropy (entropy detection is the \
                     only catch for novel / unknown high-entropy secrets)."
                );
            }
            if self.args.no_ml {
                anyhow::bail!(
                    "lockdown mode forbids --no-ml (ML confidence gating reduces \
                     false-negative rate on hand-crafted near-misses)."
                );
            }
            if self.args.fast {
                anyhow::bail!(
                    "lockdown mode forbids --fast (it disables decode + entropy + ML \
                     simultaneously, the largest detection blind spot we ship)."
                );
            }
        }
        #[cfg(feature = "verify")]
        if self.effective_config.verify.oob.enabled {
            keyhog_verifier::oob::prewarm_key_generation();
        }

        let hw = keyhog_scanner::hw_probe::probe_hardware();
        let scanner_status = self.scanner.runtime_status();
        let backend_policy = if self.effective_config.autoroute_calibration {
            "calibrate"
        } else if let Some(backend) = self.effective_config.backend_override {
            backend.label()
        } else {
            "auto:persisted-per-workload"
        };
        tracing::info!(
            backend_policy,
            gpu_available = hw.gpu_available,
            gpu_software = hw.gpu_is_software,
            hyperscan = hw.hyperscan_available,
            avx512 = hw.has_avx512,
            avx2 = hw.has_avx2,
            neon = hw.has_neon,
            "scan backend policy configured"
        );
        if show_progress {
            if let Err(error) =
                crate::write_banner(&mut std::io::stderr(), progress_ansi, self.detector_count)
            {
                tracing::debug!(%error, "banner write error");
            }
            let gpu_candidates = self.scanner.gpu_backend_candidates();
            let gpu_label = gpu_candidates
                .iter()
                .filter(|candidate| candidate.is_eligible())
                .map(|candidate| candidate.backend.label())
                .collect::<Vec<_>>()
                .join(",");
            let gpu_label = if gpu_label.is_empty() {
                "none"
            } else {
                gpu_label.as_str()
            };
            eprintln!(
                "⚡ {} | backend={backend_policy} | gpu={gpu_label}",
                keyhog_scanner::hw_probe::startup_banner(
                    hw,
                    self.detector_count,
                    scanner_status.pattern_count,
                )
            );
            for candidate in gpu_candidates
                .iter()
                .filter(|candidate| !candidate.is_eligible())
            {
                if let Some(error) = candidate.acquisition_error.as_deref() {
                    eprintln!(
                        "gpu candidate unavailable | backend={} | error={error}",
                        candidate.backend.label()
                    );
                } else if candidate.available {
                    eprintln!(
                        "gpu candidate ineligible | backend={} | software={} | complete_identity={}",
                        candidate.backend.label(),
                        candidate.is_software,
                        candidate.has_complete_identity(),
                    );
                }
            }
        }

        // Require-GPU preflight, independent of backend routing. When
        // `--require-gpu` is resolved and no usable GPU adapter is present (or
        // the GPU self-test fails), fail closed with the dedicated scan exit
        // code BEFORE warming a backend or scanning a byte. Routing the failure
        // through the CLI ExitCode here - rather than a scanner-lib
        // process::exit - keeps the exit contract in the CLI layer.
        if let Err(diagnostic) = keyhog_scanner::gpu::require_gpu_preflight() {
            eprintln!("keyhog: {diagnostic}");
            return Ok(std::process::ExitCode::from(EXIT_REQUIRE_GPU_UNMET));
        }

        // A backend owns no work until the first real batch. Eagerly warming an
        // explicit diagnostic override compiled every lazy regex and
        // deserialized every native SIMD database even for empty or rejected
        // inputs. Dispatch performs the same fail-closed initialization once it
        // has bytes, so keep zero-byte scans free of backend runtime state.
        tracing::debug!(
            target: "keyhog::routing",
            calibration_mode = self.effective_config.autoroute_calibration,
            explicit_backend = ?self.effective_config.backend_override,
            "backend materialization awaits the first real batch"
        );

        if self.args.benchmark {
            // Name the GPU that produced the GPU row so the operator can tell
            // which adapter the throughput figures came from.
            eprintln!("benchmark | gpu={}", crate::benchmark::format_gpu_summary());
            let results = crate::benchmark::run_benchmark(&self)?;
            let baseline_mb = results
                .iter()
                .map(|r| r.mb_per_sec)
                .fold(f64::INFINITY, f64::min)
                .max(f64::EPSILON);
            for result in &results {
                let speedup = result.mb_per_sec / baseline_mb;
                eprintln!(
                    "benchmark | backend={:<14} | throughput={:>8.2} MiB/s | speedup={:>5.2}× | findings={:>4} | bytes={}",
                    result.backend.label(),
                    result.mb_per_sec,
                    speedup,
                    result.findings,
                    result.bytes_scanned
                );
            }
            if let Some(fastest) = results
                .iter()
                .max_by(|a, b| a.mb_per_sec.total_cmp(&b.mb_per_sec))
            {
                eprintln!(
                    "benchmark winner: {} at {:.2} MiB/s",
                    fastest.backend.label(),
                    fastest.mb_per_sec
                );
            }
            return Ok(std::process::ExitCode::SUCCESS);
        }

        let config_digest =
            crate::orchestrator_config::autoroute_config_digest(&self.effective_config);
        let mut profile_identity = keyhog_profile::RunIdentity::new(
            env!("CARGO_PKG_VERSION"),
            self.detector_corpus_digest.clone(),
            format!("{config_digest:016x}"),
            "pending",
            "runtime-batches",
            backend_policy,
        );
        profile_identity.backend_selected =
            Some(self.effective_config.backend_override.map_or_else(
                || "autoroute-per-workload".to_owned(),
                |backend| backend.label().to_owned(),
            ));
        profile_identity.scanner_threads = rayon::current_num_threads();
        profile_identity.reader_threads = self.effective_config.reader_threads;
        let profile_enabled =
            self.effective_config.scanner.profile || self.args.profile_out.is_some();
        let detector_identity = profile_enabled.then(|| profiler_detector_identity(&self));
        let config_identity =
            profile_enabled.then(|| profiler_config_identity(&self, protection_state));
        let source_identity =
            profile_enabled.then(|| crate::sources::profiling_source_identity(&self.args, &[]));
        let early_profile_session = self.early_profile_session.take();
        let early_profile_build = self.early_profile_build.take();
        let mut operator_profile = OperatorProfile::start(
            profile_enabled,
            early_profile_session,
            early_profile_build,
            profile_identity,
            detector_identity,
            config_identity,
            source_identity,
            self.args.profile_out.clone(),
        )?;
        operator_profile.transition(keyhog_profile::RunState::Acquiring);

        let (allowlist, incremental_cache_path, merkle, merkle_status, sources) = {
            let _profile_span = keyhog_profile::span(keyhog_profile::Stage::SourceAcquire);
            let allowlist =
                load_allowlist(self.args.path.as_deref(), &self.effective_config.allowlist)?;
            let incremental_cache_path = self.incremental_cache_path()?;
            let (merkle, merkle_status) =
                self.build_merkle_index(incremental_cache_path.as_deref());
            let sources = crate::sources::build_sources(
                &self.args,
                &self.effective_config,
                allowlist.ignored_paths.as_ref().to_vec(),
                merkle.clone(),
            )?;
            (
                allowlist,
                incremental_cache_path,
                merkle,
                merkle_status,
                sources,
            )
        };
        operator_profile.set_cache_identities(
            profiler_cache_identities(&self, merkle_status.as_ref()),
            profiler_cache_transitions(&self, merkle_status.as_ref()),
        );
        if sources.is_empty() {
            anyhow::bail!(
                "no input source specified. Use --path, --stdin, --git, --git-diff, --git-history, --github-org, --gitlab-group, --bitbucket-workspace, --s3-bucket, --gcs-bucket, --azure-container-url, or --docker-image"
            );
        }
        operator_profile.set_source_identity(crate::sources::profiling_source_identity(
            &self.args, &sources,
        ));
        if let Some(identity) = operator_profile.identity_mut() {
            identity.source_kind = sources
                .iter()
                .map(|source| source.name())
                .collect::<Vec<_>>()
                .join("+");
            let mut workload_adapters = sources
                .iter()
                .map(|source| source.name())
                .collect::<Vec<_>>();
            workload_adapters.sort_unstable();
            workload_adapters.dedup();
            identity.workload_class = workload_adapters.join("+");
            identity.cache_state = match merkle_status.as_ref() {
                None => keyhog_profile::CacheState::Disabled,
                Some(keyhog_core::MerkleLoadStatus::Missing { .. }) => {
                    keyhog_profile::CacheState::Cold
                }
                Some(keyhog_core::MerkleLoadStatus::Loaded { .. }) => {
                    keyhog_profile::CacheState::Warm
                }
                // Failed load: evidence exists and the cache is rebuilt, so
                // the run is cold, never `unknown`.
                Some(_) => keyhog_profile::CacheState::Cold,
            };
        }

        operator_profile.transition(keyhog_profile::RunState::Scanning);
        let all_matches = {
            let _profile_span = keyhog_profile::span(keyhog_profile::Stage::ScanPipeline);
            self.scan_sources(sources, show_progress, merkle, incremental_cache_path)?
        };
        operator_profile.transition(keyhog_profile::RunState::Resolving);
        let filtered = {
            let _profile_span = keyhog_profile::span(keyhog_profile::Stage::Suppression);
            self.filter_and_resolve(all_matches, &allowlist)?
        };
        operator_profile.transition(keyhog_profile::RunState::Verifying);
        let mut findings = {
            let _profile_span = keyhog_profile::span(keyhog_profile::Stage::LiveVerification);
            self.finalize(filtered).await?
        };
        operator_profile.transition(keyhog_profile::RunState::Reporting);

        let _suppression_span = keyhog_profile::span(keyhog_profile::Stage::Suppression);
        let rule_suppressor = load_rule_suppressor(self.args.path.as_deref())?;
        let pre_rule_count = findings.len();
        let hide_client_safe = self.effective_config.report.hide_client_safe;
        let mut client_safe_dropped = 0usize;
        findings.retain(|f| {
            if rule_suppressor.matches(f) {
                return false;
            }
            if hide_client_safe && f.severity == keyhog_core::Severity::ClientSafe {
                client_safe_dropped += 1;
                return false;
            }
            true
        });
        drop(_suppression_span);

        // KH-GAP-096: a requested source that failed ENTIRELY, producing zero
        // chunks AND erroring (e.g. --git-history / --git-diff on a non-repo or
        // bad ref, --github-org with a bad token, an unreachable --url, or a
        // tree whose every entry was unreadable or over a cap), means the scan
        // did not cover what was asked of it. That must NOT read as "no
        // findings, all clean" + exit 0: a CI gate would take it for a clean
        // tree when nothing was examined.
        //
        // It must equally NOT discard the run. This used to return here, ahead
        // of report emission, so `-o out.json` produced NO FILE AT ALL: not an
        // empty envelope, not a gap row, nothing. Our loudest failure was the
        // only one with no machine-readable output, so a CI job could not tell
        // "we could not scan your input" from "the tool never ran", and the
        // shipped generic-shell and Drone recipes pre-seeded an empty envelope
        // purely to work around it. The verdict belongs in the exit code; the
        // reason belongs in the report. Both are now always produced.
        //
        // A partial failure (some entries unreadable in a tree that still
        // produced chunks) does not set FAILED_SOURCES at all, and a failed
        // source running alongside one that DID surface findings still exits 1,
        // because `resolve_scan_exit` ranks findings above coverage.
        let total_source_failure =
            crate::FAILED_SOURCES.load(std::sync::atomic::Ordering::Relaxed) > 0;
        if total_source_failure && findings.is_empty() {
            eprintln!(
                "error: a requested scan source failed to read and produced no data (see the \
                 warnings above). Not reporting \"clean\": that scan did not run. A report is \
                 still written, stating what was not covered and why. Check the repository \
                 path, ref, token, or URL and re-run."
            );
        }

        if show_progress {
            let dropped = pre_rule_count - findings.len() - client_safe_dropped;
            if dropped > 0 {
                eprintln!(
                    "\n  Suppressed {} finding(s) via .keyhogignore.toml",
                    dropped
                );
            }
        }
        if show_progress && client_safe_dropped > 0 {
            eprintln!(
                "\n  Suppressed {} client-safe finding(s) via --hide-client-safe (public-by-design keys)",
                client_safe_dropped
            );
        }

        // Reliability outcomes gate baseline mutation (KH-504 / KH-1352).
        // Panic, incremental-cache failure, FAIL-class coverage gaps, or a
        // source that produced nothing at all must not mint a "successful"
        // baseline. Deliberate WARN skips (binary, over-max-size) do not
        // poison baseline writes.
        let scanner_panicked = crate::SCANNER_PANICKED.load(std::sync::atomic::Ordering::Relaxed);
        let incremental_cache_failed =
            crate::INCREMENTAL_CACHE_ERRORS.load(std::sync::atomic::Ordering::Relaxed) > 0;
        let source_coverage_incomplete = source_coverage_incomplete();
        let baseline_coverage_failed = baseline_coverage_untrustworthy();
        let autoroute_persist_failed =
            crate::AUTOROUTE_PERSIST_ERRORS.load(std::sync::atomic::Ordering::Relaxed) > 0;
        let baseline_untrustworthy = scanner_panicked
            || incremental_cache_failed
            || baseline_coverage_failed
            || total_source_failure;

        if let Some(path) = &self.args.create_baseline {
            if baseline_untrustworthy {
                let exit = resolve_scan_exit(ScanOutcome {
                    autoroute_calibration: false,
                    scanner_panicked,
                    has_live_credentials: false,
                    has_blocking_findings: false,
                    incremental_cache_failed,
                    source_coverage_incomplete: baseline_coverage_failed,
                    total_source_failure,
                    autoroute_persist_failed,
                });
                eprintln!(
                    "error: refusing --create-baseline: scan is untrustworthy \
                     (panic={}, coverage_failed={}, incremental_cache_failed={}). \
                     Prior baseline left unchanged.",
                    scanner_panicked, baseline_coverage_failed, incremental_cache_failed
                );
                for (reason, count) in crate::reporting::coverage_gap_summary(
                    &crate::reporting::CoverageCounts::current(),
                ) {
                    if count > 0 {
                        eprintln!("  coverage gap: {count} {reason}");
                    }
                }
                operator_profile.finish_recorded(
                    exit,
                    &findings,
                    None,
                    scanner_panicked,
                    true,
                    self.effective_config.report.verify,
                );
                return Ok(std::process::ExitCode::from(exit));
            }
            let baseline = Baseline::from_findings(&findings);
            baseline.save(path)?;
            if show_progress {
                eprintln!(
                    "\n📝 Baseline created with {} entries at {}",
                    baseline.entries.len(),
                    path.display()
                );
            }
            // Snapshot still writes even with findings (exit 0), but Live must
            // not collapse to green: CI that combines --create-baseline --verify
            // needs exit 10 (KH-1439).
            let has_live = findings
                .iter()
                .any(|f| matches!(f.verification, VerificationResult::Live));
            if has_live {
                operator_profile.finish_recorded(
                    EXIT_LIVE_CREDENTIALS,
                    &findings,
                    Some(path),
                    scanner_panicked,
                    false,
                    self.effective_config.report.verify,
                );
                return Ok(std::process::ExitCode::from(EXIT_LIVE_CREDENTIALS));
            }
            operator_profile.finish_recorded(
                EXIT_SUCCESS,
                &findings,
                Some(path),
                scanner_panicked,
                false,
                self.effective_config.report.verify,
            );
            return Ok(std::process::ExitCode::SUCCESS);
        }

        let report_findings = if let Some(path) = &self.args.update_baseline {
            if baseline_untrustworthy {
                let exit = resolve_scan_exit(ScanOutcome {
                    autoroute_calibration: false,
                    scanner_panicked,
                    has_live_credentials: false,
                    has_blocking_findings: false,
                    incremental_cache_failed,
                    source_coverage_incomplete: baseline_coverage_failed,
                    total_source_failure,
                    autoroute_persist_failed,
                });
                eprintln!(
                    "error: refusing --update-baseline: scan is untrustworthy \
                     (panic={}, coverage_failed={}, incremental_cache_failed={}). \
                     Prior baseline left byte-identical.",
                    scanner_panicked, baseline_coverage_failed, incremental_cache_failed
                );
                for (reason, count) in crate::reporting::coverage_gap_summary(
                    &crate::reporting::CoverageCounts::current(),
                ) {
                    if count > 0 {
                        eprintln!("  coverage gap: {count} {reason}");
                    }
                }
                operator_profile.finish_recorded(
                    exit,
                    &findings,
                    None,
                    scanner_panicked,
                    true,
                    self.effective_config.report.verify,
                );
                return Ok(std::process::ExitCode::from(exit));
            }
            let mut baseline = if path.exists() {
                Baseline::load(path)?
            } else {
                Baseline::empty()
            };
            let keep = baseline.new_finding_mask(&findings);
            let new_count = keep.iter().filter(|keep| **keep).count();
            baseline.merge(&findings);
            baseline.save(path)?;
            if show_progress {
                eprintln!(
                    "\n📝 Baseline updated: added {} new entries at {}",
                    new_count,
                    path.display()
                );
            }
            Baseline::retain_mask(&mut findings, &keep);
            findings
        } else if let Some(path) = &self.args.baseline {
            let baseline = Baseline::load(path)?;
            let pre_baseline_count = findings.len();
            baseline.retain_new(&mut findings);
            let suppressed_count = pre_baseline_count - findings.len();
            if show_progress && suppressed_count > 0 {
                eprintln!("\n  Suppressed {} baseline finding(s)", suppressed_count);
            }
            findings
        } else {
            findings
        };

        let exit_class = scan_exit_code(
            &report_findings,
            self.effective_config.report.evidence_policy.is_paranoid(),
        );
        let has_live_credentials = exit_class == EXIT_LIVE_CREDENTIALS;
        let has_blocking_findings = exit_class == EXIT_FINDINGS;

        // `--stream`: emit one redacted `[stream]` preview per REPORTED finding.
        // Wired to the resolved report stream (post filter_and_resolve /
        // suppression / --min-confidence / baseline) rather than the raw scanner
        // matches, so a streamed line always corresponds to a finding the report
        // and exit code agree on. (AUD-testing_dogfood-1: the old wiring streamed
        // raw matches the report later dropped, lying about the result.)
        if self.args.stream {
            super::reporting::stream_report_previews(&report_findings);
        }

        let report_finished_at = chrono::Utc::now();
        let report_metadata = crate::reporting::report_metadata_from_scan_run_with_corpus(
            &self.args,
            wall_start,
            report_finished_at,
            start.elapsed().as_millis(),
            crate::SCANNED_CHUNKS.load(std::sync::atomic::Ordering::Relaxed),
            crate::SCANNED_BYTES.load(std::sync::atomic::Ordering::Relaxed),
            self.detector_count,
            &self.detector_corpus_digest,
            &self.detector_corpus_provenance,
            Some(crate::orchestrator_config::autoroute_config_digest(
                &self.effective_config,
            )),
        );
        let show_reporting_progress = show_progress
            && !self.args.stream
            && (self.args.output.is_some() || !std::io::stdout().is_terminal());
        let report_finding_count = report_findings.len();
        let reporting_progress = show_reporting_progress.then(|| {
            TickerGuard::spawn("reporting", move |done, started| {
                super::reporting::reporting_ticker(done, started, report_finding_count)
            })
        });
        let report_result = {
            let _profile_span = keyhog_profile::span(keyhog_profile::Stage::Reporting);
            crate::reporting::report_findings_with_metadata(
                &report_findings,
                &self.args,
                &report_metadata,
            )
        };
        if let Some(guard) = reporting_progress {
            guard.stop();
        }
        if let Err(error) = report_result {
            // Exit 3, not 13, and say so. "We could not scan your input" and
            // "we scanned it and could not write the answer down" need opposite
            // responses (fix the input versus fix the output path), and after
            // the always-emit change they would otherwise share one signature:
            // non-zero exit, no report on disk. The exit code separates them;
            // this line names the path so an operator does not have to infer it.
            match self.args.output.as_deref() {
                Some(path) => eprintln!(
                    "error: the scan completed but its report could not be written to {}: \
                     {error}. The findings above were produced and then lost at the output \
                     step; this is an output-path failure, not a coverage failure.",
                    path.display()
                ),
                None => eprintln!(
                    "error: the scan completed but its report could not be emitted: {error}. \
                     This is an output failure, not a coverage failure."
                ),
            }
            let coverage_counts = crate::reporting::CoverageCounts::current();
            let mut outcome = profiler_outcome_identity(
                EXIT_SYSTEM_ERROR,
                &report_findings,
                None,
                scanner_panicked,
                crate::INCREMENTAL_CACHE_ERRORS.load(std::sync::atomic::Ordering::Relaxed),
                &coverage_counts,
            );
            outcome.coverage = keyhog_profile::CoverageStateV2::Failed;
            outcome.status = keyhog_profile::RunState::Failed;
            outcome.error_count = keyhog_profile::Evidence::recorded(1);
            let outcome_status = outcome.status;
            operator_profile.set_outcome(outcome);
            operator_profile
                .set_verification(self.effective_config.report.verify, &report_findings);
            operator_profile.finish(outcome_status);
            return Err(error);
        }

        let elapsed = start.elapsed().as_secs_f64();
        if show_progress {
            report_completion_summary(
                &report_findings,
                elapsed,
                progress_ansi,
                self.effective_config.backend_override,
            );
            report_scanner_materialization_summary(
                progress_ansi,
                self.scanner_materialization.as_ref(),
            );
            report_compiled_cache_summary(progress_ansi, &self);
        } else {
            report_skip_summary(false);
        }
        // Autoroute cache state is status, not decoration, so it is reported in
        // both modes. `--format json -o <file>` takes the non-progress branch,
        // and that is the exact shape CI and calibration harnesses run.
        report_autoroute_cache_summary(
            show_progress && progress_ansi,
            self.effective_config.backend_override.is_some(),
        );
        dump_dogfood_trace();

        tracing::info!(
            "Done in {:.1}s. {} findings",
            elapsed,
            report_findings.len()
        );

        let exit = resolve_scan_exit(ScanOutcome {
            autoroute_calibration: self.args.autoroute_calibrate,
            scanner_panicked,
            has_live_credentials,
            has_blocking_findings,
            incremental_cache_failed,
            source_coverage_incomplete,
            total_source_failure,
            autoroute_persist_failed,
        });
        crate::action_report::write_scan_receipt(
            &self.args,
            report_findings.len(),
            exit,
            report_metadata.scan_status,
        )?;
        // The total-source-failure case already printed its own, more specific
        // diagnostic before the report was written, so do not restate it.
        if exit == EXIT_SOURCE_FAILED && !total_source_failure {
            eprintln!(
                "error: input coverage was incomplete (see coverage warnings above). Not \
                 reporting \"clean\": some requested bytes were not scanned."
            );
        }
        let coverage_counts = crate::reporting::CoverageCounts::current();
        let outcome = profiler_outcome_identity(
            exit,
            &report_findings,
            self.args.output.as_deref(),
            scanner_panicked,
            crate::INCREMENTAL_CACHE_ERRORS.load(std::sync::atomic::Ordering::Relaxed),
            &coverage_counts,
        );
        let outcome_status = outcome.status;
        operator_profile.set_outcome(outcome);
        operator_profile.set_verification(self.effective_config.report.verify, &report_findings);
        {
            let _profile_span = keyhog_profile::span(keyhog_profile::Stage::Teardown);
            drop(self.scanner);
        }
        operator_profile.finish(outcome_status);
        Ok(std::process::ExitCode::from(exit))
    }
}

/// Pure exit-code mapping for the reported finding set.
///
/// Live verification takes precedence and returns
/// [`EXIT_LIVE_CREDENTIALS`] (10). Otherwise, confirmed and likely evidence
/// return [`EXIT_FINDINGS`] (1) under the default policy. Review evidence
/// remains visible but returns [`EXIT_SUCCESS`] (0), unless `paranoid` is true.
///
/// Verification states other than `Live` do not independently change the exit
/// code. Their scanner evidence still applies, so a dead or skipped finding can
/// block when its tier is confirmed or likely.
///
/// Keeping this mapping pure gives daemon and one-shot reporting one
/// definitional source for identical exit semantics.
pub(crate) fn scan_exit_code(findings: &[VerifiedFinding], paranoid: bool) -> u8 {
    if findings
        .iter()
        .any(|finding| matches!(finding.verification, VerificationResult::Live))
    {
        EXIT_LIVE_CREDENTIALS
    } else if findings
        .iter()
        .any(|finding| finding.evidence.tier().blocks(paranoid))
    {
        EXIT_FINDINGS
    } else {
        EXIT_SUCCESS
    }
}

/// Incomplete exit 13 and baseline refusal share the CoverageGapKind FAIL set
/// (KH-1347 / KH-1352). WARN skips (binary, over-max-size, deliberate exclude,
/// advisory scanner truncations) must not flip a clean scan to exit 13.
fn source_coverage_incomplete() -> bool {
    fail_class_coverage_gaps() > 0
}

fn baseline_coverage_untrustworthy() -> bool {
    fail_class_coverage_gaps() > 0
}

fn fail_class_coverage_gaps() -> usize {
    // Single owner: CoverageGapKind severity table via CoverageCounts (KH-1410).
    crate::reporting::CoverageCounts::current().fail_class_total()
}
