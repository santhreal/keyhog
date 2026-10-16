//! Causal profiler identity construction, cache transition evidence, and operator profile rendering.

use std::io::Read;
use anyhow::Result;
use sha2::{Digest, Sha256};
use keyhog_core::VerifiedFinding;
use super::ScanOrchestrator;

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

pub(super) fn profiler_detector_identity(
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

pub(super) fn profiler_config_identity(
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

pub(super) fn profiler_cache_identities(
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

    let hyperscan_resolved = orchestrator
        .effective_config
        .hyperscan_cache_dir
        .clone()
        .or_else(|| dirs::cache_dir().map(|base| base.join("keyhog")));
    let hyperscan_path = hyperscan_resolved.as_deref();
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
pub(super) fn profiler_cache_transitions(
    orchestrator: &ScanOrchestrator,
    merkle_status: Option<&keyhog_core::MerkleLoadStatus>,
) -> Vec<super::workflow_state::CacheTransitionRecord> {
    let matcher_outcome = match &orchestrator.scanner_materialization {
        Some(super::ScannerMaterialization::Compiled { matcher_outcome }) => Some(matcher_outcome),
        _ => None,
    };
    let hyperscan_cache_dir = orchestrator
        .effective_config
        .hyperscan_cache_dir
        .clone()
        .or_else(|| dirs::cache_dir().map(|base| base.join("keyhog")));
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
            hyperscan_cache_dir.as_deref(),
            keyhog_profile::cache_hits(keyhog_profile::CacheId::HyperscanShard),
            keyhog_profile::cache_misses(keyhog_profile::CacheId::HyperscanShard),
        ),
        super::workflow_state::matcher_artifact_transition(matcher_outcome),
        super::workflow_state::gpu_program_transition(
            keyhog_profile::cache_hits(keyhog_profile::CacheId::GpuProgram),
            keyhog_profile::cache_misses(keyhog_profile::CacheId::GpuProgram),
        ),
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

pub(super) fn profiler_outcome_identity(
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

pub(super) struct OperatorProfile {
    pub(super) session: Option<keyhog_profile::Session>,
    pub(super) build: Option<keyhog_profile::BuildIdentityV2>,
    pub(super) detectors: Option<keyhog_profile::DetectorIdentityV2>,
    pub(super) config: Option<keyhog_profile::ConfigIdentityV2>,
    pub(super) source: Option<keyhog_profile::SourceIdentityV2>,
    pub(super) caches: Option<Vec<keyhog_profile::CacheLayerV2>>,
    pub(super) cache_transitions: Vec<super::workflow_state::CacheTransitionRecord>,
    pub(super) verification: Option<super::workflow_state::VerificationAggregate>,
    pub(super) outcome: Option<keyhog_profile::OutcomeIdentityV2>,
    pub(super) artifact_path: Option<std::path::PathBuf>,
}

impl OperatorProfile {
    pub(super) fn start(
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
            causal.compile_surfaces = runtime.compile_surface_reports();
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

