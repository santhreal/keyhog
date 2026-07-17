//! Read-only, operator-facing projection of persisted autoroute evidence.

use serde::Serialize;

use super::artifact_identity::current_executable_sha256;
use super::codec::{
    autoroute_cache_file_presence, parse_autoroute_cache, read_autoroute_cache_file,
    CacheParseError,
};
use super::schema::AutorouteBuildFeatures;
use super::validation::{current_unix_time_ms, validate_cache_structure_at};
use crate::orchestrator::dispatch::backend::host::{host_identity_digest, render_host_profile};
use crate::orchestrator::dispatch::backend::workload::render_workload_key;
use crate::orchestrator::dispatch::backend::AUTOROUTE_CACHE_VERSION;

#[cfg(test)]
mod tests;

/// One operator-visible readiness state shared by every autoroute health surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AutorouteReadiness {
    Direct,
    Ready,
    CalibrationRequired,
    Disabled,
    Stale,
    Invalid,
}

impl AutorouteReadiness {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Ready => "ready",
            Self::CalibrationRequired => "calibration_required",
            Self::Disabled => "disabled",
            Self::Stale => "stale",
            Self::Invalid => "invalid",
        }
    }

    pub(crate) const fn repair_command(self) -> Option<&'static str> {
        match self {
            Self::Direct | Self::Ready => None,
            Self::Disabled => Some("keyhog calibrate-autoroute --autoroute-cache <PATH>"),
            Self::CalibrationRequired | Self::Stale | Self::Invalid => {
                Some("keyhog calibrate-autoroute")
            }
        }
    }

    pub(crate) const fn required_repair_command(self) -> Result<&'static str, &'static str> {
        match self.repair_command() {
            Some(command) => Ok(command),
            None => Err("healthy autoroute readiness has no repair command"),
        }
    }
}

/// Operator-facing view of the persisted autoroute cache (one JSON object).
#[derive(Debug, Default, Serialize)]
pub(crate) struct AutorouteCacheInspection {
    pub(crate) path: Option<String>,
    /// Whether this build has multiple compiled scan backends and therefore
    /// needs persisted evidence to select among them.
    pub(crate) calibration_required: bool,
    /// The only possible route when calibration is not required.
    pub(crate) direct_backend: Option<&'static str>,
    pub(crate) present: bool,
    /// Set when this build needs the requested cache but it is disabled, or
    /// when a present cache is unreadable, incompatible, or corrupt.
    pub(crate) error: Option<String>,
    pub(crate) version: Option<u32>,
    pub(crate) binary_version: Option<String>,
    pub(crate) git_hash: Option<String>,
    pub(crate) executable_sha256: Option<String>,
    pub(crate) identity_matches_build: Option<bool>,
    pub(crate) identity_mismatch_reason: Option<String>,
    /// Compatibility projection for consumers of schema v31 inspection JSON.
    /// `configs[].host` is authoritative. This is present only when every
    /// persisted config has the same projected host identity.
    pub(crate) host: Option<String>,
    pub(crate) detector_digest: Option<String>,
    pub(crate) rules_digest: Option<String>,
    pub(crate) inspected_at_unix_ms: Option<u128>,
    pub(crate) configs: Vec<AutorouteConfigInspection>,
}

impl AutorouteCacheInspection {
    pub(crate) fn readiness(&self) -> AutorouteReadiness {
        if !self.calibration_required {
            return AutorouteReadiness::Direct;
        }
        if self.path.is_none() {
            return AutorouteReadiness::Disabled;
        }
        if !self.present && self.error.is_none() {
            return AutorouteReadiness::CalibrationRequired;
        }
        if self.error.is_some() {
            return AutorouteReadiness::Invalid;
        }
        if self.identity_matches_build == Some(false) {
            return AutorouteReadiness::Stale;
        }
        if self.present && self.identity_matches_build == Some(true) {
            AutorouteReadiness::Ready
        } else {
            AutorouteReadiness::Invalid
        }
    }
}

/// One exact resolved scan-config and host generation's calibrated decisions.
#[derive(Debug, Serialize)]
pub(crate) struct AutorouteConfigInspection {
    pub(crate) config_digest: String,
    pub(crate) host_identity: String,
    pub(crate) host: String,
    pub(crate) hyperscan_runtime_identity: Option<String>,
    pub(crate) gpu_batch_input_limit_bytes: Option<u64>,
    pub(crate) eligible_backends: Vec<String>,
    pub(crate) decision_count: usize,
    pub(crate) decisions: Vec<AutorouteDecisionInspection>,
}

/// One calibrated workload decision. Numeric fields are projections derived
/// from primary timing evidence; the cache stores no denormalized copies.
#[derive(Debug, Serialize)]
pub(crate) struct AutorouteDecisionInspection {
    pub(crate) workload: String,
    /// Canonical source-mixture components backing the workload identity.
    /// These fields make the source-class hash-free diagnosis possible for
    /// JSON consumers without parsing the human-readable workload string.
    pub(crate) source_mixture: Vec<AutorouteSourceMixtureInspection>,
    pub(crate) calibrated_at_unix_ms: u128,
    pub(crate) calibration_age_ms: u128,
    /// Cold-aware backend for an in-process one-shot scan.
    pub(crate) backend: String,
    pub(crate) phase2_localizer: bool,
    pub(crate) calibration_points: usize,
    pub(crate) sample_bytes: u64,
    pub(crate) sample_chunks: usize,
    pub(crate) sample_bytes_min: u64,
    pub(crate) sample_bytes_max: u64,
    pub(crate) sample_chunks_min: usize,
    pub(crate) sample_chunks_max: usize,
    pub(crate) measured_points: Vec<AutorouteCalibrationPointInspection>,
    pub(crate) candidate_receipts: Vec<AutorouteCandidateReceiptInspection>,
    pub(crate) simd_ms: u128,
    pub(crate) cpu_ms: Option<u128>,
    pub(crate) gpu_cuda_ms: Option<u128>,
    pub(crate) gpu_cuda_warm_ms: Option<u128>,
    pub(crate) gpu_wgpu_ms: Option<u128>,
    pub(crate) gpu_wgpu_warm_ms: Option<u128>,
    pub(crate) simd_localizer_ms: Option<u128>,
    pub(crate) cpu_localizer_ms: Option<u128>,
    pub(crate) gpu_cuda_localizer_ms: Option<u128>,
    pub(crate) gpu_cuda_localizer_warm_ms: Option<u128>,
    pub(crate) gpu_wgpu_localizer_ms: Option<u128>,
    pub(crate) gpu_wgpu_localizer_warm_ms: Option<u128>,
    /// Whether the one-shot route's 95% confidence interval is entirely below
    /// every competitor. When false, medians decide among non-dominated routes.
    pub(crate) confidence_separated: bool,
    pub(crate) selection_basis: &'static str,
    /// One-shot representative-time margin to the next candidate.
    pub(crate) selected_margin_ns: Option<u128>,
    /// Warm backend derived for a preinitialized persistent daemon.
    pub(crate) daemon_backend: String,
    pub(crate) daemon_phase2_localizer: bool,
    pub(crate) daemon_confidence_separated: bool,
    pub(crate) daemon_selection_basis: &'static str,
    pub(crate) daemon_selected_margin_ns: Option<u128>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AutorouteCalibrationPointInspection {
    pub(crate) sample_bytes: u64,
    pub(crate) sample_chunks: usize,
    pub(crate) calibrated_at_unix_ms: u128,
    pub(crate) one_shot_backend: String,
    pub(crate) one_shot_phase2_localizer: bool,
    pub(crate) daemon_backend: String,
    pub(crate) daemon_phase2_localizer: bool,
    pub(crate) one_shot_confidence_separated: bool,
    pub(crate) daemon_confidence_separated: bool,
    pub(crate) simd_ms: u128,
    pub(crate) cpu_ms: Option<u128>,
    pub(crate) gpu_cuda_ms: Option<u128>,
    pub(crate) gpu_cuda_warm_ms: Option<u128>,
    pub(crate) gpu_wgpu_ms: Option<u128>,
    pub(crate) gpu_wgpu_warm_ms: Option<u128>,
    pub(crate) simd_localizer_ms: Option<u128>,
    pub(crate) cpu_localizer_ms: Option<u128>,
    pub(crate) gpu_cuda_localizer_ms: Option<u128>,
    pub(crate) gpu_cuda_localizer_warm_ms: Option<u128>,
    pub(crate) gpu_wgpu_localizer_ms: Option<u128>,
    pub(crate) gpu_wgpu_localizer_warm_ms: Option<u128>,
    pub(crate) candidate_receipts: Vec<AutorouteCandidateReceiptInspection>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AutorouteSourceMixtureInspection {
    pub(crate) family_digest: String,
    pub(crate) has_full_size: bool,
    pub(crate) chunk_ratio: u64,
    pub(crate) payload_ratio: u64,
    pub(crate) max_span_bucket: u8,
}

#[derive(Debug, Serialize)]
pub(crate) struct AutorouteCandidateReceiptInspection {
    pub(crate) backend: String,
    pub(crate) phase2_localizer: bool,
    pub(crate) correctness_digest: String,
    pub(crate) completed_trials: usize,
    pub(crate) evidence_digest: String,
}

fn selection_basis(confidence_separated: bool) -> &'static str {
    if confidence_separated {
        "separated-95pct-confidence"
    } else {
        "lowest-measured-median-among-overlapping-confidence"
    }
}

/// Inspect without requiring the current detector/host/config inputs. Cheap
/// build drift and the full persisted structure are validated; scan-time load
/// additionally validates the live host, detector, rules, and config identity.
pub(crate) fn inspect_autoroute_cache(path: Option<&std::path::Path>) -> AutorouteCacheInspection {
    inspect_autoroute_cache_for_build(path, keyhog_scanner::hw_probe::multiple_backends_compiled())
}

fn inspect_autoroute_cache_for_build(
    path: Option<&std::path::Path>,
    multiple_backends_compiled: bool,
) -> AutorouteCacheInspection {
    let mut out = AutorouteCacheInspection {
        path: path.map(|path| path.display().to_string()),
        calibration_required: multiple_backends_compiled,
        direct_backend: (!multiple_backends_compiled)
            .then_some(keyhog_scanner::hw_probe::ScanBackend::CpuFallback.label()),
        ..AutorouteCacheInspection::default()
    };

    let Some(path) = path else {
        if multiple_backends_compiled {
            out.error = Some(
                "autoroute cache is disabled (--autoroute-cache off / [system].autoroute_cache = \
                 off); auto scans require an explicit --backend in this configuration"
                    .to_string(),
            );
        }
        return out;
    };
    match autoroute_cache_file_presence(path) {
        Ok(true) => {}
        Ok(false) => return out,
        Err(error) => {
            out.error = Some(format!(
                "autoroute cache path cannot be inspected: {error}. Fix path permissions or parent storage and retry"
            ));
            return out;
        }
    }

    let data = match read_autoroute_cache_file(path) {
        Ok(data) => data,
        Err(error) => {
            out.present = true;
            out.error = Some(format!("autoroute cache is unreadable: {error}"));
            return out;
        }
    };
    out.present = true;

    let cache = match parse_autoroute_cache(&data) {
        Ok(cache) => cache,
        Err(error) => {
            out.version = match &error {
                CacheParseError::Version { found } => Some(*found),
                CacheParseError::Payload(_) => Some(AUTOROUTE_CACHE_VERSION),
                CacheParseError::NotJson(_) => None,
            };
            out.error = Some(error.diagnostic());
            return out;
        }
    };
    out.version = Some(cache.version);
    out.binary_version = Some(cache.binary_version.clone());
    out.git_hash = Some(cache.git_hash.clone());
    out.executable_sha256 = Some(cache.executable_sha256.clone());
    out.detector_digest = Some(format!("{:016x}", cache.detector_digest));
    out.rules_digest = Some(cache.rules_digest.clone());
    let mut drift = Vec::new();
    if cache.binary_version != env!("CARGO_PKG_VERSION") {
        drift.push(format!(
            "binary version {} != current {}",
            cache.binary_version,
            env!("CARGO_PKG_VERSION")
        ));
    }
    if cache.git_hash != keyhog_core::git_hash() {
        drift.push(format!(
            "git hash {} != current {}",
            cache.git_hash,
            keyhog_core::git_hash()
        ));
    }
    match current_executable_sha256() {
        Ok(current) if cache.executable_sha256 != current => drift.push(format!(
            "executable sha256 {} != current {}",
            cache.executable_sha256, current
        )),
        Ok(_) => {}
        Err(error) => drift.push(format!("current executable identity unavailable: {error}")),
    }
    let current_features = AutorouteBuildFeatures::current();
    if cache.build_features != current_features {
        drift.push(format!(
            "build features {} != current {}",
            cache.build_features.describe(),
            current_features.describe()
        ));
    }
    out.identity_matches_build = Some(drift.is_empty());
    if !drift.is_empty() {
        out.identity_mismatch_reason = Some(drift.join("; "));
    }

    let inspected_at_unix_ms = match current_unix_time_ms() {
        Ok(timestamp) => timestamp,
        Err(error) => {
            out.error = Some(format!("autoroute cache time validation failed: {error}"));
            return out;
        }
    };
    out.inspected_at_unix_ms = Some(inspected_at_unix_ms);
    if let Err(error) = validate_cache_structure_at(&cache, inspected_at_unix_ms) {
        out.error = Some(format!(
            "autoroute cache is structurally invalid: {error}; re-run calibration"
        ));
        return out;
    }

    let common_host = cache.configs.first().map(|config| &config.host);
    if common_host.is_some()
        && cache
            .configs
            .iter()
            .all(|config| Some(&config.host) == common_host)
    {
        out.host = common_host.map(render_host_profile);
    }

    for config in &cache.configs {
        let mut decisions = Vec::with_capacity(config.decisions.len());
        for row in &config.decisions {
            let key = &row.workload;
            let decision = &row.decision;
            let Some(daemon_route) = decision.resolved_persistent_route() else {
                out.error = Some(
                    "autoroute cache decision has no persistent-daemon route evidence; \
                     re-run calibration"
                        .to_string(),
                );
                out.configs.clear();
                return out;
            };
            let confidence_separated = decision.has_separated_fastest_route();
            let daemon_confidence_separated = decision.has_separated_fastest_persistent_route();
            let primary = decision.primary_point();
            let sample_bytes_min = decision
                .calibration_points
                .iter()
                .map(|point| point.sample_bytes)
                .min()
                .unwrap_or(primary.sample_bytes);
            let sample_bytes_max = decision
                .calibration_points
                .iter()
                .map(|point| point.sample_bytes)
                .max()
                .unwrap_or(primary.sample_bytes);
            let sample_chunks_min = decision
                .calibration_points
                .iter()
                .map(|point| point.sample_chunks)
                .min()
                .unwrap_or(primary.sample_chunks);
            let sample_chunks_max = decision
                .calibration_points
                .iter()
                .map(|point| point.sample_chunks)
                .max()
                .unwrap_or(primary.sample_chunks);
            let calibrated_at_unix_ms = decision
                .calibration_points
                .iter()
                .map(|point| point.calibrated_at_unix_ms)
                .min()
                .unwrap_or(primary.calibrated_at_unix_ms);
            let measured_points = decision
                .calibration_points
                .iter()
                .map(|point| {
                    let one_shot_route = point
                        .resolve_measured_route(false)
                        .expect("validated point has a one-shot route");
                    let daemon_route = point
                        .resolve_measured_route(true)
                        .expect("validated point has a daemon route");
                    let measured_route =
                        |backend, phase2_localizer| super::super::evidence::MeasuredRoute {
                            backend,
                            phase2_localizer,
                        };
                    let gpu_projection = |backend, phase2_localizer| {
                        point
                            .gpu_cold_warm_route_for_measured(measured_route(
                                backend,
                                phase2_localizer,
                            ))
                            .map(|(_, warm, route_ns)| (route_ns / 1_000_000, warm.median_ms()))
                    };
                    let gpu_cuda = gpu_projection(keyhog_scanner::ScanBackend::GpuCuda, false);
                    let gpu_wgpu = gpu_projection(keyhog_scanner::ScanBackend::GpuWgpu, false);
                    let gpu_cuda_localizer =
                        gpu_projection(keyhog_scanner::ScanBackend::GpuCuda, true);
                    let gpu_wgpu_localizer =
                        gpu_projection(keyhog_scanner::ScanBackend::GpuWgpu, true);
                    AutorouteCalibrationPointInspection {
                        sample_bytes: point.sample_bytes,
                        sample_chunks: point.sample_chunks,
                        calibrated_at_unix_ms: point.calibrated_at_unix_ms,
                        one_shot_backend: one_shot_route.backend.label().to_string(),
                        one_shot_phase2_localizer: one_shot_route.phase2_localizer,
                        daemon_backend: daemon_route.backend.label().to_string(),
                        daemon_phase2_localizer: daemon_route.phase2_localizer,
                        one_shot_confidence_separated: point
                            .selected_route_has_non_overlapping_confidence_for(
                                one_shot_route,
                                false,
                            ),
                        daemon_confidence_separated: point
                            .selected_route_has_non_overlapping_confidence_for(daemon_route, true),
                        simd_ms: point.simd_timing.median_ms(),
                        cpu_ms: point
                            .cpu_timing
                            .as_ref()
                            .map(super::super::evidence::BackendTimingEvidence::median_ms),
                        gpu_cuda_ms: gpu_cuda.map(|(one_shot_ms, _)| one_shot_ms),
                        gpu_cuda_warm_ms: gpu_cuda.map(|(_, warm_ms)| warm_ms),
                        gpu_wgpu_ms: gpu_wgpu.map(|(one_shot_ms, _)| one_shot_ms),
                        gpu_wgpu_warm_ms: gpu_wgpu.map(|(_, warm_ms)| warm_ms),
                        simd_localizer_ms: point
                            .simd_localizer_timing
                            .as_ref()
                            .map(super::super::evidence::BackendTimingEvidence::median_ms),
                        cpu_localizer_ms: point
                            .cpu_localizer_timing
                            .as_ref()
                            .map(super::super::evidence::BackendTimingEvidence::median_ms),
                        gpu_cuda_localizer_ms: gpu_cuda_localizer
                            .map(|(one_shot_ms, _)| one_shot_ms),
                        gpu_cuda_localizer_warm_ms: gpu_cuda_localizer.map(|(_, warm_ms)| warm_ms),
                        gpu_wgpu_localizer_ms: gpu_wgpu_localizer
                            .map(|(one_shot_ms, _)| one_shot_ms),
                        gpu_wgpu_localizer_warm_ms: gpu_wgpu_localizer.map(|(_, warm_ms)| warm_ms),
                        candidate_receipts: point
                            .candidate_receipts
                            .iter()
                            .map(|receipt| AutorouteCandidateReceiptInspection {
                                backend: receipt.backend.clone(),
                                phase2_localizer: receipt.phase2_localizer,
                                correctness_digest: format!("{:016x}", receipt.correctness_digest),
                                completed_trials: receipt.completed_trials,
                                evidence_digest: format!("{:016x}", receipt.evidence_digest),
                            })
                            .collect(),
                    }
                })
                .collect();
            decisions.push(AutorouteDecisionInspection {
                workload: render_workload_key(key),
                source_mixture: key
                    .source_mixture
                    .entries
                    .iter()
                    .map(|entry| AutorouteSourceMixtureInspection {
                        family_digest: keyhog_core::hex_encode(&entry.family_digest),
                        has_full_size: entry.has_full_size,
                        chunk_ratio: entry.chunk_ratio,
                        payload_ratio: entry.payload_ratio,
                        max_span_bucket: entry.max_span_bucket,
                    })
                    .collect(),
                calibrated_at_unix_ms,
                calibration_age_ms: inspected_at_unix_ms - calibrated_at_unix_ms,
                backend: decision.backend.clone(),
                phase2_localizer: decision.phase2_localizer,
                calibration_points: decision.calibration_points.len(),
                sample_bytes: primary.sample_bytes,
                sample_chunks: primary.sample_chunks,
                sample_bytes_min,
                sample_bytes_max,
                sample_chunks_min,
                sample_chunks_max,
                measured_points,
                candidate_receipts: primary
                    .candidate_receipts
                    .iter()
                    .map(|receipt| AutorouteCandidateReceiptInspection {
                        backend: receipt.backend.clone(),
                        phase2_localizer: receipt.phase2_localizer,
                        correctness_digest: format!("{:016x}", receipt.correctness_digest),
                        completed_trials: receipt.completed_trials,
                        evidence_digest: format!("{:016x}", receipt.evidence_digest),
                    })
                    .collect(),
                simd_ms: decision.simd_ms(),
                cpu_ms: decision.cpu_ms(),
                gpu_cuda_ms: decision
                    .gpu_cold_warm_route_for(keyhog_scanner::ScanBackend::GpuCuda)
                    .map(|(_, _, route_ns)| route_ns / 1_000_000),
                gpu_cuda_warm_ms: decision
                    .gpu_cold_warm_route_for(keyhog_scanner::ScanBackend::GpuCuda)
                    .map(|(_, warm, _)| warm.median_ms()),
                gpu_wgpu_ms: decision
                    .gpu_cold_warm_route_for(keyhog_scanner::ScanBackend::GpuWgpu)
                    .map(|(_, _, route_ns)| route_ns / 1_000_000),
                gpu_wgpu_warm_ms: decision
                    .gpu_cold_warm_route_for(keyhog_scanner::ScanBackend::GpuWgpu)
                    .map(|(_, warm, _)| warm.median_ms()),
                simd_localizer_ms: primary
                    .simd_localizer_timing
                    .as_ref()
                    .map(super::super::evidence::BackendTimingEvidence::median_ms),
                cpu_localizer_ms: primary
                    .cpu_localizer_timing
                    .as_ref()
                    .map(super::super::evidence::BackendTimingEvidence::median_ms),
                gpu_cuda_localizer_ms: primary
                    .gpu_cold_warm_route_for_measured(super::super::evidence::MeasuredRoute {
                        backend: keyhog_scanner::ScanBackend::GpuCuda,
                        phase2_localizer: true,
                    })
                    .map(|(_, _, route_ns)| route_ns / 1_000_000),
                gpu_cuda_localizer_warm_ms: primary
                    .gpu_cold_warm_route_for_measured(super::super::evidence::MeasuredRoute {
                        backend: keyhog_scanner::ScanBackend::GpuCuda,
                        phase2_localizer: true,
                    })
                    .map(|(_, warm, _)| warm.median_ms()),
                gpu_wgpu_localizer_ms: primary
                    .gpu_cold_warm_route_for_measured(super::super::evidence::MeasuredRoute {
                        backend: keyhog_scanner::ScanBackend::GpuWgpu,
                        phase2_localizer: true,
                    })
                    .map(|(_, _, route_ns)| route_ns / 1_000_000),
                gpu_wgpu_localizer_warm_ms: primary
                    .gpu_cold_warm_route_for_measured(super::super::evidence::MeasuredRoute {
                        backend: keyhog_scanner::ScanBackend::GpuWgpu,
                        phase2_localizer: true,
                    })
                    .map(|(_, warm, _)| warm.median_ms()),
                confidence_separated,
                selection_basis: selection_basis(confidence_separated),
                selected_margin_ns: decision.selected_margin_ns(),
                daemon_backend: daemon_route.backend.label().to_string(),
                daemon_phase2_localizer: daemon_route.phase2_localizer,
                daemon_confidence_separated,
                daemon_selection_basis: selection_basis(daemon_confidence_separated),
                daemon_selected_margin_ns: decision.persistent_selected_margin_ns(),
            });
        }
        decisions.sort_by(|left, right| left.workload.cmp(&right.workload));
        out.configs.push(AutorouteConfigInspection {
            config_digest: format!("{:016x}", config.config_digest),
            host_identity: host_identity_digest(&config.host),
            host: render_host_profile(&config.host),
            hyperscan_runtime_identity: config.host.hyperscan_runtime_identity.clone(),
            gpu_batch_input_limit_bytes: config.host.gpu_batch_input_limit_bytes,
            eligible_backends: config.host.eligible_backends.clone(),
            decision_count: config.decisions.len(),
            decisions,
        });
    }
    out.configs.sort_by(|left, right| {
        left.config_digest
            .cmp(&right.config_digest)
            .then_with(|| left.host_identity.cmp(&right.host_identity))
    });
    out
}
