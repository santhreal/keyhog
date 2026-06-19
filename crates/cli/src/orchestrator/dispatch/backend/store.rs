//! Persistent autoroute calibration cache schema and validation.

use std::collections::HashMap;
use std::io::Write;

use serde::{Deserialize, Serialize};

use super::evidence::{
    gpu_cold_warm_route_evidence, selected_backend_margin_ns, AutorouteDecision,
};
use super::host::AutorouteHostProfile;
use super::workload::WorkloadKey;
use super::AUTOROUTE_CACHE_VERSION;
use super::AUTOROUTE_CALIBRATION_TRIALS;

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct AutorouteCache {
    pub(super) version: u32,
    pub(super) binary_version: String,
    pub(super) git_hash: String,
    #[serde(default)]
    pub(super) build_features: AutorouteBuildFeatures,
    pub(super) detector_digest: u64,
    pub(super) rules_digest: String,
    pub(super) config_digest: u64,
    pub(super) host: AutorouteHostProfile,
    pub(super) decisions: Vec<(WorkloadKey, AutorouteDecision)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct AutorouteBuildFeatures {
    #[serde(default)]
    pub(super) cli_features: Vec<String>,
    #[serde(default)]
    pub(super) scanner_features: Vec<String>,
    #[serde(default)]
    pub(super) sources_features: Vec<String>,
    #[serde(default)]
    pub(super) verifier_features: Vec<String>,
}

impl AutorouteBuildFeatures {
    fn current() -> Self {
        Self {
            cli_features: current_cli_features(),
            scanner_features: current_scanner_dependency_features(),
            sources_features: current_sources_dependency_features(),
            verifier_features: current_verifier_dependency_features(),
        }
    }

    fn describe(&self) -> String {
        format!(
            "cli=[{}] scanner=[{}] sources=[{}] verifier=[{}]",
            describe_feature_list(&self.cli_features),
            describe_feature_list(&self.scanner_features),
            describe_feature_list(&self.sources_features),
            describe_feature_list(&self.verifier_features)
        )
    }
}

fn current_cli_features() -> Vec<String> {
    let mut features = Vec::new();
    macro_rules! push_feature {
        ($name:literal) => {
            if cfg!(feature = $name) {
                features.push($name);
            }
        };
    }

    push_feature!("default");
    push_feature!("azure");
    push_feature!("binary");
    push_feature!("ci");
    push_feature!("ci-lean");
    push_feature!("cuda");
    push_feature!("docker");
    push_feature!("fast");
    push_feature!("full");
    push_feature!("gcs");
    push_feature!("github");
    push_feature!("git");
    push_feature!("gpu");
    push_feature!("mimalloc");
    push_feature!("portable");
    push_feature!("s3");
    push_feature!("simd");
    push_feature!("verify");
    push_feature!("web");
    normalize_feature_list(features)
}

fn current_scanner_dependency_features() -> Vec<String> {
    let mut features = Vec::new();
    if cfg!(feature = "default") {
        features.extend([
            "default",
            "decode",
            "entropy",
            "gpu",
            "ml",
            "multiline",
            "simd",
            "simdsieve",
        ]);
    }
    if cfg!(feature = "ci-lean") {
        features.extend([
            "ci-lean",
            "decode",
            "entropy",
            "ml",
            "multiline",
            "simd",
            "simdsieve",
        ]);
    }
    if cfg!(feature = "ci") {
        features.extend(["decode", "entropy", "ml", "multiline"]);
    }
    if cfg!(feature = "portable") || cfg!(feature = "full") {
        features.extend(["decode", "entropy", "ml", "multiline"]);
    }
    if cfg!(feature = "gpu") {
        features.extend(["gpu", "simd"]);
    }
    if cfg!(feature = "simd") {
        features.push("simd");
    }
    if cfg!(feature = "cuda") {
        features.extend(["cuda", "gpu", "simd"]);
    }
    normalize_feature_list(features)
}

fn current_sources_dependency_features() -> Vec<String> {
    let mut features = Vec::new();
    macro_rules! push_feature {
        ($cli:literal, $source:literal) => {
            if cfg!(feature = $cli) {
                features.push($source);
            }
        };
    }

    push_feature!("binary", "binary");
    push_feature!("azure", "azure");
    push_feature!("docker", "docker");
    push_feature!("gcs", "gcs");
    push_feature!("github", "github");
    push_feature!("git", "git");
    push_feature!("s3", "s3");
    push_feature!("web", "web");
    normalize_feature_list(features)
}

fn current_verifier_dependency_features() -> Vec<String> {
    let mut features = Vec::new();
    if cfg!(feature = "verify") || cfg!(feature = "web") {
        features.push("live");
    }
    normalize_feature_list(features)
}

fn normalize_feature_list(features: Vec<&'static str>) -> Vec<String> {
    let mut features: Vec<String> = features.into_iter().map(str::to_string).collect();
    features.sort_unstable();
    features.dedup();
    features
}

fn describe_feature_list(features: &[String]) -> String {
    if features.is_empty() {
        "none".to_string()
    } else {
        features.join(",")
    }
}

pub(super) fn load_autoroute_cache(
    path: &std::path::Path,
    detector_digest: u64,
    rules_digest: &str,
    config_digest: u64,
    host_profile: &AutorouteHostProfile,
) -> Result<HashMap<WorkloadKey, AutorouteDecision>, Box<dyn std::error::Error + Send + Sync>> {
    let data = std::fs::read(path)?;
    let cache: AutorouteCache = serde_json::from_slice(&data)?;
    if cache.version != AUTOROUTE_CACHE_VERSION {
        return Err("unsupported autoroute cache version".into());
    }
    host_profile.require_exact_identity()?;
    if cache.binary_version != env!("CARGO_PKG_VERSION")
        || cache.git_hash != keyhog_core::git_hash()
    {
        return Err("binary identity mismatch; cache is for a different keyhog build".into());
    }
    let current_build_features = AutorouteBuildFeatures::current();
    if cache.build_features != current_build_features {
        return Err(format!(
            "build feature set mismatch; cache is for a different keyhog feature set \
             (cache cli features: {}; current cli features: {})",
            cache.build_features.describe(),
            current_build_features.describe()
        )
        .into());
    }
    if cache.detector_digest != detector_digest {
        return Err("detector digest mismatch; cache is for a different corpus".into());
    }
    if cache.rules_digest != rules_digest {
        return Err("rules digest mismatch; cache is for a different detector rule set".into());
    }
    if cache.config_digest != config_digest {
        return Err(
            "scan config digest mismatch; cache is for a different resolved scan config".into(),
        );
    }
    if &cache.host != host_profile {
        return Err("host profile mismatch; cache is for different hardware".into());
    }
    let mut out = HashMap::with_capacity(cache.decisions.len());
    for (key, decision) in cache.decisions {
        validate_decision_calibration_evidence(&decision)?;
        let Some(selected_backend) = decision.backend() else {
            return Err(format!(
                "cache contains unsupported backend decision {:?}",
                decision.backend
            )
            .into());
        };
        if decision.trials < AUTOROUTE_CALIBRATION_TRIALS {
            return Err("cache was produced with insufficient calibration trials".into());
        }
        if decision.calibrated_at_unix_ms == 0 {
            return Err("cache decision is missing a calibration timestamp".into());
        }
        if !decision
            .simd_timing
            .is_valid_for_trials(AUTOROUTE_CALIBRATION_TRIALS)
            || decision.simd_ms != decision.simd_timing.best_ms()
        {
            return Err("cache decision has invalid SIMD timing evidence".into());
        }
        if let Some(cpu_timing) = decision.cpu_timing.as_ref() {
            if !cpu_timing.is_valid_for_trials(AUTOROUTE_CALIBRATION_TRIALS)
                || decision.cpu_ms != Some(cpu_timing.best_ms())
            {
                return Err("cache decision has invalid CPU timing evidence".into());
            }
        }
        if let Some(gpu_timing) = decision.gpu_timing.as_ref() {
            if !gpu_timing.is_valid_for_trials(AUTOROUTE_CALIBRATION_TRIALS)
                || decision.gpu_ms != Some(gpu_timing.best_ms())
            {
                return Err("cache decision has invalid GPU timing evidence".into());
            }
        }
        validate_gpu_cold_warm_cache_evidence(&decision)?;
        let Some(selected_timing) = decision.timing_for_backend(selected_backend) else {
            return Err("selected backend is missing timing evidence".into());
        };
        if !selected_timing.is_valid_for_trials(AUTOROUTE_CALIBRATION_TRIALS) {
            return Err("selected backend timing evidence is invalid".into());
        }
        let candidates = decision.route_candidates();
        let Some((fastest_backend, _)) = candidates.iter().min_by_key(|(_, ns)| *ns).copied()
        else {
            return Err("cache decision has no route timing evidence".into());
        };
        if fastest_backend != selected_backend {
            return Err("selected backend is not the fastest persisted timing evidence".into());
        }
        let expected_margin = selected_backend_margin_ns(selected_backend, &candidates);
        if decision.selected_margin_ns != expected_margin {
            return Err("cache decision has invalid selected backend margin".into());
        }
        out.insert(key, decision);
    }
    Ok(out)
}

fn validate_decision_calibration_evidence(
    decision: &AutorouteDecision,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if decision.sample_chunks == 0 || decision.sample_bytes == 0 {
        return Err("cache decision is missing calibration sample evidence".into());
    }
    if decision.correctness_digest == 0 {
        return Err("cache decision is missing correctness digest".into());
    }
    Ok(())
}

fn validate_gpu_cold_warm_cache_evidence(
    decision: &AutorouteDecision,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match decision.gpu_timing.as_ref() {
        Some(gpu_timing) => {
            let Some((cold_ns, warm_timing, route_ns)) = gpu_cold_warm_route_evidence(gpu_timing)
            else {
                return Err("cache decision has invalid GPU cold/warm timing evidence".into());
            };
            if decision.gpu_cold_ns != Some(cold_ns)
                || decision.gpu_warm_ms != Some(warm_timing.best_ms())
                || decision.gpu_warm_timing.as_ref() != Some(&warm_timing)
                || decision.gpu_route_ns != Some(route_ns)
            {
                return Err("cache decision has mismatched GPU cold/warm route evidence".into());
            }
        }
        None => {
            if decision.gpu_cold_ns.is_some()
                || decision.gpu_warm_ms.is_some()
                || decision.gpu_warm_timing.is_some()
                || decision.gpu_route_ns.is_some()
            {
                return Err("cache decision has GPU cold/warm evidence without GPU timing".into());
            }
        }
    }
    Ok(())
}

pub(super) fn save_autoroute_cache(
    path: &std::path::Path,
    detector_digest: u64,
    rules_digest: &str,
    config_digest: u64,
    host_profile: &AutorouteHostProfile,
    decisions: &HashMap<WorkloadKey, AutorouteDecision>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    host_profile.require_exact_identity()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let cache = AutorouteCache {
        version: AUTOROUTE_CACHE_VERSION,
        binary_version: env!("CARGO_PKG_VERSION").to_string(),
        git_hash: keyhog_core::git_hash().to_string(),
        build_features: AutorouteBuildFeatures::current(),
        detector_digest,
        rules_digest: rules_digest.to_string(),
        config_digest,
        host: host_profile.clone(),
        decisions: decisions
            .iter()
            .map(|(&key, decision)| (key, decision.clone()))
            .collect(),
    };
    let serialized = serde_json::to_vec_pretty(&cache)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new(".")); // LAW10: parentless cache paths preserve the exact target in '.', recall-safe.
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(&serialized)?;
    tmp.flush()?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}
