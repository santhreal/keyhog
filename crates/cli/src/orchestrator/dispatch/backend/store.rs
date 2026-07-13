//! Persistent autoroute calibration cache schema and validation.

#[cfg(test)]
use keyhog_scanner::hw_probe::ScanBackend;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;

use super::evidence::{gpu_cold_warm_route_evidence, AutorouteDecision};
use super::host::AutorouteHostProfile;
use super::workload::WorkloadKey;
use super::AUTOROUTE_CACHE_VERSION;
use super::AUTOROUTE_CALIBRATION_TRIALS;

pub(super) const AUTOROUTE_CACHE_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Minimal front-matter view used to check the schema `version` BEFORE
/// deserializing the full payload. A version bump rides along with a structural
/// schema change, so deserializing an outdated cache straight into
/// `AutorouteCache` fails with an opaque serde error (e.g. "missing field …")
/// and the version gate would never run. Reading only the version first lets an
/// incompatible cache be rejected with a clear, actionable message instead.
/// `#[serde(default)]` maps a pre-versioning cache (no `version` field) to 0,
/// which is likewise treated as incompatible.
#[derive(Deserialize)]
struct AutorouteCacheVersionEnvelope {
    #[serde(default)]
    version: u32,
}

/// On-disk autoroute calibration cache.
///
/// The shared identity fields (binary, git hash, build features, detector
/// corpus, rule set, host) are invariant across every scan-policy preset on the
/// same binary+host, so they live ONCE at the top. A change to any of them
/// invalidates the whole file. Per-resolved-config routing decisions live under
/// `configs`, keyed by `config_digest`, so the default scan policy and every
/// preset (`--fast`/`--deep`/`--precision`/a `.keyhog.toml`/`--batch-pipeline
/// --autoroute-gpu`) coexist in one file instead of overwriting each other.
/// `save_autoroute_cache` merges: it upserts the calibrated config's entry and
/// preserves the rest, so sequential install-time probes (separate processes,
/// one workload bucket each) accumulate instead of clobbering.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct AutorouteCache {
    pub(super) version: u32,
    pub(super) binary_version: String,
    pub(super) git_hash: String,
    #[serde(default)]
    pub(super) build_features: AutorouteBuildFeatures,
    pub(super) detector_digest: u64,
    pub(super) rules_digest: String,
    pub(super) host: AutorouteHostProfile,
    pub(super) configs: Vec<AutorouteConfigDecisions>,
}

/// Routing decisions for a single resolved scan-config digest. One entry per
/// distinct `autoroute_config_digest`, each holding the per-workload-bucket
/// fastest-correct backend decisions calibrated for that config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct AutorouteConfigDecisions {
    pub(super) config_digest: u64,
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
    pub(super) fn current() -> Self {
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
    push_feature!("docker");
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
    if keyhog_scanner::hw_probe::gpu_backend_compiled() {
        features.extend(["gpu", "simd"]);
    }
    if keyhog_scanner::hw_probe::simd_backend_compiled() {
        features.push("simd");
    }
    // CUDA and WGPU are runtime drivers inside the single `gpu` feature, so one
    // feature identity covers both without artifact- or driver-specific aliases.
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

/// How a raw cache read failed to parse into a trusted [`AutorouteCache`].
/// The ONE parse pipeline (envelope version gate BEFORE the full payload
/// deserialize) shared by the reader, the inspection view, and the merge-save
/// three call sites, three POLICIES, one parse.
enum CacheParseError {
    /// The bytes are not JSON with the version envelope shape at all.
    NotJson(serde_json::Error),
    /// The envelope parsed but the schema version does not match this build.
    /// A version bump accompanies a structural change, so parsing an outdated
    /// cache directly into `AutorouteCache` would fail with an opaque serde
    /// error; gating on the version FIRST yields a clear, actionable message.
    Version { found: u32 },
    /// The version matched but the full payload failed to deserialize.
    Payload(serde_json::Error),
}

fn parse_autoroute_cache(data: &[u8]) -> Result<AutorouteCache, CacheParseError> {
    let envelope: AutorouteCacheVersionEnvelope =
        serde_json::from_slice(data).map_err(CacheParseError::NotJson)?;
    if envelope.version != AUTOROUTE_CACHE_VERSION {
        return Err(CacheParseError::Version {
            found: envelope.version,
        });
    }
    serde_json::from_slice(data).map_err(CacheParseError::Payload)
}

pub(super) fn load_autoroute_cache(
    path: &std::path::Path,
    detector_digest: u64,
    rules_digest: &str,
    config_digest: u64,
    host_profile: &AutorouteHostProfile,
) -> Result<HashMap<WorkloadKey, AutorouteDecision>, Box<dyn std::error::Error + Send + Sync>> {
    let data = read_autoroute_cache_file(path)?;
    let cache = match parse_autoroute_cache(&data) {
        Ok(cache) => cache,
        Err(CacheParseError::NotJson(e)) => {
            return Err(format!("autoroute cache is not valid cache JSON: {e}").into());
        }
        Err(CacheParseError::Version { found }) => {
            return Err(format!(
                "unsupported autoroute cache version {found} (this build expects {}); \
                 re-run calibration to regenerate it",
                AUTOROUTE_CACHE_VERSION
            )
            .into());
        }
        Err(CacheParseError::Payload(e)) => return Err(e.into()),
    };
    host_profile.require_exact_identity()?;
    validate_cache_shared_identity(&cache, detector_digest, rules_digest, host_profile)?;
    // Multi-config cache: pick the decisions calibrated for THIS resolved scan
    // config. A missing entry fails closed exactly like the old single-config
    // digest mismatch, the auto scan refuses to substitute a backend, but
    // other presets calibrated on the same binary/host stay usable.
    let Some(config) = cache
        .configs
        .iter()
        .find(|c| c.config_digest == config_digest)
    else {
        return Err(format!(
            "scan config digest mismatch; cache is for a different resolved scan config \
             (this binary/host/corpus has {} calibrated config(s), none matching config \
             digest {config_digest:016x}); calibrate this scan config",
            cache.configs.len()
        )
        .into());
    };
    if config.decisions.is_empty() {
        return Err("autoroute cache contains no workload decisions".into());
    }
    let mut out = HashMap::with_capacity(config.decisions.len());
    for (key, decision) in &config.decisions {
        validate_decision_route_evidence(decision)?;
        if out.contains_key(key) {
            return Err(format!(
                "cache contains duplicate autoroute workload decision for {key:?}"
            )
            .into());
        }
        out.insert(*key, decision.clone());
    }
    Ok(out)
}

/// Validate the binary/host/corpus/rule-set identity shared by every config in a
/// cache file. Reused by both the reader and the merge-aware writer so a single
/// rule decides when an on-disk cache is for *this* exact build and host.
fn validate_cache_shared_identity(
    cache: &AutorouteCache,
    detector_digest: u64,
    rules_digest: &str,
    host_profile: &AutorouteHostProfile,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
    if &cache.host != host_profile {
        return Err("host profile mismatch; cache is for different hardware".into());
    }
    Ok(())
}

fn read_autoroute_cache_file(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len > AUTOROUTE_CACHE_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "autoroute cache exceeds {} byte cap; delete the cache file and rerun install calibration",
                AUTOROUTE_CACHE_FILE_BYTES
            ),
        ));
    }

    let mut data = Vec::with_capacity(len as usize);
    file.take(AUTOROUTE_CACHE_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut data)?;
    if data.len() as u64 > AUTOROUTE_CACHE_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "autoroute cache grew past {} byte cap while reading; retry after the file is stable",
                AUTOROUTE_CACHE_FILE_BYTES
            ),
        ));
    }
    Ok(data)
}

// --- Exact bucket resolution (test facade) ----------------------------------
//
// Autoroute evidence is scoped to the complete workload key. Neighbouring size
// buckets do not prove which backend is fastest for this one, even when their
// CPU decisions agree, so a miss must remain unresolved.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub(super) enum BucketResolution {
    /// The exact workload bucket was calibrated.
    Exact(ScanBackend),
    /// No exact decision exists (the caller must fail closed).
    Unresolved,
}

#[cfg(test)]
pub(super) fn resolve_bucket(
    decisions: &HashMap<WorkloadKey, AutorouteDecision>,
    key: &WorkloadKey,
) -> BucketResolution {
    if let Some(backend) = decisions.get(key).and_then(AutorouteDecision::backend) {
        return BucketResolution::Exact(backend);
    }
    BucketResolution::Unresolved
}

// --- Read-only inspection ---------------------------------------------------
//
// `keyhog backend --autoroute` renders the persisted cache so an operator who hit
// a fail-closed "no decision for workload bucket ..." error can see exactly which
// resolved configs and workload buckets ARE calibrated, and whether the cache is
// stale for this build. This path deliberately does NOT validate host/detector/
// rules identity, a real scan does that and surfaces a mismatch loudly. It
// deserializes and DISPLAYS, additionally flagging the cheap build-identity drift
// (binary version / git hash / feature set) that a post-upgrade stale cache shows.

/// Operator-facing view of the persisted autoroute cache (one JSON object).
#[derive(Debug, Default, Serialize)]
pub(crate) struct AutorouteCacheInspection {
    pub(crate) path: Option<String>,
    pub(crate) present: bool,
    /// Set when the cache exists but is unusable (disabled / unreadable / wrong
    /// schema version / corrupt). A real scan fails closed on the same input.
    pub(crate) error: Option<String>,
    pub(crate) version: Option<u32>,
    pub(crate) binary_version: Option<String>,
    pub(crate) git_hash: Option<String>,
    pub(crate) identity_matches_build: Option<bool>,
    pub(crate) identity_mismatch_reason: Option<String>,
    pub(crate) host: Option<String>,
    pub(crate) detector_digest: Option<String>,
    pub(crate) rules_digest: Option<String>,
    pub(crate) configs: Vec<AutorouteConfigInspection>,
}

/// One resolved scan-config digest's calibrated workload decisions.
#[derive(Debug, Serialize)]
pub(crate) struct AutorouteConfigInspection {
    pub(crate) config_digest: String,
    pub(crate) decision_count: usize,
    pub(crate) decisions: Vec<AutorouteDecisionInspection>,
}

/// One calibrated (workload bucket -> fastest-correct backend) decision, rendered
/// for `keyhog backend inspect`. Every numeric field here is DERIVED from the
/// persisted timing evidence on the source `AutorouteDecision` (which stores no
/// denormalized copies), this human-readable projection is where those derived
/// ms / margin values surface.
#[derive(Debug, Serialize)]
pub(crate) struct AutorouteDecisionInspection {
    pub(crate) workload: String,
    pub(crate) backend: String,
    pub(crate) sample_bytes: u64,
    pub(crate) sample_chunks: usize,
    pub(crate) simd_ms: u128,
    pub(crate) cpu_ms: Option<u128>,
    pub(crate) gpu_ms: Option<u128>,
    /// The ns margin by which `backend` beat the next-fastest candidate route,
    /// derived from the timing evidence. `None` when no competing route exists.
    pub(crate) selected_margin_ns: Option<u128>,
}

pub(crate) fn inspect_autoroute_cache(path: Option<&std::path::Path>) -> AutorouteCacheInspection {
    let mut out = AutorouteCacheInspection {
        path: path.map(|p| p.display().to_string()),
        ..AutorouteCacheInspection::default()
    };

    let Some(path) = path else {
        out.error = Some(
            "autoroute cache is disabled (--autoroute-cache off / [system].autoroute_cache = \
             off); auto scans require an explicit --backend in this configuration"
                .to_string(),
        );
        return out;
    };

    if !path.exists() {
        // Not an error: simply not calibrated yet.
        return out;
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
        Err(CacheParseError::NotJson(error)) => {
            out.error = Some(format!("autoroute cache is not valid cache JSON: {error}"));
            return out;
        }
        Err(CacheParseError::Version { found }) => {
            out.version = Some(found);
            out.error = Some(format!(
                "cache schema version {found} is incompatible with this build (expects {}); \
                 re-run calibration to regenerate it",
                AUTOROUTE_CACHE_VERSION
            ));
            return out;
        }
        Err(CacheParseError::Payload(error)) => {
            // The envelope parsed and matched this build's version.
            out.version = Some(AUTOROUTE_CACHE_VERSION);
            out.error = Some(format!(
                "autoroute cache payload did not deserialize: {error}"
            ));
            return out;
        }
    };
    out.version = Some(cache.version);

    out.binary_version = Some(cache.binary_version.clone());
    out.git_hash = Some(cache.git_hash.clone());
    out.detector_digest = Some(format!("{:016x}", cache.detector_digest));
    out.rules_digest = Some(cache.rules_digest.clone());
    out.host = Some(render_host_profile(&cache.host));

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

    for config in &cache.configs {
        let mut decisions: Vec<AutorouteDecisionInspection> = config
            .decisions
            .iter()
            .map(|(key, decision)| AutorouteDecisionInspection {
                workload: render_workload_key(key),
                backend: decision.backend.clone(),
                sample_bytes: decision.sample_bytes,
                sample_chunks: decision.sample_chunks,
                // Human-readable ms + margin live in the inspection view only,
                // DERIVED from the persisted timing evidence (not stored on the
                // decision (the ONE-PLACE invariant this schema enforces)).
                simd_ms: decision.simd_ms(),
                cpu_ms: decision.cpu_ms(),
                gpu_ms: decision.gpu_ms(),
                selected_margin_ns: decision.selected_margin_ns(),
            })
            .collect();
        decisions.sort_by(|a, b| a.workload.cmp(&b.workload));
        out.configs.push(AutorouteConfigInspection {
            config_digest: format!("{:016x}", config.config_digest),
            decision_count: config.decisions.len(),
            decisions,
        });
    }
    out.configs
        .sort_by(|a, b| a.config_digest.cmp(&b.config_digest));
    out
}

/// Render a workload bucket in the same field layout as the fail-closed
/// "no persisted decision for workload bucket ..." error, so an operator can
/// match the bucket they were refused against the buckets that ARE calibrated.
/// Shared by cache inspection and missing-decision diagnostics, one bucket
/// rendering, never a drifting second copy.
pub(super) fn render_workload_key(key: &WorkloadKey) -> String {
    format!(
        "bytes_log2={} chunks_log2={} max_file_log2={} patterns_log2={} \
         decode_density_log2={} source_hash={:016x}",
        key.bytes_bucket,
        key.chunks_bucket,
        key.max_file_bucket,
        key.pattern_bucket,
        key.decode_density_bucket,
        key.source_class_hash
    )
}

fn render_host_profile(host: &AutorouteHostProfile) -> String {
    let simd = if host.has_avx512 {
        "AVX-512"
    } else if host.has_avx2 {
        "AVX2"
    } else if host.has_neon {
        "NEON"
    } else {
        "scalar"
    };
    format!(
        "{}/{} {} | {}p/{}l cores | {} | hyperscan={} | gpu={}",
        host.os,
        host.arch,
        host.cpu_model.as_deref().unwrap_or("unknown-cpu"), // LAW10: display-only host label; recall-safe
        host.physical_cores,
        host.logical_cores,
        simd,
        if host.hyperscan_available {
            "yes"
        } else {
            "no"
        },
        host.gpu_name.as_deref().unwrap_or("none"), // LAW10: display-only host label; recall-safe
    )
}

fn validate_decision_route_evidence(
    decision: &AutorouteDecision,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    validate_decision_calibration_evidence(decision)?;
    let Some(selected_backend) = decision.backend() else {
        return Err(format!(
            "cache contains unsupported backend decision {:?}",
            decision.backend
        )
        .into());
    };
    if decision.backend != selected_backend.label() {
        return Err(format!(
            "cache contains non-canonical backend label {:?}; expected {:?}",
            decision.backend,
            selected_backend.label()
        )
        .into());
    }
    if decision.trials < AUTOROUTE_CALIBRATION_TRIALS {
        return Err("cache was produced with insufficient calibration trials".into());
    }
    if decision.calibrated_at_unix_ms == 0 {
        return Err("cache decision is missing a calibration timestamp".into());
    }
    // Timing-evidence VALIDITY (enough trials, well-formed CI) is a real invariant
    // and stays. The former `X_ms != X_timing.best_ms()` cross-checks are GONE:
    // per-backend ms is now DERIVED from the timing on load (`decision.simd_ms()`
    // …), so it cannot disagree with its own source, there is nothing to
    // cross-check. Same for the selected-margin: `selected_margin_ns()` is derived
    // from the timing + resolved backend, so the former stored-vs-recomputed check
    // is structurally impossible to fail and has been removed (ONE-PLACE).
    if !decision
        .simd_timing
        .is_valid_for_trials(AUTOROUTE_CALIBRATION_TRIALS)
    {
        return Err("cache decision has invalid SIMD timing evidence".into());
    }
    if let Some(cpu_timing) = decision.cpu_timing.as_ref() {
        if !cpu_timing.is_valid_for_trials(AUTOROUTE_CALIBRATION_TRIALS) {
            return Err("cache decision has invalid CPU timing evidence".into());
        }
    }
    if let Some(gpu_timing) = decision.gpu_timing.as_ref() {
        if !gpu_timing.is_valid_for_trials(AUTOROUTE_CALIBRATION_TRIALS) {
            return Err("cache decision has invalid GPU timing evidence".into());
        }
    }
    validate_gpu_cold_warm_cache_evidence(decision)?;
    let Some(selected_timing) = decision.timing_for_backend(selected_backend) else {
        return Err("selected backend is missing timing evidence".into());
    };
    if !selected_timing.is_valid_for_trials(AUTOROUTE_CALIBRATION_TRIALS) {
        return Err("selected backend timing evidence is invalid".into());
    }
    // Soundness gate. The persisted backend must equal the deterministic
    // resolution of the persisted timing evidence (`resolved_routing_backend`)
    // the SAME confidence-interval logic calibration used to select it, so a
    // tampered or non-deterministic cache that names any other backend is
    // rejected. Routing is decided from 95% CIs, never a single `best_ns` trial.
    let Some(resolved) = decision.resolved_routing_backend() else {
        return Err("cache decision has no route timing evidence".into());
    };
    // Compare by execution class so a programmatic compatibility variant can
    // never behave like a distinct measured route. Persisted decisions are
    // canonical already; this also keeps in-memory validation coherent.
    if selected_backend != resolved {
        if decision.has_separated_fastest_route() {
            // One route is provably fastest and it is not the selected one.
            return Err("selected backend is not the fastest persisted timing evidence".into());
        }
        // Two or more routes tie within measurement precision; the selected one
        // is not the deterministic lowest-overhead tie-break among them.
        return Err(
            "selected backend is not the deterministic tie-break among statistically tied routes"
                .into(),
        );
    }
    Ok(())
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
    // A persisted GPU timing set must be structurally able to produce cold/warm
    // route evidence (enough warm trials); otherwise it could not route and the
    // cache is corrupt, fail closed (Law 10), never silently drop GPU. The
    // cold/warm/route VALUES are derived on demand from this same evidence
    // (`AutorouteDecision::gpu_cold_warm_route`), so there is no stored copy to
    // cross-check, only this derivability invariant remains. No GPU timing means
    // nothing to derive: trivially valid.
    if let Some(gpu_timing) = decision.gpu_timing.as_ref() {
        if gpu_cold_warm_route_evidence(gpu_timing).is_none() {
            return Err("cache decision has invalid GPU cold/warm timing evidence".into());
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
    if decisions.is_empty() {
        return Err("autoroute cache contains no workload decisions".into());
    }
    for decision in decisions.values() {
        validate_decision_route_evidence(decision)?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Hold one cross-process lock across the entire read/merge/write cycle.
    // Atomic rename prevents torn files but cannot prevent two calibration
    // processes from reading the same base and losing one another's decisions.
    let _write_lock = keyhog_core::StateFileWriteLock::acquire(path)?;

    // Merge, do not overwrite. Preserve every other resolved-config entry from a
    // compatible on-disk cache so presets accumulate, and UNION this config's
    // freshly measured buckets over any it already had so sequential install
    // probes (separate processes, one bucket each) build up instead of each
    // clobbering the last. An incompatible/corrupt file is superseded wholesale
    // (loudly (see `read_mergeable_configs`)).
    let mut configs = read_mergeable_configs(path, detector_digest, rules_digest, host_profile);
    let mut merged: std::collections::BTreeMap<WorkloadKey, AutorouteDecision> =
        std::collections::BTreeMap::new();
    if let Some(prior) = configs.iter().find(|c| c.config_digest == config_digest) {
        for (key, decision) in &prior.decisions {
            merged.insert(*key, decision.clone());
        }
    }
    for (&key, decision) in decisions {
        merged.insert(key, decision.clone());
    }
    configs.retain(|c| c.config_digest != config_digest);
    configs.push(AutorouteConfigDecisions {
        config_digest,
        // BTreeMap iteration is WorkloadKey-sorted, so the persisted decision
        // order is deterministic regardless of HashMap iteration order.
        decisions: merged.into_iter().collect(),
    });
    configs.sort_by_key(|c| c.config_digest);

    let cache = AutorouteCache {
        version: AUTOROUTE_CACHE_VERSION,
        binary_version: env!("CARGO_PKG_VERSION").to_string(),
        git_hash: keyhog_core::git_hash().to_string(),
        build_features: AutorouteBuildFeatures::current(),
        detector_digest,
        rules_digest: rules_digest.to_string(),
        host: host_profile.clone(),
        configs,
    };
    let serialized = serde_json::to_vec_pretty(&cache)?;
    crate::atomic_file::write_bytes(path, &serialized)?;
    Ok(())
}

/// Read the per-config decisions from an existing cache that is STILL valid for
/// this exact binary/host/corpus/rule-set, so a merge-save can preserve other
/// presets. Returns an empty vec when there is nothing safe to preserve, file
/// absent (expected), an older schema or a different build/host/corpus (an
/// expected post-rebuild supersede, logged at info), or a present-but-corrupt
/// file (logged loudly per Law 10 before replacement). It never fails the save;
/// a fresh single-config cache is always derivable from the new decisions.
fn read_mergeable_configs(
    path: &std::path::Path,
    detector_digest: u64,
    rules_digest: &str,
    host_profile: &AutorouteHostProfile,
) -> Vec<AutorouteConfigDecisions> {
    if !path.exists() {
        return Vec::new();
    }
    let data = match read_autoroute_cache_file(path) {
        Ok(data) => data,
        Err(error) => {
            tracing::warn!(
                target: "keyhog::routing",
                path = %path.display(),
                %error,
                "existing autoroute cache is unreadable; replacing it with a fresh calibration (any other presets in it are lost)"
            );
            return Vec::new();
        }
    };
    let cache = match parse_autoroute_cache(&data) {
        Ok(cache) => cache,
        Err(CacheParseError::Version { found }) => {
            tracing::info!(
                target: "keyhog::routing",
                path = %path.display(),
                found_version = found,
                expected_version = AUTOROUTE_CACHE_VERSION,
                "existing autoroute cache is an older schema; superseding it with this build's calibration"
            );
            return Vec::new();
        }
        Err(CacheParseError::NotJson(error)) => {
            tracing::warn!(
                target: "keyhog::routing",
                path = %path.display(),
                %error,
                "existing autoroute cache is not valid cache JSON; replacing it with a fresh calibration"
            );
            return Vec::new();
        }
        Err(CacheParseError::Payload(error)) => {
            tracing::warn!(
                target: "keyhog::routing",
                path = %path.display(),
                %error,
                "existing autoroute cache failed to deserialize; replacing it with a fresh calibration"
            );
            return Vec::new();
        }
    };
    if let Err(error) =
        validate_cache_shared_identity(&cache, detector_digest, rules_digest, host_profile)
    {
        tracing::info!(
            target: "keyhog::routing",
            path = %path.display(),
            %error,
            "existing autoroute cache is for a different build/host/corpus; superseding it with this build's calibration"
        );
        return Vec::new();
    }
    cache.configs
}
