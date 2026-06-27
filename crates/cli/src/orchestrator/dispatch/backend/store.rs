//! Persistent autoroute calibration cache schema and validation.

use keyhog_scanner::hw_probe::ScanBackend;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;

use super::evidence::{
    gpu_cold_warm_route_evidence, selected_backend_margin_ns, AutorouteDecision,
};
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
    let data = read_autoroute_cache_file(path)?;
    // Gate on the schema version BEFORE the full deserialize. A version bump
    // accompanies a structural change, so parsing an outdated cache directly
    // into `AutorouteCache` fails with an opaque serde error and a version
    // check placed after it can never run. Reading only the version first
    // rejects an incompatible cache with a clear, actionable message.
    let envelope: AutorouteCacheVersionEnvelope = serde_json::from_slice(&data)
        .map_err(|e| format!("autoroute cache is not valid cache JSON: {e}"))?;
    if envelope.version != AUTOROUTE_CACHE_VERSION {
        return Err(format!(
            "unsupported autoroute cache version {} (this build expects {}); \
             re-run calibration to regenerate it",
            envelope.version, AUTOROUTE_CACHE_VERSION
        )
        .into());
    }
    let cache: AutorouteCache = serde_json::from_slice(&data)?;
    host_profile.require_exact_identity()?;
    validate_cache_shared_identity(&cache, detector_digest, rules_digest, host_profile)?;
    // Multi-config cache: pick the decisions calibrated for THIS resolved scan
    // config. A missing entry fails closed exactly like the old single-config
    // digest mismatch — the auto scan refuses to substitute a backend — but
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

// --- Bucket resolution (exact, else sound CPU-class interpolation) ----------
//
// A scan looks its workload bucket up in the calibrated decisions. An EXACT hit
// is a zero-cost table lookup. A miss historically failed closed (Law 10: never
// guess a backend). #34 adds ONE generalization that is not a guess: if the
// requested bucket lies strictly between two calibrated buckets that
//   (a) match it on every workload dimension EXCEPT one SIZE axis (bytes_bucket
//       or max_file_bucket), and
//   (b) BOTH resolved to the SAME CPU-class backend (SimdCpu / CpuFallback),
// then the choice is provably stable across that interval. CPU-class backends
// are exact-match — their findings are identical regardless of input size, so no
// GPU/MoE score divergence can flip recall across the span (cf. #18) — and the
// faster CPU backend is monotonic in size, so two agreeing endpoints bracket an
// interval that resolves to the same backend. GPU buckets NEVER interpolate
// (their correctness can vary with size). A non-bracketed or disagreeing miss
// stays Unresolved (fail closed). Every interpolation is surfaced LOUDLY by the
// caller (Law 10) — it is recall-safe and recorded, never a silent fallback.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BucketResolution {
    /// The exact workload bucket was calibrated.
    Exact(ScanBackend),
    /// Not directly calibrated, but bracketed by two calibrated CPU-class buckets
    /// that agree on the backend along one size axis — a sound interpolation.
    Interpolated {
        backend: ScanBackend,
        lo: WorkloadKey,
        hi: WorkloadKey,
    },
    /// Smaller than every calibrated bucket in its workload class along one size
    /// axis (e.g. `keyhog scan small.env`, below the ladder's smallest single-file
    /// probe). Resolved to setup-free [`ScanBackend::CpuFallback`]: an input too
    /// small to amortize any backend's fixed setup cannot be beaten by a backend
    /// with setup, and CpuFallback is the reference-correct backend, so this is a
    /// sound below-floor extrapolation, not a guess. `floor` is the smallest
    /// calibrated bucket in the class (proof the class itself is calibrated).
    ClampedBelowFloor {
        backend: ScanBackend,
        floor: WorkloadKey,
    },
    /// No sound resolution exists — the caller must fail closed.
    Unresolved,
}

pub(super) fn resolve_bucket(
    decisions: &HashMap<WorkloadKey, AutorouteDecision>,
    key: &WorkloadKey,
) -> BucketResolution {
    if let Some(backend) = decisions.get(key).and_then(AutorouteDecision::backend) {
        return BucketResolution::Exact(backend);
    }
    for axis in [BucketAxis::Bytes, BucketAxis::MaxFile] {
        if let Some(resolution) = interpolate_cpu_class(decisions, key, axis) {
            return resolution;
        }
    }
    // A single file BETWEEN two calibrated single-file rungs can't be bracketed by
    // the per-axis interpolation above (its two size axes move together), so try
    // the diagonal companion before the below-floor clamp — see
    // `interpolate_single_file_diagonal`.
    if let Some(resolution) = interpolate_single_file_diagonal(decisions, key) {
        return resolution;
    }
    // A query smaller than every calibrated bucket in its class has no lower
    // bracket to interpolate from (the common `keyhog scan small.env` case: a
    // single file below the ladder's smallest single-file probe). Clamp it to
    // setup-free CpuFallback — see `clamp_below_calibrated_floor`.
    clamp_below_calibrated_floor(decisions, key).unwrap_or(BucketResolution::Unresolved)
    // LAW10: fail_closed — no clamp evidence => Unresolved => caller exits 2, not a silent route
}

#[derive(Clone, Copy)]
enum BucketAxis {
    Bytes,
    MaxFile,
}

impl BucketAxis {
    fn value(self, key: &WorkloadKey) -> u8 {
        match self {
            BucketAxis::Bytes => key.bytes_bucket,
            BucketAxis::MaxFile => key.max_file_bucket,
        }
    }

    /// True when `other` matches `key` on EVERY workload dimension except this
    /// one size axis — the precondition for interpolating along it.
    fn matches_except_axis(self, key: &WorkloadKey, other: &WorkloadKey) -> bool {
        let bytes_ok = matches!(self, BucketAxis::Bytes) || other.bytes_bucket == key.bytes_bucket;
        let max_file_ok =
            matches!(self, BucketAxis::MaxFile) || other.max_file_bucket == key.max_file_bucket;
        bytes_ok
            && max_file_ok
            && other.chunks_bucket == key.chunks_bucket
            && other.pattern_bucket == key.pattern_bucket
            && other.decode_density_bucket == key.decode_density_bucket
            && other.source_class_hash == key.source_class_hash
    }
}

fn interpolate_cpu_class(
    decisions: &HashMap<WorkloadKey, AutorouteDecision>,
    key: &WorkloadKey,
    axis: BucketAxis,
) -> Option<BucketResolution> {
    let target = axis.value(key);
    let mut nearest_lo: Option<(u8, ScanBackend, WorkloadKey)> = None;
    let mut nearest_hi: Option<(u8, ScanBackend, WorkloadKey)> = None;

    for (candidate_key, decision) in decisions {
        if !axis.matches_except_axis(key, candidate_key) {
            continue;
        }
        let Some(backend) = decision.backend() else {
            continue;
        };
        // GPU correctness can vary with input size — never bracket across it.
        if super::is_gpu_backend(backend) {
            continue;
        }
        let value = axis.value(candidate_key);
        if value < target {
            let replace = match nearest_lo {
                Some((best, _, _)) => value > best,
                None => true,
            };
            if replace {
                nearest_lo = Some((value, backend, *candidate_key));
            }
        } else if value > target {
            let replace = match nearest_hi {
                Some((best, _, _)) => value < best,
                None => true,
            };
            if replace {
                nearest_hi = Some((value, backend, *candidate_key));
            }
        }
    }

    match (nearest_lo, nearest_hi) {
        (Some((_, lo_backend, lo_key)), Some((_, hi_backend, hi_key)))
            if lo_backend == hi_backend =>
        {
            Some(BucketResolution::Interpolated {
                backend: lo_backend,
                lo: lo_key,
                hi: hi_key,
            })
        }
        // Bracketing pair disagrees, or only one side exists -> not sound.
        _ => None,
    }
}

// Between-rung single-file interpolation (#46) — the diagonal companion to #34's
// per-axis interpolation, and the third sound generalization after the #44
// below-floor clamp.
//
// A SINGLE file's `bytes_bucket` and `max_file_bucket` are the SAME quantity (the
// one file's size) bucketed twice, so two different-sized single files differ on
// BOTH size axes at once. `interpolate_cpu_class` holds one axis fixed while
// varying the other, so it can never bracket them — the exact correlation that
// also forced the #44 clamp. The everyday `keyhog scan mid.env` whose size lands
// strictly between two calibrated single-file rungs (e.g. 16 KiB between the
// 4 KiB and 64 KiB probes) therefore used to fail closed (exit 2).
//
// This brackets along the size DIAGONAL instead: when the query is itself a
// single-file point (`bytes_bucket == max_file_bucket`) of a calibrated class,
// sitting strictly between two calibrated single-file rungs that AGREE on a CPU
// backend, that backend is the sound choice between them. A single file's size is
// ONE degree of freedom, so this is exactly #34's agreeing-CPU-bracket
// monotonicity applied to the true single-file size axis: under the linear
// setup+throughput cost model, a backend that is fastest-correct at a smaller AND
// a larger single-file size is fastest-correct in between, and CPU backends are
// reference-correct at every size (recall preserved). GPU is never bracketed (its
// correctness varies with size). Like every generalized resolution it is surfaced
// LOUDLY by the caller as an `Interpolated` route, not a silent default.
fn interpolate_single_file_diagonal(
    decisions: &HashMap<WorkloadKey, AutorouteDecision>,
    key: &WorkloadKey,
) -> Option<BucketResolution> {
    // Only a single-file query lives on the diagonal. A multi-file workload's two
    // size axes are independent and is owned by the per-axis interpolation above.
    if key.bytes_bucket != key.max_file_bucket {
        return None;
    }
    let target = key.bytes_bucket;
    let mut nearest_lo: Option<(u8, ScanBackend, WorkloadKey)> = None;
    let mut nearest_hi: Option<(u8, ScanBackend, WorkloadKey)> = None;

    for (candidate_key, decision) in decisions {
        // The candidate must itself be a single-file point of the SAME non-size
        // class (chunks/pattern/density/source all equal). Requiring chunks equal
        // keeps the bracket within one chunk regime — a rung across a chunk-count
        // change is not a sound single-file neighbour and is left fail-closed.
        if candidate_key.bytes_bucket != candidate_key.max_file_bucket
            || candidate_key.chunks_bucket != key.chunks_bucket
            || candidate_key.pattern_bucket != key.pattern_bucket
            || candidate_key.decode_density_bucket != key.decode_density_bucket
            || candidate_key.source_class_hash != key.source_class_hash
        {
            continue;
        }
        let Some(backend) = decision.backend() else {
            continue;
        };
        // GPU correctness can vary with input size — never bracket across it.
        if super::is_gpu_backend(backend) {
            continue;
        }
        let value = candidate_key.bytes_bucket;
        if value < target {
            let replace = match nearest_lo {
                Some((best, _, _)) => value > best,
                None => true,
            };
            if replace {
                nearest_lo = Some((value, backend, *candidate_key));
            }
        } else if value > target {
            let replace = match nearest_hi {
                Some((best, _, _)) => value < best,
                None => true,
            };
            if replace {
                nearest_hi = Some((value, backend, *candidate_key));
            }
        }
    }

    match (nearest_lo, nearest_hi) {
        (Some((_, lo_backend, lo_key)), Some((_, hi_backend, hi_key)))
            if lo_backend == hi_backend =>
        {
            Some(BucketResolution::Interpolated {
                backend: lo_backend,
                lo: lo_key,
                hi: hi_key,
            })
        }
        // Bracketing pair disagrees, only one side exists, or the query is above
        // every rung (a between-floor clamp owns below; above stays fail-closed).
        _ => None,
    }
}

// Below-floor extrapolation (the second sound generalization, after #34's
// interpolation). A single small file — `keyhog scan small.env`, by far the most
// common scan — lands in a size bucket BELOW the ladder's smallest single-file
// probe (4 KiB) and used to fail closed (exit 2) on an everyday input.
//
// Why interpolation can't reach it: for a SINGLE file, bytes_bucket and
// max_file_bucket are perfectly correlated (both track the one file's size), so
// two different-sized single files differ on BOTH size axes at once.
// `interpolate_cpu_class` varies ONE axis while holding the other fixed, so it
// never brackets them. This clamp instead works on the size FRONTIER: both axes
// together.
//
// The resolution is sound, not a guess: when the query is STRICTLY smaller than
// every calibrated bucket in its class on BOTH size axes, it is smaller than
// anything measured, so no backend's FIXED setup (Hyperscan scratch/database
// alloc, GPU kernel launch) can be amortized and the setup-free CpuFallback is
// the lowest-overhead correct choice — a backend that paid setup to win at a
// LARGER size only loses ground as the input shrinks. CpuFallback is also the
// reference-correct backend (identical findings at any size), so recall is
// preserved. GPU is never the anchor (its correctness varies with size).
//
// Strict on BOTH axes is deliberate: a query equal to a calibrated bucket on one
// axis (same total bytes, fewer/larger files) is NOT unambiguously smaller, so it
// stays fail-closed here rather than risk a slower route. A query BETWEEN two
// calibrated single-file rungs is not a floor either — it is owned by the
// diagonal interpolation (`interpolate_single_file_diagonal`, #46) which runs
// before this clamp; by the time the clamp is reached, the query is genuinely
// below the whole single-file frontier. The class must have at least one
// calibrated CPU bucket (proof the class itself was calibrated); a wholly
// uncalibrated class still fails closed. Surfaced LOUDLY by the caller, like
// interpolation.
fn clamp_below_calibrated_floor(
    decisions: &HashMap<WorkloadKey, AutorouteDecision>,
    key: &WorkloadKey,
) -> Option<BucketResolution> {
    let mut floor: Option<WorkloadKey> = None;

    for (candidate_key, decision) in decisions {
        // Same workload class on every NON-size dimension.
        if candidate_key.chunks_bucket != key.chunks_bucket
            || candidate_key.pattern_bucket != key.pattern_bucket
            || candidate_key.decode_density_bucket != key.decode_density_bucket
            || candidate_key.source_class_hash != key.source_class_hash
        {
            continue;
        }
        let Some(backend) = decision.backend() else {
            continue;
        };
        // GPU correctness can vary with input size — never anchor a clamp to it.
        if super::is_gpu_backend(backend) {
            continue;
        }
        // Any calibrated CPU bucket that is NOT strictly larger than the query on
        // BOTH size axes means the query is not below this class's frontier — an
        // exact hit, an interpolation, or a between-bucket miss owns it, never a
        // clamp. Bail rather than clamp over real (or equal) bracketing evidence.
        if candidate_key.bytes_bucket <= key.bytes_bucket
            || candidate_key.max_file_bucket <= key.max_file_bucket
        {
            return None;
        }
        // Strictly larger on both axes: a genuine floor. Keep the smallest one.
        let smaller = match floor {
            Some(best) => {
                (candidate_key.bytes_bucket, candidate_key.max_file_bucket)
                    < (best.bytes_bucket, best.max_file_bucket)
            }
            None => true,
        };
        if smaller {
            floor = Some(*candidate_key);
        }
    }

    floor.map(|floor_key| BucketResolution::ClampedBelowFloor {
        backend: ScanBackend::CpuFallback,
        floor: floor_key,
    })
}

// --- Read-only inspection ---------------------------------------------------
//
// `keyhog backend --autoroute` renders the persisted cache so an operator who hit
// a fail-closed "no decision for workload bucket ..." error can see exactly which
// resolved configs and workload buckets ARE calibrated, and whether the cache is
// stale for this build. This path deliberately does NOT validate host/detector/
// rules identity — a real scan does that and surfaces a mismatch loudly. It
// deserializes and DISPLAYS, additionally flagging the cheap build-identity drift
// (binary version / git hash / feature set) that a post-upgrade stale cache shows.

/// Operator-facing view of the persisted autoroute cache (one JSON object).
#[derive(Debug, Serialize)]
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

/// One calibrated (workload bucket -> fastest-correct backend) decision.
#[derive(Debug, Serialize)]
pub(crate) struct AutorouteDecisionInspection {
    pub(crate) workload: String,
    pub(crate) backend: String,
    pub(crate) sample_bytes: u64,
    pub(crate) sample_chunks: usize,
    pub(crate) simd_ms: u128,
    pub(crate) cpu_ms: Option<u128>,
    pub(crate) gpu_ms: Option<u128>,
}

pub(crate) fn inspect_autoroute_cache(path: Option<&std::path::Path>) -> AutorouteCacheInspection {
    let mut out = AutorouteCacheInspection {
        path: path.map(|p| p.display().to_string()),
        present: false,
        error: None,
        version: None,
        binary_version: None,
        git_hash: None,
        identity_matches_build: None,
        identity_mismatch_reason: None,
        host: None,
        detector_digest: None,
        rules_digest: None,
        configs: Vec::new(),
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

    match serde_json::from_slice::<AutorouteCacheVersionEnvelope>(&data) {
        Ok(envelope) => {
            out.version = Some(envelope.version);
            if envelope.version != AUTOROUTE_CACHE_VERSION {
                out.error = Some(format!(
                    "cache schema version {} is incompatible with this build (expects {}); \
                     re-run calibration to regenerate it",
                    envelope.version, AUTOROUTE_CACHE_VERSION
                ));
                return out;
            }
        }
        Err(error) => {
            out.error = Some(format!("autoroute cache is not valid cache JSON: {error}"));
            return out;
        }
    }

    let cache: AutorouteCache = match serde_json::from_slice(&data) {
        Ok(cache) => cache,
        Err(error) => {
            out.error = Some(format!(
                "autoroute cache payload did not deserialize: {error}"
            ));
            return out;
        }
    };

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
                simd_ms: decision.simd_ms,
                cpu_ms: decision.cpu_ms,
                gpu_ms: decision.gpu_ms,
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
/// Shared by the inspection view and the interpolation notice — one bucket
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

/// Collapse the two GPU labels to one route class for routing-decision
/// comparison. `Gpu` and `MegaScan` share the same measured GPU timing evidence
/// and differ only by a config-driven execution label, so they are equivalent
/// when checking which route the timings selected. SIMD and CPU stay distinct.
fn normalized_route_class(backend: ScanBackend) -> ScanBackend {
    match backend {
        ScanBackend::MegaScan => ScanBackend::Gpu,
        other => other,
    }
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
    validate_gpu_cold_warm_cache_evidence(decision)?;
    let Some(selected_timing) = decision.timing_for_backend(selected_backend) else {
        return Err("selected backend is missing timing evidence".into());
    };
    if !selected_timing.is_valid_for_trials(AUTOROUTE_CALIBRATION_TRIALS) {
        return Err("selected backend timing evidence is invalid".into());
    }
    let candidates = decision.route_candidates_for_selected_backend(selected_backend);
    let expected_margin = selected_backend_margin_ns(selected_backend, &candidates);
    if decision.selected_margin_ns != expected_margin {
        return Err("cache decision has invalid selected backend margin".into());
    }
    // Soundness gate. The persisted backend must equal the deterministic
    // resolution of the persisted timing evidence (`resolved_routing_backend`) —
    // the SAME confidence-interval logic calibration used to select it — so a
    // tampered or non-deterministic cache that names any other backend is
    // rejected. Routing is decided from 95% CIs, never a single `best_ns` trial.
    let Some(resolved) = decision.resolved_routing_backend() else {
        return Err("cache decision has no route timing evidence".into());
    };
    // Compare by route CLASS: `Gpu` and `MegaScan` are the same physical GPU
    // route with a config-driven label, not a timing decision, so a MegaScan
    // decision is consistent with a resolved `Gpu` winner. SIMD/CPU stay
    // distinct classes.
    if normalized_route_class(selected_backend) != normalized_route_class(resolved) {
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
    if decisions.is_empty() {
        return Err("autoroute cache contains no workload decisions".into());
    }
    for decision in decisions.values() {
        validate_decision_route_evidence(decision)?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Merge, do not overwrite. Preserve every other resolved-config entry from a
    // compatible on-disk cache so presets accumulate, and UNION this config's
    // freshly measured buckets over any it already had so sequential install
    // probes (separate processes, one bucket each) build up instead of each
    // clobbering the last. An incompatible/corrupt file is superseded wholesale
    // (loudly — see `read_mergeable_configs`).
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
/// presets. Returns an empty vec when there is nothing safe to preserve — file
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
    match serde_json::from_slice::<AutorouteCacheVersionEnvelope>(&data) {
        Ok(envelope) if envelope.version == AUTOROUTE_CACHE_VERSION => {}
        Ok(envelope) => {
            tracing::info!(
                target: "keyhog::routing",
                path = %path.display(),
                found_version = envelope.version,
                expected_version = AUTOROUTE_CACHE_VERSION,
                "existing autoroute cache is an older schema; superseding it with this build's calibration"
            );
            return Vec::new();
        }
        Err(error) => {
            tracing::warn!(
                target: "keyhog::routing",
                path = %path.display(),
                %error,
                "existing autoroute cache is not valid cache JSON; replacing it with a fresh calibration"
            );
            return Vec::new();
        }
    }
    let cache: AutorouteCache = match serde_json::from_slice(&data) {
        Ok(cache) => cache,
        Err(error) => {
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
