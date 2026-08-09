//! Persisted compiled matcher / `CompileState` artifact cache.
//!
//! This cache stores the eager detector-spec construction that would otherwise
//! run on every cold one-shot and `--incremental` invocation. It is distinct
//! from Hyperscan `--cache-dir` `.db` shards: those persist only the Hyperscan
//! database build, not the detector-spec / regex construction floor.
//!
//! LazyRegex programs stay compile-on-first-use. Retaining every compiled
//! detector regex would erase the remaining ~42% of the construction floor, but
//! it would also restore the hundreds-of-MiB residency MemoryFootprint removed.
//! This cache therefore serializes the eager half only.
//!
//! Fail closed: a stale or mismatched identity never yields a matcher. Callers
//! record every consultation through [`keyhog_profile::CacheId::MatcherArtifact`].

use crate::compiled_scanner::GpuInitPolicy;
use crate::compiler::compiler_build::CompileState;
use crate::engine::CompiledScanner;
use crate::error::{Result, ScanError};
use crate::execution_pack::matcher_sections::{
    decode_authenticated_compile_state_sections, CompiledRouteMatcherSections,
};
use crate::execution_pack::{CanonicalDetectorExecutionIr, ExecutionPackBackend};
use crate::hw_probe::ScanBackend;
use crate::types::ScannerTuningConfig;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

/// On-disk magic for MatcherArtifact cache files.
pub const MATCHER_ARTIFACT_MAGIC: &[u8; 4] = b"KHMA";
/// Cache format version. Bump when the envelope layout changes.
pub const MATCHER_ARTIFACT_VERSION: u32 = 1;
/// Filename suffix for MatcherArtifact cache files.
pub const MATCHER_ARTIFACT_SUFFIX: &str = ".khm";
/// Hard cap for one MatcherArtifact cache file, including header.
pub const MATCHER_ARTIFACT_FILE_BYTES: u64 = 256 * 1024 * 1024;

static CONFIGURED_CACHE_DIR: OnceLock<parking_lot::RwLock<Option<PathBuf>>> = OnceLock::new();

fn configured_cache_dir_cell() -> &'static parking_lot::RwLock<Option<PathBuf>> {
    CONFIGURED_CACHE_DIR.get_or_init(|| parking_lot::RwLock::new(None))
}

/// Configure the MatcherArtifact cache directory for this process.
///
/// `Some(path)` enables persistence at that absolute directory. `None` disables
/// the cache for subsequent compiles in this process.
pub fn set_matcher_artifact_cache_dir(path: Option<PathBuf>) {
    *configured_cache_dir_cell().write() = path;
}

/// Currently configured MatcherArtifact cache directory, if enabled.
pub fn configured_matcher_artifact_cache_dir() -> Option<PathBuf> {
    configured_cache_dir_cell().read().clone()
}

/// Default MatcherArtifact cache directory under the platform user cache root.
pub fn default_matcher_artifact_cache_dir() -> std::result::Result<PathBuf, String> {
    default_matcher_artifact_cache_dir_from_base(dirs::cache_dir())
}

/// Resolve the default MatcherArtifact cache directory from an explicit base.
pub fn default_matcher_artifact_cache_dir_from_base(
    base: Option<PathBuf>,
) -> std::result::Result<PathBuf, String> {
    let base = base.ok_or_else(|| {
        "could not determine a platform cache directory for matcher artifacts; configure \
         --matcher-cache <DIR|off> or [system].matcher_cache"
            .to_owned()
    })?;
    Ok(base.join("keyhog").join("matcher-artifacts"))
}

/// Validate an explicit MatcherArtifact cache directory.
pub fn validate_matcher_artifact_cache_dir(path: &Path) -> std::result::Result<(), String> {
    if !path.is_absolute() {
        return Err(format!(
            "matcher-artifact cache dir '{}' must be absolute",
            path.display()
        ));
    }
    let home = dirs::home_dir().ok_or_else(|| "could not determine HOME directory".to_owned())?;
    let uid = current_uid();
    let temp_root = std::env::temp_dir();
    let tmp_user_dir = temp_root.join(format!("keyhog-cache-{uid}"));
    if !(path.starts_with(&home) || path.starts_with(&tmp_user_dir)) {
        return Err(format!(
            "matcher-artifact cache dir must be under {} or {}",
            home.display(),
            tmp_user_dir.display()
        ));
    }
    if path.exists() {
        let meta = std::fs::symlink_metadata(path).map_err(|error| {
            format!("could not read matcher-artifact cache dir metadata: {error}")
        })?;
        if meta.file_type().is_symlink() {
            return Err("matcher-artifact cache dir cannot be a symlink".to_owned());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != uid {
                return Err(
                    "matcher-artifact cache directory is not owned by the current user".to_owned(),
                );
            }
        }
    }
    Ok(())
}

fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and returns the effective uid.
        unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Outcome of one MatcherArtifact cache consultation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MatcherArtifactCacheOutcome {
    /// Cache disabled for this compile.
    Disabled,
    /// Exact identity hit; eager construction was skipped.
    Hit,
    /// No usable entry; eager construction ran and a fresh entry was stored when possible.
    Miss,
    /// An on-disk entry existed but failed identity or integrity checks.
    Invalidated {
        /// Why the on-disk entry was refused.
        reason: String,
    },
}

impl MatcherArtifactCacheOutcome {
    /// Stable label for logs and profile text.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Hit => "hit",
            Self::Miss => "miss",
            Self::Invalidated { .. } => "invalidated",
        }
    }
}

/// Identity that must match exactly before a cached matcher may be reused.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MatcherArtifactIdentity {
    pub version: u32,
    pub binary_digest: String,
    pub binary_version: String,
    pub git_hash: String,
    pub target: String,
    pub features: String,
    pub detector_corpus_digest: String,
    pub resolved_config_digest: String,
    pub pack_generation: String,
    pub backend: String,
    pub runtime_identity: String,
    pub route_matcher_section_version: u16,
}

impl MatcherArtifactIdentity {
    /// Build the identity for one compile request.
    pub fn new(
        detector_corpus_digest: [u8; 32],
        resolved_config_digest: [u8; 32],
        pack_generation: Option<&str>,
        backend: ExecutionPackBackend,
        runtime_identity: Option<&str>,
    ) -> std::result::Result<Self, String> {
        Ok(Self {
            version: MATCHER_ARTIFACT_VERSION,
            binary_digest: current_executable_sha256()?,
            binary_version: env!("CARGO_PKG_VERSION").to_owned(),
            git_hash: keyhog_core::git_hash().to_owned(),
            target: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
            features: scanner_feature_identity(),
            detector_corpus_digest: keyhog_core::hex_encode(&detector_corpus_digest),
            resolved_config_digest: keyhog_core::hex_encode(&resolved_config_digest),
            pack_generation: pack_generation.unwrap_or("none").to_owned(),
            backend: backend_name(backend).to_owned(),
            runtime_identity: runtime_identity.unwrap_or("none").to_owned(),
            route_matcher_section_version: crate::execution_pack::ROUTE_MATCHER_SECTION_VERSION,
        })
    }

    /// Stable digest over every identity field.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        update_tagged(
            &mut hasher,
            b"domain",
            b"keyhog-matcher-artifact-identity-v1",
        );
        update_tagged(&mut hasher, b"version", &self.version.to_le_bytes());
        update_tagged(&mut hasher, b"binary_digest", self.binary_digest.as_bytes());
        update_tagged(
            &mut hasher,
            b"binary_version",
            self.binary_version.as_bytes(),
        );
        update_tagged(&mut hasher, b"git_hash", self.git_hash.as_bytes());
        update_tagged(&mut hasher, b"target", self.target.as_bytes());
        update_tagged(&mut hasher, b"features", self.features.as_bytes());
        update_tagged(
            &mut hasher,
            b"detector_corpus_digest",
            self.detector_corpus_digest.as_bytes(),
        );
        update_tagged(
            &mut hasher,
            b"resolved_config_digest",
            self.resolved_config_digest.as_bytes(),
        );
        update_tagged(
            &mut hasher,
            b"pack_generation",
            self.pack_generation.as_bytes(),
        );
        update_tagged(&mut hasher, b"backend", self.backend.as_bytes());
        update_tagged(
            &mut hasher,
            b"runtime_identity",
            self.runtime_identity.as_bytes(),
        );
        update_tagged(
            &mut hasher,
            b"route_matcher_section_version",
            &self.route_matcher_section_version.to_le_bytes(),
        );
        *hasher.finalize().as_bytes()
    }

    /// On-disk filename for this identity.
    pub fn cache_filename(&self) -> String {
        format!(
            "matcher-{}{}",
            keyhog_core::hex_encode(&self.digest()),
            MATCHER_ARTIFACT_SUFFIX
        )
    }
}

fn update_tagged(hasher: &mut blake3::Hasher, tag: &[u8], value: &[u8]) {
    hasher.update(&(tag.len() as u64).to_le_bytes());
    hasher.update(tag);
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn scanner_feature_identity() -> String {
    let mut features = Vec::new();
    macro_rules! push_feature {
        ($name:literal) => {
            if cfg!(feature = $name) {
                features.push($name);
            }
        };
    }
    push_feature!("ml");
    push_feature!("entropy");
    push_feature!("decode");
    push_feature!("multiline");
    push_feature!("simd");
    push_feature!("simdsieve");
    push_feature!("gpu");
    push_feature!("static-hyperscan");
    features.join(",")
}

fn backend_name(backend: ExecutionPackBackend) -> &'static str {
    match backend {
        ExecutionPackBackend::Cpu => "Cpu",
        ExecutionPackBackend::Simd => "Simd",
        ExecutionPackBackend::GpuCuda => "GpuCuda",
        ExecutionPackBackend::GpuWgpu => "GpuWgpu",
        ExecutionPackBackend::GpuMetal => "GpuMetal",
    }
}

fn parse_backend_name(name: &str) -> Option<ExecutionPackBackend> {
    match name {
        "Cpu" => Some(ExecutionPackBackend::Cpu),
        "Simd" => Some(ExecutionPackBackend::Simd),
        "GpuCuda" => Some(ExecutionPackBackend::GpuCuda),
        "GpuWgpu" => Some(ExecutionPackBackend::GpuWgpu),
        "GpuMetal" => Some(ExecutionPackBackend::GpuMetal),
        _ => None,
    }
}

/// Map a selected scan backend onto the matcher-artifact backend tag.
pub fn execution_pack_backend_for_scan_backend(
    backend: ScanBackend,
) -> Option<ExecutionPackBackend> {
    match backend {
        ScanBackend::CpuFallback => Some(ExecutionPackBackend::Cpu),
        ScanBackend::SimdCpu => Some(ExecutionPackBackend::Simd),
        ScanBackend::GpuCuda => Some(ExecutionPackBackend::GpuCuda),
        ScanBackend::GpuWgpu => Some(ExecutionPackBackend::GpuWgpu),
        ScanBackend::GpuMetal => Some(ExecutionPackBackend::GpuMetal),
    }
}

/// Resolve the matcher-artifact backend tag for a compile-time GPU policy.
pub fn matcher_backend_for_gpu_policy(policy: GpuInitPolicy) -> Option<ExecutionPackBackend> {
    match policy {
        GpuInitPolicy::SelectedBackend(backend) => execution_pack_backend_for_scan_backend(backend),
        // Eager CompileState is backend-agnostic. Ambiguous GPU policies still
        // build that same graph before peer acquisition, so tag and reuse it as
        // Cpu rather than skipping the cache.
        GpuInitPolicy::ForceDisabled
        | GpuInitPolicy::FromRuntimePolicy
        | GpuInitPolicy::ForceEnabled => Some(ExecutionPackBackend::Cpu),
    }
}

fn current_executable_sha256() -> std::result::Result<String, String> {
    static DIGEST: OnceLock<std::result::Result<String, String>> = OnceLock::new();
    DIGEST
        .get_or_init(|| {
            use sha2::{Digest, Sha256};
            let path = std::env::current_exe().map_err(|error| {
                format!("locate running executable for matcher identity: {error}")
            })?;
            let mut file = std::fs::File::open(&path).map_err(|error| {
                format!(
                    "open running executable {} for matcher identity: {error}",
                    path.display()
                )
            })?;
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 128 * 1024];
            loop {
                let read = file.read(&mut buffer).map_err(|error| {
                    format!(
                        "read running executable {} for matcher identity: {error}",
                        path.display()
                    )
                })?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
            Ok(format!("{:x}", hasher.finalize()))
        })
        .clone()
}

#[derive(Serialize, Deserialize)]
struct MatcherArtifactFile {
    identity: MatcherArtifactIdentity,
    identity_digest: String,
    content_digest: String,
    literal_index: Vec<u8>,
    regex_programs: Vec<u8>,
    suppression_policy: Vec<u8>,
}

/// Load a MatcherArtifact for `identity` from `cache_dir`.
///
/// Returns `Ok(sections)` only when every identity field and content digest
/// matches. Any mismatch is `Err` with a reason suitable for invalidation
/// telemetry; callers must rebuild rather than serve the foreign matcher.
pub fn load_matcher_artifact(
    cache_dir: &Path,
    identity: &MatcherArtifactIdentity,
) -> std::result::Result<CompiledRouteMatcherSections, String> {
    let path = cache_dir.join(identity.cache_filename());
    let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            format!("matcher artifact cache miss: {}", path.display())
        } else {
            format!("cannot stat matcher artifact {}: {error}", path.display())
        }
    })?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "matcher artifact {} is a symlink; refusing to load",
            path.display()
        ));
    }
    if metadata.len() > MATCHER_ARTIFACT_FILE_BYTES {
        return Err(format!(
            "matcher artifact {} exceeds {} byte cap",
            path.display(),
            MATCHER_ARTIFACT_FILE_BYTES
        ));
    }
    let mut file = std::fs::File::open(&path)
        .map_err(|error| format!("cannot open matcher artifact {}: {error}", path.display()))?;
    let mut header = [0u8; 8];
    file.read_exact(&mut header).map_err(|error| {
        format!(
            "cannot read matcher artifact header {}: {error}",
            path.display()
        )
    })?;
    if &header[..4] != MATCHER_ARTIFACT_MAGIC {
        return Err(format!(
            "matcher artifact {} has invalid magic",
            path.display()
        ));
    }
    let version = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    if version != MATCHER_ARTIFACT_VERSION {
        return Err(format!(
            "matcher artifact {} version {version} is incompatible with {MATCHER_ARTIFACT_VERSION}",
            path.display()
        ));
    }
    let mut limited = file.take(MATCHER_ARTIFACT_FILE_BYTES.saturating_sub(8));
    let mut body = Vec::new();
    limited
        .read_to_end(&mut body)
        .map_err(|error| format!("cannot read matcher artifact {}: {error}", path.display()))?;
    let decoded: MatcherArtifactFile = serde_json::from_slice(&body).map_err(|error| {
        format!(
            "matcher artifact {} is not valid JSON: {error}",
            path.display()
        )
    })?;
    if decoded.identity != *identity {
        return Err(format!(
            "matcher artifact {} identity fields do not match the running scan",
            path.display()
        ));
    }
    let expected_digest = identity.digest();
    let stored_digest = parse_hex32(&decoded.identity_digest).ok_or_else(|| {
        format!(
            "matcher artifact {} has a malformed identity digest",
            path.display()
        )
    })?;
    if stored_digest != expected_digest {
        return Err(format!(
            "matcher artifact {} identity digest mismatch",
            path.display()
        ));
    }
    let sections = CompiledRouteMatcherSections {
        backend: parse_backend_name(&decoded.identity.backend).ok_or_else(|| {
            format!(
                "matcher artifact {} has unknown backend {}",
                path.display(),
                decoded.identity.backend
            )
        })?,
        literal_index: decoded.literal_index,
        regex_programs: decoded.regex_programs,
        suppression_policy: decoded.suppression_policy,
    };
    let content = sections.content_digest();
    let stored_content = parse_hex32(&decoded.content_digest).ok_or_else(|| {
        format!(
            "matcher artifact {} has a malformed content digest",
            path.display()
        )
    })?;
    if content != stored_content {
        return Err(format!(
            "matcher artifact {} content digest mismatch",
            path.display()
        ));
    }
    sections.validate_canonical().map_err(|error| {
        format!(
            "matcher artifact {} failed canonical validation: {error}",
            path.display()
        )
    })?;
    Ok(sections)
}

/// Persist `sections` under `identity` into `cache_dir`.
pub fn store_matcher_artifact(
    cache_dir: &Path,
    identity: &MatcherArtifactIdentity,
    sections: &CompiledRouteMatcherSections,
) -> std::result::Result<(), String> {
    let expected_backend =
        parse_backend_name(&identity.backend).ok_or_else(|| "unknown identity backend".to_owned())?;
    if sections.backend != expected_backend {
        return Err("matcher artifact backend does not match identity".to_owned());
    }
    std::fs::create_dir_all(cache_dir).map_err(|error| {
        format!(
            "cannot create matcher-artifact cache dir {}: {error}",
            cache_dir.display()
        )
    })?;
    let path = cache_dir.join(identity.cache_filename());
    let file = MatcherArtifactFile {
        identity: identity.clone(),
        identity_digest: keyhog_core::hex_encode(&identity.digest()),
        content_digest: keyhog_core::hex_encode(&sections.content_digest()),
        literal_index: sections.literal_index.clone(),
        regex_programs: sections.regex_programs.clone(),
        suppression_policy: sections.suppression_policy.clone(),
    };
    let body = serde_json::to_vec(&file)
        .map_err(|error| format!("cannot serialize matcher artifact: {error}"))?;
    if (body.len() as u64).saturating_add(8) > MATCHER_ARTIFACT_FILE_BYTES {
        return Err(format!(
            "matcher artifact would exceed {} byte cap",
            MATCHER_ARTIFACT_FILE_BYTES
        ));
    }
    let mut bytes = Vec::with_capacity(8 + body.len());
    bytes.extend_from_slice(MATCHER_ARTIFACT_MAGIC);
    bytes.extend_from_slice(&MATCHER_ARTIFACT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&body);
    atomic_write(&path, &bytes)
        .map_err(|error| format!("cannot write matcher artifact {}: {error}", path.display()))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let tmp = tempfile::NamedTempFile::new_in(parent)?;
    {
        let mut file = tmp.reopen()?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    tmp.persist(path).map(drop).map_err(|error| error.error)
}

fn parse_hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, chunk) in text.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[index] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn record_outcome(outcome: &MatcherArtifactCacheOutcome) {
    match outcome {
        MatcherArtifactCacheOutcome::Hit => {
            keyhog_profile::record_cache_hit(keyhog_profile::CacheId::MatcherArtifact);
        }
        MatcherArtifactCacheOutcome::Miss
        | MatcherArtifactCacheOutcome::Invalidated { .. }
        | MatcherArtifactCacheOutcome::Disabled => {
            keyhog_profile::record_cache_miss(keyhog_profile::CacheId::MatcherArtifact);
        }
    }
}

/// Compile a scanner, consulting the MatcherArtifact cache when configured.
///
/// On hit, eager `build_compile_state` is skipped and the authenticated matcher
/// graph is hydrated. On miss/invalidation the corpus is compiled once, stored
/// when a cache directory is configured, then hydrated from that artifact so the
/// miss path does not compile twice.
pub fn compile_shared_with_matcher_artifact_cache(
    detectors: Arc<[keyhog_core::DetectorSpec]>,
    gpu_policy: GpuInitPolicy,
    tuning_config: &ScannerTuningConfig,
    resolved_config_digest: [u8; 32],
    pack_generation: Option<&str>,
    runtime_identity: Option<&str>,
) -> Result<(CompiledScanner, MatcherArtifactCacheOutcome)> {
    let cache_dir = configured_matcher_artifact_cache_dir();
    let Some(backend) = matcher_backend_for_gpu_policy(gpu_policy) else {
        let outcome = MatcherArtifactCacheOutcome::Disabled;
        record_outcome(&outcome);
        let scanner = CompiledScanner::compile_shared_with_gpu_policy_and_tuning(
            detectors,
            gpu_policy,
            tuning_config,
        )?;
        return Ok((scanner, outcome));
    };

    let ir = CanonicalDetectorExecutionIr::compile(detectors.as_ref()).map_err(|error| {
        ScanError::Config(format!(
            "cannot compile detector execution IR for matcher cache: {error}"
        ))
    })?;
    let detector_digest = ir.digest();
    let sorted: Arc<[keyhog_core::DetectorSpec]> = ir.detectors().to_vec().into();
    let identity = MatcherArtifactIdentity::new(
        detector_digest,
        resolved_config_digest,
        pack_generation,
        backend,
        runtime_identity,
    )
    .map_err(ScanError::Config)?;

    if let Some(cache_dir) = cache_dir.as_ref() {
        match load_matcher_artifact(cache_dir, &identity) {
            Ok(sections) => {
                let state =
                    hydrate_authenticated_state(&sections, detector_digest, sorted.as_ref())?;
                let scanner = CompiledScanner::compile_shared_from_compile_state(
                    Arc::clone(&sorted),
                    gpu_policy,
                    tuning_config,
                    state,
                )?;
                let outcome = MatcherArtifactCacheOutcome::Hit;
                record_outcome(&outcome);
                return Ok((scanner, outcome));
            }
            Err(reason) => {
                let path = cache_dir.join(identity.cache_filename());
                let outcome = if path.exists() {
                    MatcherArtifactCacheOutcome::Invalidated {
                        reason: reason.clone(),
                    }
                } else {
                    MatcherArtifactCacheOutcome::Miss
                };
                tracing::debug!(
                    target: "keyhog::matcher_artifact_cache",
                    %reason,
                    outcome = outcome.as_str(),
                    "matcher artifact cache miss"
                );
                let sections =
                    CompiledRouteMatcherSections::compile(&ir, backend).map_err(|error| {
                        ScanError::Config(format!(
                            "cannot compile matcher artifact sections: {error}"
                        ))
                    })?;
                if let Err(store_error) = store_matcher_artifact(cache_dir, &identity, &sections) {
                    tracing::warn!(
                        target: "keyhog::matcher_artifact_cache",
                        error = %store_error,
                        "failed to persist matcher artifact cache entry"
                    );
                }
                let state =
                    hydrate_authenticated_state(&sections, detector_digest, sorted.as_ref())?;
                let scanner = CompiledScanner::compile_shared_from_compile_state(
                    sorted,
                    gpu_policy,
                    tuning_config,
                    state,
                )?;
                record_outcome(&outcome);
                return Ok((scanner, outcome));
            }
        }
    }

    let outcome = MatcherArtifactCacheOutcome::Disabled;
    record_outcome(&outcome);
    let scanner = CompiledScanner::compile_shared_with_gpu_policy_and_tuning(
        sorted,
        gpu_policy,
        tuning_config,
    )?;
    Ok((scanner, outcome))
}

fn hydrate_authenticated_state(
    sections: &CompiledRouteMatcherSections,
    detector_digest: [u8; 32],
    detectors: &[keyhog_core::DetectorSpec],
) -> Result<CompileState> {
    decode_authenticated_compile_state_sections(
        sections.backend,
        &sections.literal_index,
        &sections.regex_programs,
        &sections.suppression_policy,
        detector_digest,
        detectors,
    )
    .map_err(|error| ScanError::Config(error.to_string()))
}

/// Record a MatcherArtifact hit for an authenticated execution-pack hydration.
///
/// Installed packs already carry the eager matcher graph; profile output still
/// attributes that reuse to `CacheId::MatcherArtifact`.
pub fn record_matcher_artifact_pack_hit() {
    keyhog_profile::record_cache_hit(keyhog_profile::CacheId::MatcherArtifact);
}
