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
    decode_local_matcher_artifact_compile_state_sections, CompiledRouteMatcherSections,
};
use crate::execution_pack::{CanonicalDetectorExecutionIr, ExecutionPackBackend};
use crate::hw_probe::ScanBackend;
use crate::types::ScannerTuningConfig;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

/// Cache format version. Bump when the envelope layout changes.
pub use keyhog_core::MATCHER_ARTIFACT_FORMAT_VERSION as MATCHER_ARTIFACT_VERSION;
/// On-disk magic for MatcherArtifact cache files.
pub use keyhog_core::MATCHER_ARTIFACT_MAGIC;
/// Filename suffix for MatcherArtifact cache files.
pub use keyhog_core::MATCHER_ARTIFACT_SUFFIX;
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
    Ok(base.join(keyhog_core::KEYHOG_MATCHER_ARTIFACTS_SUBDIR))
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
    /// On-disk envelope version.
    pub version: u32,
    /// SHA-256 of the running keyhog executable.
    pub binary_digest: String,
    /// `CARGO_PKG_VERSION` of the running binary.
    pub binary_version: String,
    /// Git commit stamped into the binary.
    pub git_hash: String,
    /// Host target triple class (`arch-os`).
    pub target: String,
    /// Scanner feature identity string.
    pub features: String,
    /// Hex digest of the canonical detector execution IR.
    pub detector_corpus_digest: String,
    /// Hex digest of matcher-relevant resolved scan config.
    pub resolved_config_digest: String,
    /// Authenticated pack generation id, or `"none"`.
    pub pack_generation: String,
    /// Matcher backend name (`Cpu`, `Simd`, …).
    pub backend: String,
    /// Hyperscan/runtime identity, or `"none"`.
    pub runtime_identity: String,
    /// Route-matcher section schema version.
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
            "{}{}{}",
            keyhog_core::MATCHER_ARTIFACT_FILENAME_PREFIX,
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

/// MatcherArtifact v3 body layout (after the 8-byte magic/version header):
/// `identity_json_len:u32` + identity JSON + `identity_digest:[u8;32]` +
/// `content_digest:[u8;32]` + length-prefixed raw `literal_index` /
/// `regex_programs` / `suppression_policy` blobs.

fn read_u32_le(bytes: &[u8], offset: &mut usize, path: &Path) -> std::result::Result<u32, String> {
    let end = offset
        .checked_add(4)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| format!("matcher artifact {} is truncated", path.display()))?;
    let arr: [u8; 4] = bytes[*offset..end]
        .try_into()
        .map_err(|_| format!("matcher artifact {} is truncated", path.display()))?;
    let value = u32::from_le_bytes(arr);
    *offset = end;
    Ok(value)
}

fn read_exact<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    len: usize,
    path: &Path,
) -> std::result::Result<&'a [u8], String> {
    let end = offset
        .checked_add(len)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| format!("matcher artifact {} is truncated", path.display()))?;
    let slice = &bytes[*offset..end];
    *offset = end;
    Ok(slice)
}

/// Loaded MatcherArtifact payload (eager route-matcher sections only).
#[derive(Clone, Debug)]
pub struct LoadedMatcherArtifact {
    /// Route-matcher sections validated against the outer content digest.
    pub sections: CompiledRouteMatcherSections,
}

fn parse_loaded_matcher_artifact(
    path: &Path,
    bytes: &[u8],
    expected_identity: Option<&MatcherArtifactIdentity>,
) -> std::result::Result<(MatcherArtifactIdentity, LoadedMatcherArtifact), String> {
    if bytes.len() < 8 {
        return Err(format!("matcher artifact {} is truncated", path.display()));
    }
    if &bytes[..4] != MATCHER_ARTIFACT_MAGIC {
        return Err(format!(
            "matcher artifact {} has invalid magic",
            path.display()
        ));
    }
    let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if version != MATCHER_ARTIFACT_VERSION {
        return Err(format!(
            "matcher artifact {} version {version} is incompatible with {MATCHER_ARTIFACT_VERSION}",
            path.display()
        ));
    }

    let mut offset = 8usize;
    let identity_len = read_u32_le(bytes, &mut offset, path)? as usize;
    let identity_bytes = read_exact(bytes, &mut offset, identity_len, path)?;
    let decoded_identity: MatcherArtifactIdentity = serde_json::from_slice(identity_bytes)
        .map_err(|error| {
            format!(
                "matcher artifact {} identity is not valid JSON: {error}",
                path.display()
            )
        })?;
    if let Some(expected) = expected_identity {
        if decoded_identity != *expected {
            return Err(format!(
                "matcher artifact {} identity fields do not match the running scan",
                path.display()
            ));
        }
    }
    let stored_identity_digest: [u8; 32] = read_exact(bytes, &mut offset, 32, path)?
        .try_into()
        .map_err(|_| format!("matcher artifact {} is truncated", path.display()))?;
    let expected_digest = decoded_identity.digest();
    if stored_identity_digest != expected_digest {
        return Err(format!(
            "matcher artifact {} identity digest mismatch",
            path.display()
        ));
    }
    let stored_content_digest: [u8; 32] = read_exact(bytes, &mut offset, 32, path)?
        .try_into()
        .map_err(|_| format!("matcher artifact {} is truncated", path.display()))?;
    let literal_len = read_u32_le(bytes, &mut offset, path)? as usize;
    let literal_index = read_exact(bytes, &mut offset, literal_len, path)?.to_vec();
    let regex_len = read_u32_le(bytes, &mut offset, path)? as usize;
    let regex_programs = read_exact(bytes, &mut offset, regex_len, path)?.to_vec();
    let supp_len = read_u32_le(bytes, &mut offset, path)? as usize;
    let suppression_policy = read_exact(bytes, &mut offset, supp_len, path)?.to_vec();
    // v4: no trailing detector-IR blob. Reject unexpected trailing bytes so a
    // truncated/extended file cannot be accepted after the section digests.
    if offset != bytes.len() {
        return Err(format!(
            "matcher artifact {} has trailing bytes after the envelope",
            path.display()
        ));
    }

    let sections = CompiledRouteMatcherSections {
        backend: parse_backend_name(&decoded_identity.backend).ok_or_else(|| {
            format!(
                "matcher artifact {} has unknown backend {}",
                path.display(),
                decoded_identity.backend
            )
        })?,
        literal_index,
        regex_programs,
        suppression_policy,
    };
    let content = sections.content_digest();
    if content != stored_content_digest {
        return Err(format!(
            "matcher artifact {} content digest mismatch",
            path.display()
        ));
    }
    // Intentionally skip validate_canonical here: hydrate/decode re-parses the
    // section envelopes and fails closed. Avoiding a second 2.8 MiB JSON parse
    // keeps second-run tiny-file CPU near the warm-daemon reference.
    Ok((decoded_identity, LoadedMatcherArtifact { sections }))
}

/// Load a MatcherArtifact for `identity` from `cache_dir`.
pub fn load_matcher_artifact(
    cache_dir: &Path,
    identity: &MatcherArtifactIdentity,
) -> std::result::Result<CompiledRouteMatcherSections, String> {
    Ok(load_matcher_artifact_with_ir(cache_dir, identity)?.sections)
}

/// Load matcher sections plus the canonical detector IR for `identity`.
pub fn load_matcher_artifact_with_ir(
    cache_dir: &Path,
    identity: &MatcherArtifactIdentity,
) -> std::result::Result<LoadedMatcherArtifact, String> {
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != current_uid() {
            return Err(format!(
                "matcher artifact {} is not owned by the current user; refusing to load",
                path.display()
            ));
        }
    }
    if metadata.len() > MATCHER_ARTIFACT_FILE_BYTES {
        return Err(format!(
            "matcher artifact {} exceeds {} byte cap",
            path.display(),
            MATCHER_ARTIFACT_FILE_BYTES
        ));
    }
    let bytes = std::fs::read(&path)
        .map_err(|error| format!("cannot read matcher artifact {}: {error}", path.display()))?;
    let (_identity, loaded) = parse_loaded_matcher_artifact(&path, &bytes, Some(identity))?;
    Ok(loaded)
}

/// Persist `sections` under `identity`.
pub fn store_matcher_artifact(
    cache_dir: &Path,
    identity: &MatcherArtifactIdentity,
    sections: &CompiledRouteMatcherSections,
) -> std::result::Result<(), String> {
    let expected_backend = parse_backend_name(&identity.backend)
        .ok_or_else(|| "unknown identity backend".to_owned())?;
    if sections.backend != expected_backend {
        return Err("matcher artifact backend does not match identity".to_owned());
    }
    validate_matcher_artifact_cache_dir(cache_dir)?;
    // Only tighten mode on directories we create. Do not chmod a pre-existing
    // operator-supplied path (for example $HOME or $HOME/.cache).
    let created_cache_dir = !cache_dir.exists();
    std::fs::create_dir_all(cache_dir).map_err(|error| {
        format!(
            "cannot create matcher-artifact cache dir {}: {error}",
            cache_dir.display()
        )
    })?;
    #[cfg(unix)]
    if created_cache_dir {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(cache_dir)
            .map_err(|error| {
                format!(
                    "cannot stat matcher-artifact cache dir {}: {error}",
                    cache_dir.display()
                )
            })?
            .permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(cache_dir, perms).map_err(|error| {
            format!(
                "cannot tighten matcher-artifact cache dir {}: {error}",
                cache_dir.display()
            )
        })?;
    }
    let path = cache_dir.join(identity.cache_filename());
    let identity_json = serde_json::to_vec(identity)
        .map_err(|error| format!("cannot serialize matcher artifact identity: {error}"))?;
    let identity_digest = identity.digest();
    let content_digest = sections.content_digest();

    let mut bytes = Vec::with_capacity(
        8 + 4
            + identity_json.len()
            + 64
            + 12
            + sections.literal_index.len()
            + sections.regex_programs.len()
            + sections.suppression_policy.len(),
    );
    bytes.extend_from_slice(MATCHER_ARTIFACT_MAGIC);
    bytes.extend_from_slice(&MATCHER_ARTIFACT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&(identity_json.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&identity_json);
    bytes.extend_from_slice(&identity_digest);
    bytes.extend_from_slice(&content_digest);
    bytes.extend_from_slice(&(sections.literal_index.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&sections.literal_index);
    bytes.extend_from_slice(&(sections.regex_programs.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&sections.regex_programs);
    bytes.extend_from_slice(&(sections.suppression_policy.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&sections.suppression_policy);

    if (bytes.len() as u64) > MATCHER_ARTIFACT_FILE_BYTES {
        return Err(format!(
            "matcher artifact would exceed {} byte cap",
            MATCHER_ARTIFACT_FILE_BYTES
        ));
    }
    atomic_write(&path, &bytes)
        .map_err(|error| format!("cannot write matcher artifact {}: {error}", path.display()))?;
    evict_old_matcher_artifacts(cache_dir);
    Ok(())
}

const MATCHER_ARTIFACT_MAX_ENTRIES: usize = 8;

fn evict_old_matcher_artifacts(cache_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(cache_dir) else {
        return;
    };
    let mut artifacts = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("khm") {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        artifacts.push((modified, path));
    }
    if artifacts.len() <= MATCHER_ARTIFACT_MAX_ENTRIES {
        return;
    }
    artifacts.sort_by_key(|(modified, _)| *modified);
    let stale = artifacts.len() - MATCHER_ARTIFACT_MAX_ENTRIES;
    for (_, path) in artifacts.into_iter().take(stale) {
        let _ = std::fs::remove_file(path);
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    // Create the scratch file outside the MatcherArtifact cache root so an
    // in-flight `.tmp*` cannot trip lockdown's past-findings audit of that
    // directory. Fall back to copy when rename crosses filesystems.
    let mut tmp = tempfile::NamedTempFile::new()?;
    {
        tmp.write_all(bytes)?;
        tmp.as_file().sync_all()?;
    }
    match tmp.persist(path) {
        Ok(_) => Ok(()),
        Err(error) => {
            std::fs::copy(error.file.path(), path)?;
            // `std::fs::copy` inherits the process umask (often 0644). Tighten
            // to owner-only so the cross-filesystem fallback matches the
            // NamedTempFile/persist 0600 path.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(path)?.permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(path, perms)?;
            }
            let file = std::fs::File::open(path)?;
            file.sync_all()?;
            Ok(())
        }
    }
}

fn record_outcome(outcome: &MatcherArtifactCacheOutcome) {
    match outcome {
        MatcherArtifactCacheOutcome::Hit => {
            keyhog_profile::record_cache_hit(keyhog_profile::CacheId::MatcherArtifact);
        }
        MatcherArtifactCacheOutcome::Miss | MatcherArtifactCacheOutcome::Invalidated { .. } => {
            keyhog_profile::record_cache_miss(keyhog_profile::CacheId::MatcherArtifact);
        }
        // Intentionally disabled: do not record a miss for a cache that was never
        // consulted, so --profile does not look like a warm-cache failure.
        MatcherArtifactCacheOutcome::Disabled => {}
    }
}

/// Compile a scanner, consulting the MatcherArtifact cache when configured.
///
/// On hit, eager `build_compile_state` is skipped and the persisted matcher
/// graph is hydrated through the local digest-checked section decoder. On miss
/// or invalidation the corpus is compiled once via
/// [`CompiledRouteMatcherSections::compile_with_state`]; the live
/// [`CompileState`] is reused for the scanner while the envelopes are stored
/// when a cache directory is writable. Damaged on-disk entries are removed and
/// reported as `Invalidated`, not `Disabled`.
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
        return compile_without_matcher_artifact_cache(detectors, gpu_policy, tuning_config);
    };

    // Cache disabled: keep the historical compile cost (no IR round-trip).
    if cache_dir.is_none() {
        return compile_without_matcher_artifact_cache(detectors, gpu_policy, tuning_config);
    }

    // Identity keys on the canonical detector-IR digest (same digest packs use).
    // Computing it requires IR normalization; the avoided cost on hit is the
    // route-matcher section compile + eager CompileState construction. The
    // normalized detector list is also required to hydrate companions against
    // the live corpus, so this work is not optional bookkeeping.
    let ir = match CanonicalDetectorExecutionIr::compile(detectors.as_ref()) {
        Ok(ir) => ir,
        Err(error) => {
            tracing::warn!(
                target: "keyhog::matcher_artifact_cache",
                "matcher artifact cache unavailable ({error}); compiling without cache"
            );
            return compile_with_matcher_artifact_outcome(
                detectors,
                gpu_policy,
                tuning_config,
                MatcherArtifactCacheOutcome::Miss,
            );
        }
    };
    let detector_digest = ir.digest();
    let sorted: Arc<[keyhog_core::DetectorSpec]> = ir.detectors().to_vec().into();
    let identity = match MatcherArtifactIdentity::new(
        detector_digest,
        resolved_config_digest,
        pack_generation,
        backend,
        runtime_identity,
    ) {
        Ok(identity) => identity,
        Err(error) => {
            tracing::warn!(
                target: "keyhog::matcher_artifact_cache",
                "matcher artifact cache unavailable ({error}); compiling without cache"
            );
            return compile_with_matcher_artifact_outcome(
                sorted,
                gpu_policy,
                tuning_config,
                MatcherArtifactCacheOutcome::Miss,
            );
        }
    };

    let Some(cache_dir) = cache_dir.as_ref() else {
        return compile_without_matcher_artifact_cache(sorted, gpu_policy, tuning_config);
    };

    let path = cache_dir.join(identity.cache_filename());
    // When a structurally intact entry is not reusable for this live corpus
    // (hydrate/compile failure after a successful load), do not immediately
    // rewrite the same identity - that would delete+recreate forever.
    let mut allow_store = true;
    let rebuild_outcome = match load_matcher_artifact_with_ir(cache_dir, &identity) {
        Ok(loaded) => {
            match hydrate_matcher_artifact_state(&loaded.sections, detector_digest, sorted.as_ref())
            {
                Ok(state) => {
                    match CompiledScanner::compile_shared_from_compile_state(
                        Arc::clone(&sorted),
                        gpu_policy,
                        tuning_config,
                        state,
                    ) {
                        Ok(scanner) => {
                            let outcome = MatcherArtifactCacheOutcome::Hit;
                            record_outcome(&outcome);
                            return Ok((scanner, outcome));
                        }
                        Err(error) => {
                            let reason = format!("compile from hydrated state failed: {error}");
                            tracing::warn!(
                                target: "keyhog::matcher_artifact_cache",
                                "matcher artifact hit unusable ({}); removing entry {} and rebuilding",
                                error,
                                path.display()
                            );
                            if let Err(remove_error) = std::fs::remove_file(&path) {
                                tracing::warn!(
                                    target: "keyhog::matcher_artifact_cache",
                                    "failed to remove unusable matcher artifact entry {}: {}",
                                    path.display(),
                                    remove_error
                                );
                            }
                            allow_store = false;
                            MatcherArtifactCacheOutcome::Invalidated { reason }
                        }
                    }
                }
                Err(error) => {
                    let reason = format!("hydrate failed: {error}");
                    tracing::warn!(
                        target: "keyhog::matcher_artifact_cache",
                        "matcher artifact hydrate failed ({}); removing entry {} and rebuilding",
                        error,
                        path.display()
                    );
                    if let Err(remove_error) = std::fs::remove_file(&path) {
                        tracing::warn!(
                            target: "keyhog::matcher_artifact_cache",
                            "failed to remove unusable matcher artifact entry {}: {}",
                            path.display(),
                            remove_error
                        );
                    }
                    allow_store = false;
                    MatcherArtifactCacheOutcome::Invalidated { reason }
                }
            }
        }
        Err(reason) => {
            let outcome = if path.exists() {
                MatcherArtifactCacheOutcome::Invalidated {
                    reason: reason.clone(),
                }
            } else {
                MatcherArtifactCacheOutcome::Miss
            };
            tracing::debug!(
                target: "keyhog::matcher_artifact_cache",
                "matcher artifact cache miss ({}); outcome={}",
                reason,
                outcome.as_str()
            );
            outcome
        }
    };

    // Miss / invalidated rebuild: compile sections once, keep the live
    // CompileState, and persist the envelopes without a serialize/hydrate tax.
    let (sections, state) = match CompiledRouteMatcherSections::compile_with_state(&ir, backend) {
        Ok(pair) => pair,
        Err(error) => {
            tracing::warn!(
                target: "keyhog::matcher_artifact_cache",
                "matcher artifact section compile failed ({}); compiling without cache",
                error
            );
            return compile_with_matcher_artifact_outcome(
                sorted,
                gpu_policy,
                tuning_config,
                MatcherArtifactCacheOutcome::Miss,
            );
        }
    };
    if allow_store {
        // Only persist envelopes that survive the same hydrate path a later
        // process will use. Otherwise a miss would rewrite an unrehydratable
        // artifact every other scan forever.
        match hydrate_matcher_artifact_state(&sections, detector_digest, sorted.as_ref()) {
            Ok(_) => {
                if let Err(store_error) =
                    store_matcher_artifact(cache_dir, &identity, &sections)
                {
                    tracing::warn!(
                        target: "keyhog::matcher_artifact_cache",
                        "failed to persist matcher artifact cache entry: {}",
                        store_error
                    );
                }
            }
            Err(error) => {
                tracing::warn!(
                    target: "keyhog::matcher_artifact_cache",
                    "skipping matcher artifact persist; freshly compiled envelopes fail hydrate ({}): {}",
                    path.display(),
                    error
                );
            }
        }
    } else {
        tracing::warn!(
            target: "keyhog::matcher_artifact_cache",
            "skipping matcher artifact rewrite after deterministic reuse failure for {}",
            path.display()
        );
    }
    match CompiledScanner::compile_shared_from_compile_state(
        Arc::clone(&sorted),
        gpu_policy,
        tuning_config,
        state,
    ) {
        Ok(scanner) => {
            record_outcome(&rebuild_outcome);
            Ok((scanner, rebuild_outcome))
        }
        Err(error) => {
            tracing::warn!(
                target: "keyhog::matcher_artifact_cache",
                "matcher artifact rebuild compile failed ({}); compiling without cache",
                error
            );
            compile_with_matcher_artifact_outcome(
                sorted,
                gpu_policy,
                tuning_config,
                rebuild_outcome,
            )
        }
    }
}

fn compile_without_matcher_artifact_cache(
    detectors: Arc<[keyhog_core::DetectorSpec]>,
    gpu_policy: GpuInitPolicy,
    tuning_config: &ScannerTuningConfig,
) -> Result<(CompiledScanner, MatcherArtifactCacheOutcome)> {
    compile_with_matcher_artifact_outcome(
        detectors,
        gpu_policy,
        tuning_config,
        MatcherArtifactCacheOutcome::Disabled,
    )
}

fn compile_with_matcher_artifact_outcome(
    detectors: Arc<[keyhog_core::DetectorSpec]>,
    gpu_policy: GpuInitPolicy,
    tuning_config: &ScannerTuningConfig,
    outcome: MatcherArtifactCacheOutcome,
) -> Result<(CompiledScanner, MatcherArtifactCacheOutcome)> {
    record_outcome(&outcome);
    let scanner = CompiledScanner::compile_shared_with_gpu_policy_and_tuning(
        detectors,
        gpu_policy,
        tuning_config,
    )?;
    Ok((scanner, outcome))
}

fn hydrate_matcher_artifact_state(
    sections: &CompiledRouteMatcherSections,
    detector_digest: [u8; 32],
    detectors: &[keyhog_core::DetectorSpec],
) -> Result<CompileState> {
    // Outer identity/content digests already bound these bytes to the live
    // process (and `--lockdown` disables the cache). Skip only the untrusted-pack
    // JSON canonical re-encode (~1 CPU-s on a ~6 MiB artifact); still run
    // companion validation before constructing LazyRegex programs.
    decode_local_matcher_artifact_compile_state_sections(
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
