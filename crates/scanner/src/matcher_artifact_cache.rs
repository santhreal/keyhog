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
use std::ops::Range;
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
/// Default maximum retained matcher artifacts in cache directory.
pub const MATCHER_ARTIFACT_MAX_ENTRIES: usize = keyhog_core::CacheKind::MatcherArtifacts
    .default_policy()
    .max_entries;
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
    validate_and_tighten_matcher_artifact_cache_dir(path, false)
}

/// Validate a MatcherArtifact cache directory with optional auto-tightening for default locations.
pub fn validate_and_tighten_matcher_artifact_cache_dir(
    path: &Path,
    auto_tighten: bool,
) -> std::result::Result<(), String> {
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
            "matcher-artifact cache dir must be under {} or {}; configure with --matcher-cache <DIR>",
            home.display(),
            tmp_user_dir.display()
        ));
    }
    if path.exists() {
        let meta = std::fs::symlink_metadata(path).map_err(|error| {
            format!("could not read matcher-artifact cache dir metadata: {error}")
        })?;
        if meta.file_type().is_symlink() {
            return Err(format!(
                "matcher-artifact cache dir cannot be a symlink; repair with `rm {}`",
                path.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != uid {
                return Err(format!(
                    "matcher-artifact cache directory is not owned by the current user (uid {uid}); repair with `chown -R {uid} {}`",
                    path.display()
                ));
            }
            if meta.mode() & 0o077 != 0 {
                if auto_tighten {
                    use std::os::unix::fs::PermissionsExt;
                    if let Err(error) =
                        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                    {
                        return Err(format!(
                            "matcher-artifact cache directory is group- or world-accessible and tightening permissions failed: {error}; repair with `chmod 700 {}`",
                            path.display()
                        ));
                    }
                } else if meta.mode() & 0o022 != 0 {
                    return Err(format!(
                        "matcher-artifact cache directory must not be group- or world-writable; repair with `chmod 700 {}`",
                        path.display()
                    ));
                }
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

/// Explicit reason why the MatcherArtifact cache was disabled.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatcherArtifactCacheDisableReason {
    /// Explicitly disabled by operator configuration (`--matcher-cache off` or `[system].matcher_cache = "off"`).
    ConfiguredOff,
    /// Disabled because `--lockdown` forbids loading unsigned on-disk artifacts.
    LockdownActive,
    /// No usable cache directory available or default path was unusable.
    UnusableLocation,
    /// The selected GPU policy has no fixed execution backend matcher representation.
    NoBackendForGpuPolicy,
}

impl MatcherArtifactCacheDisableReason {
    /// Every disable reason variant in stable wire order.
    pub const ALL: &'static [Self] = &[
        Self::ConfiguredOff,
        Self::LockdownActive,
        Self::UnusableLocation,
        Self::NoBackendForGpuPolicy,
    ];

    /// Stable reason label used in logs, profiles, and operator reporting.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConfiguredOff => "configured-off",
            Self::LockdownActive => "lockdown-active",
            Self::UnusableLocation => "unusable-location",
            Self::NoBackendForGpuPolicy => "no-backend-for-gpu-policy",
        }
    }

    /// Operator-visible explanation for why the cache was disabled.
    #[must_use]
    pub const fn operator_explanation(self) -> &'static str {
        match self {
            Self::ConfiguredOff => "MatcherArtifact cache explicitly disabled via --matcher-cache off",
            Self::LockdownActive => "MatcherArtifact cache disabled because --lockdown forbids unsigned on-disk caches",
            Self::UnusableLocation => "MatcherArtifact cache disabled because cache location is missing or unusable",
            Self::NoBackendForGpuPolicy => "MatcherArtifact cache disabled because selected GPU policy has no fixed matcher backend",
        }
    }

    /// Whether this disable reason represents an accidental disable (which requires an operator warning at default verbosity)
    /// vs an intentional operator configuration.
    #[must_use]
    pub const fn is_accidental(self) -> bool {
        matches!(self, Self::UnusableLocation)
    }
}

/// Outcome of one MatcherArtifact cache consultation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MatcherArtifactCacheOutcome {
    /// Cache disabled for this compile with an explicit reason.
    Disabled {
        reason: MatcherArtifactCacheDisableReason,
    },
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
            Self::Disabled { .. } => "disabled",
            Self::Hit => "hit",
            Self::Miss => "miss",
            Self::Invalidated { .. } => "invalidated",
        }
    }

    /// Retrieve the disable reason if disabled.
    pub const fn disable_reason(&self) -> Option<MatcherArtifactCacheDisableReason> {
        match self {
            Self::Disabled { reason } => Some(*reason),
            _ => None,
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
            backend: backend.pascal_name().to_owned(),
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

/// Map a selected scan backend onto the matcher-artifact backend tag.
pub fn execution_pack_backend_for_scan_backend(
    backend: ScanBackend,
) -> Option<ExecutionPackBackend> {
    ExecutionPackBackend::from_scan_backend(backend)
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
    keyhog_core::current_executable_sha256()
}

/// MatcherArtifact v4 body layout (after the 8-byte magic/version header):
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

#[derive(Clone, Debug)]
struct MatcherArtifactSectionRanges {
    backend: ExecutionPackBackend,
    literal_index: Range<usize>,
    regex_programs: Range<usize>,
    suppression_policy: Range<usize>,
}

#[derive(Debug)]
struct BorrowedMatcherArtifact {
    bytes: Vec<u8>,
    ranges: MatcherArtifactSectionRanges,
}

impl BorrowedMatcherArtifact {
    fn section_bytes(&self) -> (&[u8], &[u8], &[u8]) {
        (
            &self.bytes[self.ranges.literal_index.clone()],
            &self.bytes[self.ranges.regex_programs.clone()],
            &self.bytes[self.ranges.suppression_policy.clone()],
        )
    }

    // Public loader compatibility only. The scanner startup path hydrates from
    // `section_bytes` and never materializes this second owned section set.
    fn to_owned_sections(&self) -> CompiledRouteMatcherSections {
        let (literal_index, regex_programs, suppression_policy) = self.section_bytes();
        CompiledRouteMatcherSections {
            backend: self.ranges.backend,
            literal_index: literal_index.to_vec(),
            regex_programs: regex_programs.to_vec(),
            suppression_policy: suppression_policy.to_vec(),
        }
    }
}

fn parse_matcher_artifact_ranges(
    path: &Path,
    bytes: &[u8],
    expected_identity: Option<&MatcherArtifactIdentity>,
) -> std::result::Result<(MatcherArtifactIdentity, MatcherArtifactSectionRanges), String> {
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
    let literal_start = offset;
    read_exact(bytes, &mut offset, literal_len, path)?;
    let literal_index = literal_start..offset;

    let regex_len = read_u32_le(bytes, &mut offset, path)? as usize;
    let regex_start = offset;
    read_exact(bytes, &mut offset, regex_len, path)?;
    let regex_programs = regex_start..offset;

    let supp_len = read_u32_le(bytes, &mut offset, path)? as usize;
    let suppression_start = offset;
    read_exact(bytes, &mut offset, supp_len, path)?;
    let suppression_policy = suppression_start..offset;

    // v4: no trailing detector-IR blob. Reject unexpected trailing bytes so a
    // truncated/extended file cannot be accepted after the section digests.
    if offset != bytes.len() {
        return Err(format!(
            "matcher artifact {} has trailing bytes after the envelope",
            path.display()
        ));
    }

    let backend =
        ExecutionPackBackend::from_pascal_name(&decoded_identity.backend).ok_or_else(|| {
            format!(
                "matcher artifact {} has unknown backend {}",
                path.display(),
                decoded_identity.backend
            )
        })?;
    let content = CompiledRouteMatcherSections::content_digest_for(
        &bytes[literal_index.clone()],
        &bytes[regex_programs.clone()],
        &bytes[suppression_policy.clone()],
    );
    if content != stored_content_digest {
        return Err(format!(
            "matcher artifact {} content digest mismatch",
            path.display()
        ));
    }
    // Hydration re-parses the section envelopes and fails closed. Avoiding a
    // second canonical parse and keeping the sections borrowed from the capped
    // file buffer removes the startup-path copies.
    Ok((
        decoded_identity,
        MatcherArtifactSectionRanges {
            backend,
            literal_index,
            regex_programs,
            suppression_policy,
        },
    ))
}

fn load_borrowed_matcher_artifact(
    cache_dir: &Path,
    identity: &MatcherArtifactIdentity,
) -> std::result::Result<BorrowedMatcherArtifact, String> {
    let path = cache_dir.join(identity.cache_filename());
    let bytes = read_matcher_artifact_bytes(&path)?;
    let (_identity, ranges) = parse_matcher_artifact_ranges(&path, &bytes, Some(identity))?;
    Ok(BorrowedMatcherArtifact { bytes, ranges })
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
    let loaded = load_borrowed_matcher_artifact(cache_dir, identity)?;
    Ok(LoadedMatcherArtifact {
        sections: loaded.to_owned_sections(),
    })
}

fn read_capped_matcher_artifact(
    file: std::fs::File,
    metadata_len: u64,
    path: &Path,
) -> std::result::Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(metadata_len.min(MATCHER_ARTIFACT_FILE_BYTES) as usize);
    file.take(MATCHER_ARTIFACT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read matcher artifact {}: {error}", path.display()))?;
    if bytes.len() as u64 > MATCHER_ARTIFACT_FILE_BYTES {
        return Err(format!(
            "matcher artifact {} exceeds {} byte cap",
            path.display(),
            MATCHER_ARTIFACT_FILE_BYTES
        ));
    }
    Ok(bytes)
}

fn read_matcher_artifact_bytes(path: &Path) -> std::result::Result<Vec<u8>, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        options.custom_flags(libc::O_NOFOLLOW);
        let file = match options.open(path) {
            Ok(file) => file,
            Err(error) => {
                if error.raw_os_error() == Some(libc::ELOOP) {
                    return Err(format!(
                        "matcher artifact {} is a symlink; refusing to load",
                        path.display()
                    ));
                }
                if error.kind() == std::io::ErrorKind::NotFound {
                    return Err(format!("matcher artifact cache miss: {}", path.display()));
                }
                return Err(format!(
                    "cannot open matcher artifact {}: {error}",
                    path.display()
                ));
            }
        };
        let metadata = file.metadata().map_err(|error| {
            format!("cannot fstat matcher artifact {}: {error}", path.display())
        })?;
        if !metadata.file_type().is_file() {
            return Err(format!(
                "matcher artifact {} is not a regular file; refusing to load",
                path.display()
            ));
        }
        if metadata.uid() != current_uid() {
            return Err(format!(
                "matcher artifact {} is not owned by the current user; refusing to load",
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
        return read_capped_matcher_artifact(file, metadata.len(), path);
    }
    #[cfg(not(unix))]
    {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
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
        let file = std::fs::File::open(path)
            .map_err(|error| format!("cannot open matcher artifact {}: {error}", path.display()))?;
        read_capped_matcher_artifact(file, metadata.len(), path)
    }
}

fn checked_matcher_artifact_len(
    identity_len: usize,
    literal_len: usize,
    regex_len: usize,
    suppression_len: usize,
) -> std::result::Result<usize, String> {
    let artifact_len = [
        8usize,
        4,
        identity_len,
        64,
        12,
        literal_len,
        regex_len,
        suppression_len,
    ]
    .into_iter()
    .try_fold(0usize, usize::checked_add)
    .ok_or_else(|| "matcher artifact size overflow".to_owned())?;
    if artifact_len as u64 > MATCHER_ARTIFACT_FILE_BYTES {
        return Err(format!(
            "matcher artifact would exceed {} byte cap",
            MATCHER_ARTIFACT_FILE_BYTES
        ));
    }
    Ok(artifact_len)
}

/// Persist `sections` under `identity`.
pub fn store_matcher_artifact(
    cache_dir: &Path,
    identity: &MatcherArtifactIdentity,
    sections: &CompiledRouteMatcherSections,
) -> std::result::Result<(), String> {
    let expected_backend = ExecutionPackBackend::from_pascal_name(&identity.backend)
        .ok_or_else(|| "unknown identity backend".to_owned())?;
    if sections.backend != expected_backend {
        return Err("matcher artifact backend does not match identity".to_owned());
    }
    validate_and_tighten_matcher_artifact_cache_dir(cache_dir, true)?;
    std::fs::create_dir_all(cache_dir).map_err(|error| {
        format!(
            "cannot create matcher-artifact cache dir {}: {error}",
            cache_dir.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::symlink_metadata(cache_dir) { // LAW10: best-effort permissions check on newly created cache dir; failure surfaced if chmod fails
            if !meta.file_type().is_symlink() && (meta.permissions().mode() & 0o077 != 0) {
                std::fs::set_permissions(cache_dir, std::fs::Permissions::from_mode(0o700))
                    .map_err(|error| {
                        format!(
                            "cannot tighten matcher-artifact cache dir {}: {error}; repair with `chmod 700 {}`",
                            cache_dir.display(),
                            cache_dir.display()
                        )
                    })?;
            }
        }
    }
    let path = cache_dir.join(identity.cache_filename());
    let identity_json = serde_json::to_vec(identity)
        .map_err(|error| format!("cannot serialize matcher artifact identity: {error}"))?;
    let identity_digest = identity.digest();
    let content_digest = sections.content_digest();

    let identity_len = u32::try_from(identity_json.len())
        .map_err(|_| "matcher artifact identity exceeds u32 length".to_owned())?;
    let literal_len = u32::try_from(sections.literal_index.len())
        .map_err(|_| "matcher artifact literal index exceeds u32 length".to_owned())?;
    let regex_len = u32::try_from(sections.regex_programs.len())
        .map_err(|_| "matcher artifact regex programs exceed u32 length".to_owned())?;
    let suppression_len = u32::try_from(sections.suppression_policy.len())
        .map_err(|_| "matcher artifact suppression policy exceeds u32 length".to_owned())?;
    let artifact_len = checked_matcher_artifact_len(
        identity_json.len(),
        sections.literal_index.len(),
        sections.regex_programs.len(),
        sections.suppression_policy.len(),
    )?;

    atomic_write(&path, artifact_len, |tmp| {
        tmp.write_all(MATCHER_ARTIFACT_MAGIC)?;
        tmp.write_all(&MATCHER_ARTIFACT_VERSION.to_le_bytes())?;
        tmp.write_all(&identity_len.to_le_bytes())?;
        tmp.write_all(&identity_json)?;
        tmp.write_all(&identity_digest)?;
        tmp.write_all(&content_digest)?;
        tmp.write_all(&literal_len.to_le_bytes())?;
        tmp.write_all(&sections.literal_index)?;
        tmp.write_all(&regex_len.to_le_bytes())?;
        tmp.write_all(&sections.regex_programs)?;
        tmp.write_all(&suppression_len.to_le_bytes())?;
        tmp.write_all(&sections.suppression_policy)
    })
    .map_err(|error| format!("cannot write matcher artifact {}: {error}", path.display()))?;
    evict_old_matcher_artifacts(cache_dir);
    Ok(())
}

fn evict_old_matcher_artifacts(cache_dir: &Path) {
    let policy = keyhog_core::CacheKind::MatcherArtifacts.default_policy();
    crate::cache_eviction::evict_cache_dir_with_policy(
        cache_dir,
        keyhog_core::CacheKind::MatcherArtifacts,
        policy,
    );
}

fn atomic_write(
    path: &Path,
    expected_len: usize,
    write_body: impl FnOnce(&mut tempfile::NamedTempFile) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "matcher artifact path has no parent directory",
            )
        })?;
    std::fs::create_dir_all(parent)?;
    // Same-directory tempfile + rename (parity with HS shard cache). Keeps
    // publish atomic on the common `/tmp` vs `$HOME` layout. In-flight
    // tempfile names are not trusted by lockdown's compiled-pattern filename
    // check, so a concurrent `--lockdown` audit still fails closed rather than
    // treating a partial graph as clean.
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    write_body(&mut tmp)?;
    let actual_len = usize::try_from(tmp.as_file().metadata()?.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "matcher artifact length exceeds usize",
        )
    })?;
    if actual_len != expected_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("matcher artifact writer produced {actual_len} bytes, expected {expected_len}"),
        ));
    }
    tmp.as_file().sync_all()?;
    tmp.persist(path).map(|_| ()).map_err(|error| error.error)
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
        MatcherArtifactCacheOutcome::Disabled { .. } => {}
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
        return compile_without_matcher_artifact_cache(
            detectors,
            gpu_policy,
            tuning_config,
            MatcherArtifactCacheDisableReason::NoBackendForGpuPolicy,
        );
    };

    // Cache disabled: skip IR/cache I/O, but still normalize the detector list the
    // same way the cache-enabled path does so enabling the cache cannot change
    // scanner assembly ordering.
    if cache_dir.is_none() {
        return compile_without_matcher_artifact_cache(
            detectors,
            gpu_policy,
            tuning_config,
            MatcherArtifactCacheDisableReason::ConfiguredOff,
        );
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
                normalize_detectors_for_matcher_compile(detectors),
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
        return compile_without_matcher_artifact_cache(
            sorted,
            gpu_policy,
            tuning_config,
            MatcherArtifactCacheDisableReason::ConfiguredOff,
        );
    };

    let path = cache_dir.join(identity.cache_filename());
    // When a structurally intact entry is not reusable for this live corpus
    // (hydrate/compile failure after a successful load), do not immediately
    // rewrite the same identity - that would delete+recreate forever.
    let mut allow_store = true;
    let rebuild_outcome = match load_borrowed_matcher_artifact(cache_dir, &identity) {
        Ok(loaded) => {
            let (literal_index, regex_programs, suppression_policy) = loaded.section_bytes();
            match hydrate_matcher_artifact_bytes(
                loaded.ranges.backend,
                literal_index,
                regex_programs,
                suppression_policy,
                detector_digest,
                sorted.as_ref(),
            ) {
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
                if let Err(store_error) = store_matcher_artifact(cache_dir, &identity, &sections) {
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

fn normalize_detectors_for_matcher_compile(
    detectors: Arc<[keyhog_core::DetectorSpec]>,
) -> Arc<[keyhog_core::DetectorSpec]> {
    let mut normalized = detectors.to_vec();
    normalized.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    for detector in &mut normalized {
        detector.tests.clear();
    }
    normalized.into()
}

fn compile_without_matcher_artifact_cache(
    detectors: Arc<[keyhog_core::DetectorSpec]>,
    gpu_policy: GpuInitPolicy,
    tuning_config: &ScannerTuningConfig,
    reason: MatcherArtifactCacheDisableReason,
) -> Result<(CompiledScanner, MatcherArtifactCacheOutcome)> {
    let sorted = match CanonicalDetectorExecutionIr::compile(detectors.as_ref()) {
        Ok(ir) => Arc::from(ir.detectors().to_vec()),
        Err(_) => normalize_detectors_for_matcher_compile(detectors), // LAW10: fallback normalization if canonical IR compilation fails; recall-preserving
    };
    compile_with_matcher_artifact_outcome(
        sorted,
        gpu_policy,
        tuning_config,
        MatcherArtifactCacheOutcome::Disabled { reason },
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
    hydrate_matcher_artifact_bytes(
        sections.backend,
        &sections.literal_index,
        &sections.regex_programs,
        &sections.suppression_policy,
        detector_digest,
        detectors,
    )
}

fn hydrate_matcher_artifact_bytes(
    backend: ExecutionPackBackend,
    literal_index: &[u8],
    regex_programs: &[u8],
    suppression_policy: &[u8],
    detector_digest: [u8; 32],
    detectors: &[keyhog_core::DetectorSpec],
) -> Result<CompileState> {
    // Outer identity/content digests already bind these bytes to the live
    // process (and `--lockdown` disables the cache). Keep the capped artifact
    // buffer alive through decode and borrow its section ranges directly.
    decode_local_matcher_artifact_compile_state_sections(
        backend,
        literal_index,
        regex_programs,
        suppression_policy,
        detector_digest,
        detectors,
    )
    .map_err(|error| ScanError::Config(error.to_string()))
}

#[cfg(test)]
#[path = "../tests/unit/matcher_artifact_cache_inline.rs"]
mod tests;
