use anyhow::{bail, Context, Result};
use keyhog_scanner::execution_pack::{
    ExecutionPack, ExecutionPackBackend, ExecutionPackPolicy, ExecutionPackSignature,
    ExecutionPackSigningKey,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

/// The exact set of program entry points permitted to compile detector artifacts.
pub const PERMITTED_DETECTOR_COMPILATION_ENTRY_POINTS: &[&str] = &["install", "update"];

/// Exact repair command for missing/unusable execution-pack artifacts.
pub const REPAIR_COMMAND: &str = "keyhog install";

/// Distinct identity input dimensions bound to installed artifact classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub enum ArtifactIdentityInput {
    BinaryDigest,
    TargetHardwareDigest,
    FeatureDigest,
    DetectorCorpusDigest,
    ConfigDigest,
    SigningKeyIdentity,
    GpuDeviceIdentity,
}

impl ArtifactIdentityInput {
    pub const ALL: &[Self] = &[
        Self::BinaryDigest,
        Self::TargetHardwareDigest,
        Self::FeatureDigest,
        Self::DetectorCorpusDigest,
        Self::ConfigDigest,
        Self::SigningKeyIdentity,
        Self::GpuDeviceIdentity,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::BinaryDigest => "binary digest",
            Self::TargetHardwareDigest => "target hardware digest",
            Self::FeatureDigest => "feature digest",
            Self::DetectorCorpusDigest => "detector corpus digest",
            Self::ConfigDigest => "config digest",
            Self::SigningKeyIdentity => "signing key identity",
            Self::GpuDeviceIdentity => "GPU device identity",
        }
    }
}

/// Distinct artifact classes in an execution-pack installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub enum InstalledArtifactClass {
    Manifest,
    VerificationKey,
    ExecutionPack,
    Signature,
    GpuLiteralArtifact,
    AutorouteCalibration,
}

impl InstalledArtifactClass {
    pub const ALL: &[Self] = &[
        Self::Manifest,
        Self::VerificationKey,
        Self::ExecutionPack,
        Self::Signature,
        Self::GpuLiteralArtifact,
        Self::AutorouteCalibration,
    ];

    pub const EXECUTION_PACK_CLASSES: &[Self] = &[
        Self::Manifest,
        Self::VerificationKey,
        Self::ExecutionPack,
        Self::Signature,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Manifest => "execution-pack manifest",
            Self::VerificationKey => "execution-pack verification key",
            Self::ExecutionPack => "execution pack",
            Self::Signature => "execution-pack signature",
            Self::GpuLiteralArtifact => "gpu literal artifact",
            Self::AutorouteCalibration => "autoroute calibration",
        }
    }

    pub const fn file_pattern(self) -> &'static str {
        match self {
            Self::Manifest => "manifest.json",
            Self::VerificationKey => "signing.key",
            Self::ExecutionPack => "*.khpack",
            Self::Signature => "*.sig",
            Self::GpuLiteralArtifact => "*.bin",
            Self::AutorouteCalibration => "autoroute.json",
        }
    }

    pub const fn identity_inputs(self) -> &'static [ArtifactIdentityInput] {
        match self {
            Self::Manifest => &[
                ArtifactIdentityInput::BinaryDigest,
                ArtifactIdentityInput::TargetHardwareDigest,
                ArtifactIdentityInput::FeatureDigest,
                ArtifactIdentityInput::DetectorCorpusDigest,
            ],
            Self::VerificationKey => &[ArtifactIdentityInput::SigningKeyIdentity],
            Self::ExecutionPack => &[
                ArtifactIdentityInput::BinaryDigest,
                ArtifactIdentityInput::TargetHardwareDigest,
                ArtifactIdentityInput::FeatureDigest,
                ArtifactIdentityInput::DetectorCorpusDigest,
                ArtifactIdentityInput::SigningKeyIdentity,
            ],
            Self::Signature => &[
                ArtifactIdentityInput::SigningKeyIdentity,
                ArtifactIdentityInput::BinaryDigest,
                ArtifactIdentityInput::DetectorCorpusDigest,
            ],
            Self::GpuLiteralArtifact => &[
                ArtifactIdentityInput::BinaryDigest,
                ArtifactIdentityInput::DetectorCorpusDigest,
                ArtifactIdentityInput::GpuDeviceIdentity,
            ],
            Self::AutorouteCalibration => &[
                ArtifactIdentityInput::BinaryDigest,
                ArtifactIdentityInput::TargetHardwareDigest,
                ArtifactIdentityInput::FeatureDigest,
                ArtifactIdentityInput::DetectorCorpusDigest,
                ArtifactIdentityInput::ConfigDigest,
                ArtifactIdentityInput::GpuDeviceIdentity,
            ],
        }
    }
    pub const fn is_produced_by_installer(self) -> bool {
        true
    }

    pub const fn is_consumed_by_scan(self) -> bool {
        true
    }
}

/// Unified registry connecting artifact production, update regeneration, and scan loading.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InstalledArtifactRegistry;

impl InstalledArtifactRegistry {
    /// Return all registered artifact classes.
    pub fn all_classes() -> &'static [InstalledArtifactClass] {
        InstalledArtifactClass::ALL
    }

    /// Return the set of all artifact classes produced by the installer.
    pub fn produced_classes() -> BTreeSet<InstalledArtifactClass> {
        InstalledArtifactClass::ALL
            .iter()
            .copied()
            .filter(|class| class.is_produced_by_installer())
            .collect()
    }

    /// Return the set of all artifact classes consumed by the scan path.
    pub fn consumed_classes() -> BTreeSet<InstalledArtifactClass> {
        InstalledArtifactClass::ALL
            .iter()
            .copied()
            .filter(|class| class.is_consumed_by_scan())
            .collect()
    }

    /// Validate bidirectional set equality between produced and consumed classes.
    pub fn assert_bidirectional_registry_equality() -> Result<()> {
        let produced = Self::produced_classes();
        let consumed = Self::consumed_classes();

        if produced != consumed {
            let produced_not_consumed: Vec<_> = produced.difference(&consumed).copied().collect();
            let consumed_not_produced: Vec<_> = consumed.difference(&produced).copied().collect();
            bail!(
                "installed artifact registry set inequality: produced_not_consumed={produced_not_consumed:?}, consumed_not_produced={consumed_not_produced:?}"
            );
        }

        for class in InstalledArtifactClass::ALL {
            if class.identity_inputs().is_empty() {
                bail!("artifact class {:?} has empty identity inputs", class);
            }
        }
        Ok(())
    }

    /// Execute the installer producer loop over every registered artifact class.
    pub fn execute_installer_producer_loop<F>(
        mut producer: F,
    ) -> Result<BTreeSet<InstalledArtifactClass>>
    where
        F: FnMut(InstalledArtifactClass) -> Result<()>,
    {
        let mut produced = BTreeSet::new();
        for &class in Self::all_classes() {
            producer(class).with_context(|| {
                format!("installer producer failed for artifact class {class:?}")
            })?;
            produced.insert(class);
        }
        Ok(produced)
    }

    /// Execute the updater regeneration loop over every registered artifact class.
    pub fn execute_updater_regeneration_loop<F>(
        mut regenerator: F,
    ) -> Result<BTreeSet<InstalledArtifactClass>>
    where
        F: FnMut(InstalledArtifactClass) -> Result<()>,
    {
        let mut regenerated = BTreeSet::new();
        for &class in Self::all_classes() {
            regenerator(class).with_context(|| {
                format!("updater regeneration failed for artifact class {class:?}")
            })?;
            regenerated.insert(class);
        }
        Ok(regenerated)
    }

    /// Execute the scan loader verification loop over every registered artifact class.
    pub fn execute_scan_loader_loop<F>(mut loader: F) -> Result<BTreeSet<InstalledArtifactClass>>
    where
        F: FnMut(InstalledArtifactClass) -> Result<()>,
    {
        let mut loaded = BTreeSet::new();
        for &class in Self::all_classes() {
            loader(class)
                .with_context(|| format!("scan loader failed for artifact class {class:?}"))?;
            loaded.insert(class);
        }
        Ok(loaded)
    }
}

pub(crate) const MANIFEST_VERSION: u16 = 1;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutionPackGenerationBinding {
    pub(crate) manifest_digest: [u8; 32],
    pub(crate) detector_digest: String,
    pub(crate) target_digest: String,
    pub(crate) binary_digest: String,
    pub(crate) feature_digest: String,
    pub(crate) fixture_digest: String,
    pub(crate) packs: Vec<ExecutionPackIdentityBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutionPackIdentityBinding {
    pub(crate) policy: String,
    pub(crate) backend: String,
    pub(crate) file: String,
    pub(crate) signature_file: String,
    pub(crate) identity_digest: String,
    pub(crate) content_digest: String,
    pub(crate) signed_pack_digest: String,
    pub(crate) bytes: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstallPackManifest {
    pub(crate) version: u16,
    pub(crate) detector_digest: String,
    pub(crate) target_digest: String,
    pub(crate) binary_digest: String,
    pub(crate) feature_digest: String,
    pub(crate) fixture_digest: String,
    pub(crate) packs: Vec<ExecutionPackIdentityBinding>,
}

pub(crate) fn installed_execution_pack_directory() -> Result<PathBuf> {
    Ok(dirs::cache_dir()
        .context("platform cache directory is unavailable")?
        .join("keyhog")
        .join("execution-packs")
        .join("current"))
}

pub fn current_binary_digest() -> Result<[u8; 32]> {
    #[cfg(target_os = "linux")]
    let mut file = File::open("/proc/self/exe").or_else(|_| {
        let path = std::env::current_exe().context("resolving current KeyHog executable")?;
        File::open(&path).with_context(|| format!("opening {}", path.display()))
    })?;
    #[cfg(not(target_os = "linux"))]
    let mut file = {
        let path = std::env::current_exe().context("resolving current KeyHog executable")?;
        File::open(&path).with_context(|| format!("opening {}", path.display()))?
    };
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .context("hashing current executable image")?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(crate) fn current_target_digest() -> [u8; 32] {
    let hardware = keyhog_scanner::hw_probe::probe_host_hardware();
    let physical_cores = hardware.physical_cores.to_le_bytes();
    let logical_cores = hardware.logical_cores.to_le_bytes();
    let feature_flags = [
        u8::from(hardware.has_avx2),
        u8::from(hardware.has_avx512),
        u8::from(hardware.has_neon),
        u8::from(hardware.hyperscan_available),
    ];
    let total_memory_mb = hardware.total_memory_mb.unwrap_or_default().to_le_bytes(); // LAW10: absent optional memory metadata is disambiguated by the adjacent presence flag in this hardware digest.
    let option_flags = [
        u8::from(hardware.total_memory_mb.is_some()),
        u8::from(hardware.hyperscan_runtime_identity.is_some()),
    ];
    // Source and accelerator health are deliberately excluded. io_uring is a
    // transient acquisition probe, while every VYRE pack authenticates its own
    // exact runtime, driver, device, and hardware-limit identity. Binding either
    // here made unrelated CPU/SIMD packs alternate between valid and stale.
    digest_parts(&[
        b"keyhog-execution-pack-target-v2",
        std::env::consts::OS.as_bytes(),
        std::env::consts::ARCH.as_bytes(),
        &physical_cores,
        &logical_cores,
        &feature_flags,
        &option_flags,
        &total_memory_mb,
        hardware
            .hyperscan_runtime_identity
            .as_deref()
            .unwrap_or_default() // LAW10: absent optional runtime identity is disambiguated by the adjacent presence flag in this hardware digest.
            .as_bytes(),
    ])
}

pub(crate) fn current_feature_digest() -> [u8; 32] {
    digest_parts(&[
        if cfg!(feature = "simd") {
            b"simd=1"
        } else {
            b"simd=0"
        },
        if cfg!(feature = "gpu") {
            b"gpu=1"
        } else {
            b"gpu=0"
        },
        env!("CARGO_PKG_VERSION").as_bytes(),
    ])
}

fn digest_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// Status of installed artifact freshness across all identity dimensions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactFreshnessStatus {
    Fresh,
    Missing {
        detail: String,
    },
    Stale {
        dimension: ArtifactIdentityInput,
        actual: String,
        expected: String,
    },
}

pub fn current_embedded_detector_digest() -> Result<[u8; 32]> {
    static EMBEDDED_DIGEST: std::sync::LazyLock<Result<[u8; 32], String>> =
        std::sync::LazyLock::new(|| {
            let detectors = keyhog_core::load_embedded_detectors_or_fail().map_err(|e| {
                format!("loading embedded detectors for execution-pack detector digest: {e}")
            })?;
            let ir =
                keyhog_scanner::execution_pack::CanonicalDetectorExecutionIr::compile(&detectors)
                    .map_err(|e| {
                    format!("compiling canonical detector execution IR for digest: {e}")
                })?;
            Ok(ir.digest())
        });
    (*EMBEDDED_DIGEST).clone().map_err(anyhow::Error::msg)
}
/// Invalidate installed execution packs and autoroute cache due to an identity change.
pub fn invalidate_installed_artifacts(reason: &str) -> Result<()> {
    invalidate_installed_artifacts_at(dirs::cache_dir().as_deref(), reason)
}

/// Invalidate installed execution packs and autoroute cache under a specific base cache directory.
pub fn invalidate_installed_artifacts_at(
    base_cache_dir: Option<&Path>,
    reason: &str,
) -> Result<()> {
    tracing::info!(reason = %reason, "invalidating installed execution-pack artifacts");
    let cache_dir = match base_cache_dir {
        Some(dir) => dir.to_path_buf(),
        None => match dirs::cache_dir() {
            Some(dir) => dir,
            None => return Ok(()),
        },
    };
    let directory = cache_dir
        .join("keyhog")
        .join("execution-packs")
        .join("current");
    if directory.exists() {
        if let Err(error) = fs::remove_dir_all(&directory) {
            tracing::warn!(
                error = %error,
                "failed to remove stale execution-pack directory {}",
                directory.display()
            );
        }
    }
    let autoroute_cache = cache_dir.join("keyhog").join("autoroute.json");
    if autoroute_cache.exists() {
        if let Err(error) = fs::remove_file(&autoroute_cache) {
            tracing::warn!(
                error = %error,
                "failed to remove stale autoroute cache {}",
                autoroute_cache.display()
            );
        }
    }
    Ok(())
}

/// Check the freshness of installed artifacts against current binary, target hardware,
/// cargo features, and detector corpus.
pub fn check_installed_artifacts_freshness() -> Result<ArtifactFreshnessStatus> {
    check_installed_artifacts_freshness_at(dirs::cache_dir().as_deref())
}

/// Check the freshness of installed artifacts under a specific base cache directory.
pub fn check_installed_artifacts_freshness_at(
    base_cache_dir: Option<&Path>,
) -> Result<ArtifactFreshnessStatus> {
    let cache_dir = match base_cache_dir {
        Some(dir) => dir.to_path_buf(),
        None => match dirs::cache_dir() {
            Some(dir) => dir,
            None => {
                return Ok(ArtifactFreshnessStatus::Missing {
                    detail: "platform cache directory is unavailable".to_string(),
                })
            }
        },
    };
    let directory = cache_dir
        .join("keyhog")
        .join("execution-packs")
        .join("current");
    let manifest_path = directory.join("manifest.json");
    if !manifest_path.exists() {
        return Ok(ArtifactFreshnessStatus::Missing {
            detail: format!("manifest {} does not exist", manifest_path.display()),
        });
    }
    let bytes = match fs::read(&manifest_path) {
        Ok(b) => b,
        Err(err) => {
            return Ok(ArtifactFreshnessStatus::Missing {
                detail: err.to_string(),
            })
        }
    };
    let manifest: InstallPackManifest = match serde_json::from_slice(&bytes) {
        Ok(m) => m,
        Err(err) => {
            return Ok(ArtifactFreshnessStatus::Missing {
                detail: err.to_string(),
            })
        }
    };

    let binary_expected = keyhog_core::hex_encode(&current_binary_digest()?);
    if manifest.binary_digest != binary_expected {
        return Ok(ArtifactFreshnessStatus::Stale {
            dimension: ArtifactIdentityInput::BinaryDigest,
            actual: manifest.binary_digest,
            expected: binary_expected,
        });
    }

    let target_expected = keyhog_core::hex_encode(&current_target_digest());
    if manifest.target_digest != target_expected {
        return Ok(ArtifactFreshnessStatus::Stale {
            dimension: ArtifactIdentityInput::TargetHardwareDigest,
            actual: manifest.target_digest,
            expected: target_expected,
        });
    }

    let feature_expected = keyhog_core::hex_encode(&current_feature_digest());
    if manifest.feature_digest != feature_expected {
        return Ok(ArtifactFreshnessStatus::Stale {
            dimension: ArtifactIdentityInput::FeatureDigest,
            actual: manifest.feature_digest,
            expected: feature_expected,
        });
    }

    let detector_expected = keyhog_core::hex_encode(&current_embedded_detector_digest()?);
    if manifest.detector_digest != detector_expected {
        return Ok(ArtifactFreshnessStatus::Stale {
            dimension: ArtifactIdentityInput::DetectorCorpusDigest,
            actual: manifest.detector_digest,
            expected: detector_expected,
        });
    }

    Ok(ArtifactFreshnessStatus::Fresh)
}

pub(crate) fn load_installed_execution_pack(
    policy: ExecutionPackPolicy,
    backend: ExecutionPackBackend,
) -> Result<ExecutionPack> {
    let directory = installed_execution_pack_directory()?;
    let (_, manifest, signing_key) = load_manifest(&directory)?;
    let row = manifest
        .packs
        .iter()
        .find(|row| {
            row.policy == policy.lowercase_name() && row.backend == backend.lowercase_name()
        })
        .with_context(|| {
            format!(
                "installed generation has no {} {} execution pack. Fix: run `keyhog install` or `keyhog update`",
                policy.lowercase_name(),
                backend.lowercase_name(),
            )
        })?;
    authenticate_manifest_pack(&directory, &manifest, row, &signing_key)
}
pub(crate) fn load_installed_preferred_matcher_pack(
    policy: ExecutionPackPolicy,
) -> Result<ExecutionPack> {
    let directory = installed_execution_pack_directory()?;
    let (_, manifest, signing_key) = load_manifest(&directory)?;
    let policy = policy.lowercase_name();
    let row = manifest
        .packs
        .iter()
        .find(|row| row.policy == policy && row.backend == "simd")
        .or_else(|| {
            manifest
                .packs
                .iter()
                .find(|row| row.policy == policy && row.backend == "cpu")
        })
        .with_context(|| {
            format!("installed generation has no {policy} SIMD or CPU execution pack. Fix: run `keyhog install` or `keyhog update`")
        })?;
    authenticate_manifest_pack(&directory, &manifest, row, &signing_key)
}

pub(crate) fn load_installed_detector_execution_pack_for_backend(
    policy: ExecutionPackPolicy,
    backend: ExecutionPackBackend,
) -> Result<ExecutionPack> {
    load_installed_execution_pack(policy, backend)
}
pub(crate) fn load_installed_preferred_detector_execution_pack(
    policy: ExecutionPackPolicy,
) -> Result<ExecutionPack> {
    load_installed_preferred_matcher_pack(policy)
}

pub(crate) fn load_authenticated_binding(
    directory: &Path,
) -> Result<ExecutionPackGenerationBinding> {
    let (bytes, manifest, signing_key) = load_manifest(directory)?;
    let mut identities = BTreeSet::new();
    for row in &manifest.packs {
        if !identities.insert((row.policy.as_str(), row.backend.as_str())) {
            bail!(
                "execution-pack manifest repeats policy {} backend {}",
                row.policy,
                row.backend
            );
        }
        let _pack = authenticate_manifest_pack(directory, &manifest, row, &signing_key)?;
    }
    Ok(ExecutionPackGenerationBinding {
        manifest_digest: *blake3::hash(&bytes).as_bytes(),
        detector_digest: manifest.detector_digest,
        target_digest: manifest.target_digest,
        binary_digest: manifest.binary_digest,
        feature_digest: manifest.feature_digest,
        fixture_digest: manifest.fixture_digest,
        packs: manifest.packs,
    })
}

fn load_manifest(
    directory: &Path,
) -> Result<(Vec<u8>, InstallPackManifest, ExecutionPackSigningKey)> {
    let manifest_path = directory.join("manifest.json");
    let metadata = fs::symlink_metadata(&manifest_path).with_context(|| {
        format!(
            "inspecting execution-pack manifest {}. Fix: run `keyhog install` or `keyhog update`",
            manifest_path.display()
        )
    })?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_MANIFEST_BYTES
    {
        bail!(
            "execution-pack manifest {} must be a nonempty regular file no larger than {MAX_MANIFEST_BYTES} bytes. Fix: run `keyhog install` or `keyhog update`",
            manifest_path.display()
        );
    }
    let bytes = fs::read(&manifest_path).with_context(|| {
        format!(
            "reading execution-pack manifest {}. Fix: run `keyhog install` or `keyhog update`",
            manifest_path.display()
        )
    })?;
    let manifest: InstallPackManifest = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "parsing execution-pack manifest {}. Fix: run `keyhog install` or `keyhog update`",
            manifest_path.display()
        )
    })?;
    if manifest.version != MANIFEST_VERSION {
        bail!(
            "execution-pack manifest version {} is unsupported; reinstall with version {MANIFEST_VERSION}. Fix: run `keyhog install` or `keyhog update`",
            manifest.version
        );
    }
    if manifest.packs.is_empty() {
        bail!("execution-pack manifest contains no packs. Fix: run `keyhog install` or `keyhog update`");
    }
    let embedded_detectors = keyhog_core::load_embedded_detectors_or_fail()
        .context("loading embedded detectors for execution-pack verification")?;
    let embedded_ir =
        keyhog_scanner::execution_pack::CanonicalDetectorExecutionIr::compile(&embedded_detectors)
            .map_err(anyhow::Error::msg)
            .context("compiling canonical detector execution IR for verification")?;
    let expected_detector_digest = keyhog_core::hex_encode(&embedded_ir.digest());
    let current_binary = keyhog_core::hex_encode(&current_binary_digest()?);
    let current_target = keyhog_core::hex_encode(&current_target_digest());
    let current_feature = keyhog_core::hex_encode(&current_feature_digest());

    for (name, actual, expected) in [
        (
            "detector",
            manifest.detector_digest.as_str(),
            expected_detector_digest.as_str(),
        ),
        (
            "binary",
            manifest.binary_digest.as_str(),
            current_binary.as_str(),
        ),
        (
            "target",
            manifest.target_digest.as_str(),
            current_target.as_str(),
        ),
        (
            "feature",
            manifest.feature_digest.as_str(),
            current_feature.as_str(),
        ),
    ] {
        if actual != expected {
            bail!(
                "execution-pack manifest identity for '{name}' is stale (manifest {actual}, host {expected}); \
                 rebuild packs with this binary before scanning. Fix: run `keyhog install` or `keyhog update`"
            );
        }
    }
    let key_path = directory
        .parent()
        .map(|parent| parent.join("signing.key"))
        .context("execution-pack generation has no installation root. Fix: run `keyhog install` or `keyhog update`")?;
    let key_bytes = fs::read(&key_path).with_context(|| {
        format!(
            "reading execution-pack verification key {}. Fix: run `keyhog install` or `keyhog update`",
            key_path.display()
        )
    })?;
    let signing_key = ExecutionPackSigningKey::from_bytes(key_bytes.try_into().map_err(|_| {
        anyhow::anyhow!("execution-pack verification key must be exactly 32 bytes. Fix: run `keyhog install` or `keyhog update`")
    })?)
    .map_err(anyhow::Error::msg)?;
    Ok((bytes, manifest, signing_key))
}

fn authenticate_manifest_pack(
    directory: &Path,
    manifest: &InstallPackManifest,
    row: &ExecutionPackIdentityBinding,
    signing_key: &ExecutionPackSigningKey,
) -> Result<ExecutionPack> {
    validate_filename(&row.file)?;
    validate_filename(&row.signature_file)?;
    let pack_path = directory.join(&row.file);
    let signature_path = directory.join(&row.signature_file);
    let metadata = fs::symlink_metadata(&pack_path).with_context(|| {
        format!(
            "inspecting execution pack {}. Fix: run `keyhog install` or `keyhog update`",
            pack_path.display()
        )
    })?;
    if !metadata.file_type().is_file() || metadata.len() != row.bytes as u64 {
        bail!(
            "execution pack {} has {} bytes, manifest requires {}. Fix: run `keyhog install` or `keyhog update`",
            pack_path.display(),
            metadata.len(),
            row.bytes
        );
    }
    let sig_metadata = fs::symlink_metadata(&signature_path).with_context(|| {
        format!(
            "inspecting execution-pack signature {}. Fix: run `keyhog install` or `keyhog update`",
            signature_path.display()
        )
    })?;
    if !sig_metadata.file_type().is_file() || sig_metadata.len() == 0 {
        bail!(
            "execution-pack signature {} is missing or empty. Fix: run `keyhog install` or `keyhog update`",
            signature_path.display()
        );
    }
    let pack = ExecutionPack::open_authenticated_discover(&pack_path, &signature_path, signing_key)
        .map_err(anyhow::Error::msg)
        .with_context(|| {
            format!(
                "authenticating execution pack {}. Fix: run `keyhog install` or `keyhog update`",
                pack_path.display()
            )
        })?;
    let identity = pack.identity();
    for (name, actual, expected) in [
        (
            "detector",
            keyhog_core::hex_encode(&identity.detector_digest),
            manifest.detector_digest.as_str(),
        ),
        (
            "target",
            keyhog_core::hex_encode(&identity.target_digest),
            manifest.target_digest.as_str(),
        ),
        (
            "binary",
            keyhog_core::hex_encode(&identity.binary_digest),
            manifest.binary_digest.as_str(),
        ),
        (
            "feature",
            keyhog_core::hex_encode(&identity.feature_digest),
            manifest.feature_digest.as_str(),
        ),
        (
            "identity",
            keyhog_core::hex_encode(&identity.digest()),
            row.identity_digest.as_str(),
        ),
        (
            "content",
            keyhog_core::hex_encode(&pack.content_digest()),
            row.content_digest.as_str(),
        ),
    ] {
        if actual != expected {
            bail!(
                "execution pack {} '{name}' identity does not match its manifest. Fix: run `keyhog install` or `keyhog update`",
                pack_path.display()
            );
        }
    }
    if identity.policy.lowercase_name() != row.policy
        || identity.backend.lowercase_name() != row.backend
    {
        bail!(
            "execution pack {} 'policy/backend' identity does not match its manifest. Fix: run `keyhog install` or `keyhog update`",
            pack_path.display()
        );
    }
    let signature_bytes = fs::read(&signature_path).with_context(|| {
        format!(
            "reading execution-pack signature {}. Fix: run `keyhog install` or `keyhog update`",
            signature_path.display()
        )
    })?;
    let signature = ExecutionPackSignature::decode(&signature_bytes).map_err(anyhow::Error::msg)?;
    if keyhog_core::hex_encode(&signature.pack_digest) != row.signed_pack_digest {
        bail!(
            "execution-pack signature {} signed digest does not match its manifest identity. Fix: run `keyhog install` or `keyhog update`",
            pack_path.display()
        );
    }
    Ok(pack)
}

fn validate_filename(name: &str) -> Result<()> {
    let path = PathBuf::from(name);
    if name.is_empty() || path.file_name().and_then(|value| value.to_str()) != Some(name) {
        bail!("execution-pack manifest filename {name:?} is not a single safe path component");
    }
    Ok(())
}
