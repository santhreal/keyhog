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

pub(crate) fn current_binary_digest() -> Result<[u8; 32]> {
    let path = std::env::current_exe().context("resolving current KeyHog executable")?;
    let mut file = File::open(&path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("hashing {}", path.display()))?;
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
                "installed generation has no {} {} execution pack",
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
            format!("installed generation has no {policy} SIMD or CPU execution pack")
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
            "inspecting execution-pack manifest {}",
            manifest_path.display()
        )
    })?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_MANIFEST_BYTES
    {
        bail!(
            "execution-pack manifest {} must be a nonempty regular file no larger than {MAX_MANIFEST_BYTES} bytes",
            manifest_path.display()
        );
    }
    let bytes = fs::read(&manifest_path).with_context(|| {
        format!(
            "reading execution-pack manifest {}",
            manifest_path.display()
        )
    })?;
    let manifest: InstallPackManifest = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "parsing execution-pack manifest {}",
            manifest_path.display()
        )
    })?;
    if manifest.version != MANIFEST_VERSION {
        bail!(
            "execution-pack manifest version {} is unsupported; reinstall with version {MANIFEST_VERSION}",
            manifest.version
        );
    }
    if manifest.packs.is_empty() {
        bail!("execution-pack manifest contains no packs");
    }
    for (name, actual, expected) in [
        (
            "binary",
            manifest.binary_digest.as_str(),
            keyhog_core::hex_encode(&current_binary_digest()?),
        ),
        (
            "target",
            manifest.target_digest.as_str(),
            keyhog_core::hex_encode(&current_target_digest()),
        ),
        (
            "feature",
            manifest.feature_digest.as_str(),
            keyhog_core::hex_encode(&current_feature_digest()),
        ),
    ] {
        if actual != expected {
            bail!(
                "execution-pack {name} identity is stale (manifest {actual}, host {expected}); \
                 rebuild packs with this binary before calibration"
            );
        }
    }
    let key_path = directory
        .parent()
        .map(|parent| parent.join("signing.key"))
        .context("execution-pack generation has no installation root")?;
    let key_bytes = fs::read(&key_path).with_context(|| {
        format!(
            "reading execution-pack verification key {}",
            key_path.display()
        )
    })?;
    let signing_key = ExecutionPackSigningKey::from_bytes(key_bytes.try_into().map_err(|_| {
        anyhow::anyhow!("execution-pack verification key must be exactly 32 bytes")
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
    let metadata = fs::symlink_metadata(&pack_path)
        .with_context(|| format!("inspecting execution pack {}", pack_path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() != row.bytes as u64 {
        bail!(
            "execution pack {} has {} bytes, manifest requires {}",
            pack_path.display(),
            metadata.len(),
            row.bytes
        );
    }
    let pack = ExecutionPack::open_authenticated_discover(&pack_path, &signature_path, signing_key)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("authenticating execution pack {}", pack_path.display()))?;
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
                "execution pack {} {name} identity does not match its manifest",
                pack_path.display()
            );
        }
    }
    if identity.policy.lowercase_name() != row.policy
        || identity.backend.lowercase_name() != row.backend
    {
        bail!(
            "execution pack {} policy/backend identity does not match its manifest",
            pack_path.display()
        );
    }
    let signature_bytes = fs::read(&signature_path).with_context(|| {
        format!(
            "reading execution-pack signature {}",
            signature_path.display()
        )
    })?;
    let signature = ExecutionPackSignature::decode(&signature_bytes).map_err(anyhow::Error::msg)?;
    if keyhog_core::hex_encode(&signature.pack_digest) != row.signed_pack_digest {
        bail!(
            "execution pack {} signed digest does not match its manifest identity",
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
