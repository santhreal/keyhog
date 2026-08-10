//! Exact identity of the running executable used by persisted calibration.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Component, Path};
use std::sync::OnceLock;

const INSTALLED_MANIFEST_BYTES: u64 = 1024 * 1024;
const INSTALLED_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
const INSTALLED_ARTIFACT_COUNT: usize = 64;

fn read_bounded(path: &Path, limit: u64) -> Option<Vec<u8>> {
    let mut file = std::fs::File::open(path).ok()?;
    let declared_len = file.metadata().ok()?.len();
    if declared_len > limit {
        return None;
    }
    let mut bytes = Vec::with_capacity(usize::try_from(declared_len).ok()?);
    file.by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    (u64::try_from(bytes.len()).ok()? <= limit).then_some(bytes)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledGpuArtifactManifest {
    version: u32,
    artifacts: Vec<InstalledGpuArtifactEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledGpuArtifactEntry {
    file_name: String,
    sha256: String,
}

pub(crate) fn installed_gpu_sidecar_digest(cache_dir: &Path) -> Option<String> {
    let manifest_path = cache_dir.join(".installed_manifest.json");
    let manifest_metadata = std::fs::symlink_metadata(&manifest_path).ok()?;
    if !manifest_metadata.file_type().is_file()
        || manifest_metadata.len() > INSTALLED_MANIFEST_BYTES
    {
        return None;
    }
    let manifest: InstalledGpuArtifactManifest =
        serde_json::from_slice(&read_bounded(&manifest_path, INSTALLED_MANIFEST_BYTES)?).ok()?;
    if manifest.version != 1
        || manifest.artifacts.is_empty()
        || manifest.artifacts.len() > INSTALLED_ARTIFACT_COUNT
    {
        return None;
    }

    let mut entries = manifest.artifacts;
    entries.sort_by(|left, right| left.file_name.cmp(&right.file_name));
    let mut names = BTreeSet::new();
    let mut identity = Sha256::new();
    identity.update(b"gpu_installed_manifest_v1:");
    let mut buffer = [0u8; 64 * 1024];
    for entry in entries {
        let name = Path::new(&entry.file_name);
        if name.components().count() != 1
            || !matches!(name.components().next(), Some(Component::Normal(_)))
            || !entry.file_name.ends_with(".bin")
            || !names.insert(entry.file_name.clone())
            || entry.sha256.len() != 64
        {
            return None;
        }
        let path = cache_dir.join(&entry.file_name);
        let metadata = std::fs::symlink_metadata(&path).ok()?;
        if !metadata.file_type().is_file() || metadata.len() > INSTALLED_ARTIFACT_BYTES {
            return None;
        }
        let mut file = std::fs::File::open(path).ok()?;
        let mut artifact = Sha256::new();
        let mut artifact_bytes = 0u64;
        loop {
            let read = file.read(&mut buffer).ok()?;
            if read == 0 {
                break;
            }
            artifact.update(&buffer[..read]);
            artifact_bytes = artifact_bytes.saturating_add(read as u64);
            if artifact_bytes > INSTALLED_ARTIFACT_BYTES {
                return None;
            }
        }
        let actual = artifact.finalize();
        let actual_hex = format!("{actual:x}");
        if !actual_hex.eq_ignore_ascii_case(&entry.sha256) {
            return None;
        }
        identity.update((entry.file_name.len() as u64).to_le_bytes());
        identity.update(entry.file_name.as_bytes());
        identity.update(actual);
    }
    Some(format!("{:x}", identity.finalize()))
}

pub(super) fn current_executable_sha256(
) -> Result<&'static str, Box<dyn std::error::Error + Send + Sync>> {
    static DIGEST: OnceLock<Result<String, String>> = OnceLock::new();
    DIGEST
        .get_or_init(|| {
            let path = std::env::current_exe().map_err(|error| {
                format!("locate running executable for autoroute identity: {error}")
            })?;
            let mut file = std::fs::File::open(&path).map_err(|error| {
                format!(
                    "open running executable {} for autoroute identity: {error}",
                    path.display()
                )
            })?;
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 128 * 1024];
            loop {
                let read = file.read(&mut buffer).map_err(|error| {
                    format!(
                        "read running executable {} for autoroute identity: {error}",
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
        .as_deref()
        .map_err(|error| error.clone().into())
}
pub(super) fn current_gpu_sidecar_sha256() -> Option<String> {
    let cache_dir = keyhog_scanner::gpu_literal_artifact_cache_dir().ok()?;
    installed_gpu_sidecar_digest(&cache_dir)
}
