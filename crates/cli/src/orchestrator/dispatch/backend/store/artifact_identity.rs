//! Exact identity of the running executable used by persisted calibration.

use sha2::{Digest, Sha256};
use std::io::Read;
use std::sync::{LazyLock, OnceLock};

static GPU_SIDECAR_DIGEST: LazyLock<Option<String>> = LazyLock::new(|| {
    let cache_dir = keyhog_scanner::gpu_literal_artifact_cache_dir().ok()?;
    let entries = std::fs::read_dir(&cache_dir).ok()?;
    let mut bin_files = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|ext| ext == "bin") {
            bin_files.push(path);
        }
    }
    if bin_files.is_empty() {
        return None;
    }
    bin_files.sort();
    let mut hasher = Sha256::new();
    hasher.update(b"gpu_sidecar:");
    let mut buffer = [0u8; 64 * 1024];
    for path in bin_files {
        let filename = path.file_name()?.to_string_lossy();
        hasher.update(filename.as_bytes());
        let mut file = std::fs::File::open(&path).ok()?;
        loop {
            let read = file.read(&mut buffer).ok()?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
    }
    Some(format!("{:x}", hasher.finalize()))
});

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
    GPU_SIDECAR_DIGEST.clone()
}

pub(super) fn current_vyre_artifact_sha256() -> Option<String> {
    current_gpu_sidecar_sha256()
}
