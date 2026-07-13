//! Exact identity of the running executable used by persisted calibration.

use sha2::{Digest, Sha256};
use std::io::Read;
use std::sync::OnceLock;

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
