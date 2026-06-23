use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn calibration_store_digest(calibration: &keyhog_core::Calibration) -> u64 {
    let mut hasher = crate::stable_hash::StableHasher::new("calibration-store-digest");
    let entries = calibration.entries();
    hasher.field_usize("entries.len", entries.len());
    for (id, counters) in entries {
        hasher.field_str("detector.id", &id);
        hasher.field_u64("detector.alpha", counters.alpha as u64);
        hasher.field_u64("detector.beta", counters.beta as u64);
    }
    hasher.finish_u64()
}

pub(super) fn load_explicit_scan_calibration(
    path: Option<&Path>,
) -> Result<(
    Option<PathBuf>,
    Option<Arc<keyhog_core::Calibration>>,
    usize,
    u64,
)> {
    let Some(path) = path else {
        return Ok((None, None, 0, 0));
    };
    if path.is_dir() {
        anyhow::bail!(
            "calibration cache path '{}' is a directory. \
             Fix: pass a file path or remove --calibration-cache for a hermetic scan.",
            path.display()
        );
    }
    let calibration = match keyhog_core::Calibration::try_load(path) {
        Ok(Some(calibration)) => calibration,
        Ok(None) => {
            anyhow::bail!(
                "calibration cache '{}' does not exist. \
                 Fix: run `keyhog calibrate --cache '{}' --tp <detector-id>` or remove \
                 --calibration-cache for a hermetic scan.",
                path.display(),
                path.display()
            );
        }
        Err(error) => {
            anyhow::bail!(
                "{error}. Fix: repair or remove the cache, rerun `keyhog calibrate --cache '{}'`, \
                 or remove --calibration-cache for a hermetic scan.",
                path.display()
            );
        }
    };
    let entry_count = calibration.entries().len();
    let digest = calibration_store_digest(&calibration);
    Ok((
        Some(path.to_path_buf()),
        Some(Arc::new(calibration)),
        entry_count,
        digest,
    ))
}
