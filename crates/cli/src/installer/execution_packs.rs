use anyhow::{bail, Context, Result};
use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A published self-update generation. Dropping it before `commit` restores the
/// exact packs, calibration cache, and installation key that preceded it.

struct NewSigningKey(Option<PathBuf>);

impl Drop for NewSigningKey {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            if let Err(error) = remove_regular_file_if_present(&path) {
                tracing::error!(error = %error, "failed to remove uncommitted execution-pack signing key");
            }
        }
    }
}

pub(crate) struct ExecutionGenerationInstallTransaction {
    current_packs: PathBuf,
    current_cache: PathBuf,
    old_packs: PathBuf,
    old_cache: PathBuf,
    _stage: Option<tempfile::TempDir>,
    packs_published: bool,
    cache_published: bool,
    had_old_packs: bool,
    had_old_cache: bool,
    created_signing_key: Option<PathBuf>,
    committed: bool,
}

impl ExecutionGenerationInstallTransaction {
    pub(crate) fn commit(mut self) {
        self.committed = true;
    }

    pub(crate) fn is_committed(&self) -> bool {
        self.committed
    }
    fn rollback(&mut self) -> Result<()> {
        if self.cache_published {
            remove_regular_file_if_present(&self.current_cache)?;
            self.cache_published = false;
        }
        if self.had_old_cache && self.old_cache.exists() {
            fs::rename(&self.old_cache, &self.current_cache).with_context(|| {
                format!("restoring autoroute cache {}", self.current_cache.display())
            })?;
        }
        if self.packs_published {
            remove_directory_if_present(&self.current_packs)?;
            self.packs_published = false;
        }
        if self.had_old_packs && self.old_packs.exists() {
            fs::rename(&self.old_packs, &self.current_packs).with_context(|| {
                format!("restoring execution packs {}", self.current_packs.display())
            })?;
        }
        if let Some(path) = self.created_signing_key.take() {
            remove_regular_file_if_present(&path)?;
        }
        Ok(())
    }
}

impl Drop for ExecutionGenerationInstallTransaction {
    fn drop(&mut self) {
        if !self.committed {
            if let Err(error) = self.rollback() {
                tracing::error!(error = %error, "self-update execution-generation rollback failed");
            }
        }
    }
}

/// Compile, authenticate, calibrate, and publish the candidate binary's exact
/// execution generation. The returned guard must be committed only after every
/// other self-update health gate succeeds.
pub(crate) fn install_execution_generation(
    candidate: &Path,
) -> Result<ExecutionGenerationInstallTransaction> {
    let probe = Command::new(candidate)
        .arg("compile-execution-packs")
        .arg("--help")
        .output()
        .with_context(|| {
            format!(
                "executing candidate binary {} to probe execution-pack capabilities",
                candidate.display()
            )
        })?;
    if !probe.status.success() {
        // Candidate binary genuinely lacks compile-execution-packs (legacy version).
        // Surface warning loudly. We do not stage or publish packs, but we preserve existing
        // artifacts in place so rollbacks remain valid if the candidate fails later health gates.
        eprintln!(
            "warning: candidate binary {} does not support compile-execution-packs; skipping generation compilation",
            candidate.display()
        );
        return Ok(ExecutionGenerationInstallTransaction {
            current_packs: PathBuf::new(),
            current_cache: PathBuf::new(),
            old_packs: PathBuf::new(),
            old_cache: PathBuf::new(),
            _stage: None,
            packs_published: false,
            cache_published: false,
            had_old_packs: false,
            had_old_cache: false,
            created_signing_key: None,
            committed: true,
        });
    }
    let cache_root = dirs::cache_dir()
        .context("platform cache directory is unavailable; cannot publish execution packs")?
        .join("keyhog");
    let pack_root = cache_root.join("execution-packs");
    fs::create_dir_all(&pack_root)
        .with_context(|| format!("creating execution-pack root {}", pack_root.display()))?;
    reject_symlink_or_non_directory(&cache_root)?;
    reject_symlink_or_non_directory(&pack_root)?;

    let signing_key = pack_root.join("signing.key");
    let mut new_signing_key =
        NewSigningKey(ensure_signing_key(&signing_key)?.then_some(signing_key.clone()));
    let stage = tempfile::Builder::new()
        .prefix(".execution-generation-")
        .tempdir_in(&cache_root)
        .with_context(|| {
            format!(
                "creating update generation stage in {}",
                cache_root.display()
            )
        })?;
    let staged_packs = stage.path().join("packs");
    let staged_cache = stage.path().join("autoroute.json");
    run_candidate(
        candidate,
        &[
            "compile-execution-packs",
            "--output-dir",
            path_utf8(&staged_packs)?,
            "--signing-key",
            path_utf8(&signing_key)?,
        ],
        "execution-pack compilation",
    )?;
    run_candidate(
        candidate,
        &[
            "calibrate-autoroute",
            "--quiet",
            "--autoroute-cache",
            path_utf8(&staged_cache)?,
            "--execution-packs",
            path_utf8(&staged_packs)?,
        ],
        "pack-bound autoroute calibration",
    )?;

    let current_packs = pack_root.join("current");
    let current_cache = cache_root.join("autoroute.json");
    let old_packs = stage.path().join("previous-packs");
    let old_cache = stage.path().join("previous-autoroute.json");
    let had_old_packs = path_lexists(&current_packs)?;
    let had_old_cache = path_lexists(&current_cache)?;
    if had_old_packs {
        reject_symlink_or_non_directory(&current_packs)?;
    }
    if had_old_cache {
        reject_symlink_or_non_file(&current_cache)?;
    }

    let mut transaction = ExecutionGenerationInstallTransaction {
        current_packs,
        current_cache,
        old_packs,
        old_cache,
        _stage: Some(stage),
        packs_published: false,
        cache_published: false,
        had_old_packs,
        had_old_cache,
        created_signing_key: new_signing_key.0.take(),
        committed: false,
    };
    if transaction.had_old_packs {
        fs::rename(&transaction.current_packs, &transaction.old_packs)
            .context("backing up current execution-pack generation")?;
    }
    fs::rename(&staged_packs, &transaction.current_packs)
        .context("publishing candidate execution-pack generation")?;
    transaction.packs_published = true;

    if transaction.had_old_cache {
        fs::rename(&transaction.current_cache, &transaction.old_cache)
            .context("backing up current autoroute cache")?;
    }
    if staged_cache.exists() {
        reject_symlink_or_non_file(&staged_cache)?;
        fs::rename(&staged_cache, &transaction.current_cache)
            .context("publishing candidate autoroute cache")?;
        transaction.cache_published = true;
    }
    Ok(transaction)
}

#[allow(dead_code)]
/// Invalidate the current installed execution-pack generation and autoroute cache.
pub(crate) fn invalidate_installed_execution_generation() -> Result<()> {
    let cache_root = match dirs::cache_dir() {
        Some(dir) => dir.join("keyhog"),
        None => return Ok(()),
    };
    let current_packs = cache_root.join("execution-packs").join("current");
    let current_cache = cache_root.join("autoroute.json");
    remove_directory_if_present(&current_packs)?;
    remove_regular_file_if_present(&current_cache)?;
    Ok(())
}

#[allow(dead_code)]
/// Regenerate the installed execution-pack generation and autoroute calibration.
pub(crate) fn regenerate_installed_execution_generation(
    candidate: &Path,
) -> Result<ExecutionGenerationInstallTransaction> {
    install_execution_generation(candidate)
}
fn run_candidate(candidate: &Path, args: &[&str], phase: &str) -> Result<()> {
    let output = Command::new(candidate)
        .args(args)
        .output()
        .with_context(|| format!("starting candidate {phase}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "candidate {phase} failed with {}: {}",
            output.status,
            stderr.trim()
        );
    }
    Ok(())
}

fn ensure_signing_key(path: &Path) -> Result<bool> {
    if path.exists() {
        reject_symlink_or_non_file(path)?;
        let metadata = fs::metadata(path)?;
        if metadata.len() != 32 {
            bail!(
                "execution-pack signing key {} must be exactly 32 bytes",
                path.display()
            );
        }
        return Ok(false);
    }
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating execution-pack signing key {}", path.display()))?;
    use std::io::Write;
    if let Err(error) = file.write_all(&key).and_then(|()| file.sync_all()) {
        key.fill(0);
        let _ = fs::remove_file(path); // LAW10: best-effort removal cannot hide the signing-key persistence error returned immediately below.
        return Err(error).context("persisting execution-pack signing key");
    }
    key.fill(0);
    Ok(true)
}

fn path_utf8(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("installer path is not UTF-8: {}", path.display()))
}

fn path_lexists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

fn reject_symlink_or_non_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspecting installer directory {}", path.display()))?;
    if !metadata.file_type().is_dir() {
        bail!("installer path {} must be a real directory", path.display());
    }
    Ok(())
}

fn reject_symlink_or_non_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspecting installer file {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("installer path {} must be a regular file", path.display());
    }
    Ok(())
}

fn remove_regular_file_if_present(path: &Path) -> Result<()> {
    if !path_lexists(path)? {
        return Ok(());
    }
    reject_symlink_or_non_file(path)?;
    fs::remove_file(path).with_context(|| format!("removing {}", path.display()))
}

fn remove_directory_if_present(path: &Path) -> Result<()> {
    if !path_lexists(path)? {
        return Ok(());
    }
    reject_symlink_or_non_directory(path)?;
    fs::remove_dir_all(path).with_context(|| format!("removing {}", path.display()))
}

#[cfg(test)]
#[path = "../../tests/unit/installer_execution_generation.rs"]
mod tests;
