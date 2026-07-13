use anyhow::{anyhow, Context, Result};
use flate2::read::GzDecoder;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};

const MAX_ARCHIVE_ENTRIES: usize = 64;
const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_EXPANDED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
pub(crate) struct GpuLiteralFile {
    pub(crate) name: String,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Deserialize)]
struct ArtifactManifest {
    format_version: u32,
    keyhog_version: String,
    artifacts: Vec<ArtifactManifestEntry>,
}

#[derive(Deserialize)]
struct ArtifactManifestEntry {
    file_name: String,
    byte_len: usize,
}

pub(crate) fn parse_gpu_literal_sidecar(
    archive_bytes: &[u8],
    expected_release_tag: &str,
) -> Result<Vec<GpuLiteralFile>> {
    let decoder = GzDecoder::new(Cursor::new(archive_bytes));
    let mut archive = tar::Archive::new(decoder);
    let mut files = BTreeMap::<String, Vec<u8>>::new();
    let mut manifest_bytes = None;
    let mut entry_count = 0usize;
    let mut expanded_bytes = 0u64;

    for entry in archive
        .entries()
        .context("read GPU literal sidecar archive")?
    {
        entry_count = entry_count.saturating_add(1);
        if entry_count > MAX_ARCHIVE_ENTRIES {
            anyhow::bail!(
                "GPU literal sidecar contains more than {MAX_ARCHIVE_ENTRIES} archive entries"
            );
        }
        let entry = entry.context("read GPU literal sidecar entry")?;
        let path = entry
            .path()
            .context("read GPU literal sidecar entry path")?
            .into_owned();
        if !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        {
            anyhow::bail!(
                "GPU literal sidecar contains unsafe archive path {}",
                path.display()
            );
        }
        if entry.header().entry_type().is_dir() {
            continue;
        }
        if !entry.header().entry_type().is_file() {
            anyhow::bail!(
                "GPU literal sidecar contains non-file entry {}",
                path.display()
            );
        }

        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow!("GPU literal sidecar entry name is not valid UTF-8"))?
            .to_string();
        let limit = if name == "manifest.json" {
            MAX_MANIFEST_BYTES
        } else if name.ends_with(".bin") {
            MAX_ARTIFACT_BYTES
        } else {
            anyhow::bail!(
                "GPU literal sidecar contains unexpected file {}",
                path.display()
            );
        };
        let declared = entry.size();
        if declared > limit {
            anyhow::bail!(
                "GPU literal sidecar entry {} exceeds its {limit}-byte limit",
                path.display()
            );
        }
        expanded_bytes = expanded_bytes.saturating_add(declared);
        if expanded_bytes > MAX_EXPANDED_BYTES {
            anyhow::bail!(
                "GPU literal sidecar expands beyond the {MAX_EXPANDED_BYTES}-byte total limit"
            );
        }
        let mut bytes = Vec::with_capacity(
            usize::try_from(declared).unwrap_or(0).min(64 * 1024), // LAW10: perf-only allocation hint; take/read_to_end and exact declared-length validation below remain authoritative
        );
        entry
            .take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .with_context(|| format!("read GPU literal sidecar entry {}", path.display()))?;
        if bytes.len() as u64 != declared {
            anyhow::bail!(
                "GPU literal sidecar entry {} is truncated: header declares {declared} bytes, read {}",
                path.display(),
                bytes.len()
            );
        }
        if name == "manifest.json" {
            if manifest_bytes.replace(bytes).is_some() {
                anyhow::bail!("GPU literal sidecar contains duplicate manifest.json files");
            }
        } else if files.insert(name.clone(), bytes).is_some() {
            anyhow::bail!("GPU literal sidecar contains duplicate artifact {name}");
        }
    }

    let manifest_bytes =
        manifest_bytes.ok_or_else(|| anyhow!("GPU literal sidecar contains no manifest.json"))?;
    let manifest: ArtifactManifest =
        serde_json::from_slice(&manifest_bytes).context("parse GPU literal sidecar manifest")?;
    if manifest.format_version != 1 {
        anyhow::bail!(
            "GPU literal sidecar format {} is unsupported; expected 1",
            manifest.format_version
        );
    }
    let expected = super::parse_version(expected_release_tag)
        .ok_or_else(|| anyhow!("release tag `{expected_release_tag}` is not valid SemVer"))?;
    let actual = super::parse_version(&manifest.keyhog_version).ok_or_else(|| {
        anyhow!(
            "GPU literal sidecar manifest version `{}` is not valid SemVer",
            manifest.keyhog_version
        )
    })?;
    if actual != expected {
        anyhow::bail!(
            "GPU literal sidecar is for keyhog v{} but release metadata resolved {expected_release_tag}",
            manifest.keyhog_version
        );
    }

    let mut declared_names = BTreeSet::new();
    for artifact in manifest.artifacts {
        let file_name = Path::new(&artifact.file_name);
        if file_name.components().count() != 1 || !artifact.file_name.ends_with(".bin") {
            anyhow::bail!(
                "GPU literal sidecar manifest contains invalid artifact name `{}`",
                artifact.file_name
            );
        }
        if !declared_names.insert(artifact.file_name.clone()) {
            anyhow::bail!(
                "GPU literal sidecar manifest repeats artifact `{}`",
                artifact.file_name
            );
        }
        let bytes = files.get(&artifact.file_name).ok_or_else(|| {
            anyhow!(
                "GPU literal sidecar manifest names missing artifact `{}`",
                artifact.file_name
            )
        })?;
        if bytes.len() != artifact.byte_len {
            anyhow::bail!(
                "GPU literal sidecar artifact `{}` has {} bytes but manifest declares {}",
                artifact.file_name,
                bytes.len(),
                artifact.byte_len
            );
        }
    }
    if declared_names.is_empty() {
        anyhow::bail!("GPU literal sidecar manifest contains no artifacts");
    }
    let actual_names = files.keys().cloned().collect::<BTreeSet<_>>();
    if actual_names != declared_names {
        anyhow::bail!("GPU literal sidecar contains artifacts absent from its manifest");
    }

    Ok(files
        .into_iter()
        .map(|(name, bytes)| GpuLiteralFile { name, bytes })
        .collect())
}

pub(crate) struct GpuArtifactInstallTransaction {
    cache_dir: PathBuf,
    _write_lock: keyhog_core::StateFileWriteLock,
    installed: Vec<PathBuf>,
    backups: Vec<(PathBuf, PathBuf)>,
    committed: bool,
}

impl GpuArtifactInstallTransaction {
    pub(crate) fn commit(mut self) {
        self.committed = true;
        for (_, backup) in &self.backups {
            super::remove_installer_artifact_best_effort(
                backup,
                "GPU literal artifact backup cleanup after successful install",
            );
        }
    }
}

impl Drop for GpuArtifactInstallTransaction {
    fn drop(&mut self) {
        if !self.committed {
            for target in self.installed.iter().rev() {
                super::remove_installer_artifact_best_effort(
                    target,
                    "GPU literal artifact rollback remove",
                );
            }
            for (target, backup) in self.backups.iter().rev() {
                if let Err(error) = std::fs::rename(backup, target) {
                    tracing::error!(
                        target = %target.display(),
                        backup = %backup.display(),
                        %error,
                        "GPU literal artifact rollback failed; restore the backup manually"
                    );
                }
            }
        }
    }
}

pub(crate) fn install_gpu_literal_files(
    files: &[GpuLiteralFile],
) -> Result<GpuArtifactInstallTransaction> {
    let cache_dir = keyhog_scanner::gpu_literal_artifact_cache_dir()
        .map_err(|error| anyhow!(error.to_string()))?;
    install_gpu_literal_files_in_dir(&cache_dir, files)
}

pub(crate) fn install_gpu_literal_files_in_dir(
    cache_dir: &Path,
    files: &[GpuLiteralFile],
) -> Result<GpuArtifactInstallTransaction> {
    std::fs::create_dir_all(cache_dir).with_context(|| {
        format!(
            "create GPU literal artifact cache directory {}",
            cache_dir.display()
        )
    })?;
    let lock_target = cache_dir.join(".keyhog-maintenance");
    let write_lock = keyhog_core::StateFileWriteLock::acquire(&lock_target).with_context(|| {
        format!(
            "acquire GPU literal cache maintenance lock beside {}",
            lock_target.display()
        )
    })?;
    let mut transaction = GpuArtifactInstallTransaction {
        cache_dir: cache_dir.to_path_buf(),
        _write_lock: write_lock,
        installed: Vec::new(),
        backups: Vec::new(),
        committed: false,
    };

    for file in files {
        let target = transaction.cache_dir.join(&file.name);
        let backup = transaction.cache_dir.join(format!(
            ".{}.keyhog-artifact-bak-{}",
            file.name,
            std::process::id()
        ));
        if backup.exists() {
            anyhow::bail!(
                "stale GPU literal artifact backup exists at {}; inspect or remove it before retrying",
                backup.display()
            );
        }
        if target.exists() {
            std::fs::rename(&target, &backup).with_context(|| {
                format!(
                    "back up GPU literal artifact {} before update",
                    target.display()
                )
            })?;
            transaction.backups.push((target.clone(), backup));
        }

        let mut staged = tempfile::NamedTempFile::new_in(&transaction.cache_dir)
            .context("stage GPU literal artifact in its cache directory")?;
        staged
            .write_all(&file.bytes)
            .with_context(|| format!("write staged GPU literal artifact {}", file.name))?;
        staged
            .as_file()
            .sync_all()
            .with_context(|| format!("sync staged GPU literal artifact {}", file.name))?;
        staged
            .persist(&target)
            .map_err(|error| error.error)
            .with_context(|| {
                format!(
                    "atomically install GPU literal artifact {}",
                    target.display()
                )
            })?;
        transaction.installed.push(target);
    }

    Ok(transaction)
}
