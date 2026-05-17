use std::borrow::Cow;
use std::path::{Path, PathBuf};

pub(crate) fn invalidate_impacted(
    intervention_mask: &[u32],
    rule_adj: &[u32],
    state: &[u32],
    join_rules: &[u32],
    n: u32,
    max_iterations: u32,
    pipeline_lineage_cell: &[u32],
    cache_keys: &[String],
) -> std::io::Result<()> {
    let dir = disk_pipeline_cache_dir();
    let impact_mask = vyre_driver::cache_invalidation::impacted_entries(
        intervention_mask,
        rule_adj,
        state,
        join_rules,
        n,
        max_iterations,
        pipeline_lineage_cell,
    );

    for (i, &is_impacted) in impact_mask.iter().enumerate() {
        if is_impacted != 0 {
            if let Some(key) = cache_keys.get(i) {
                let wgsl_path = cache_entry_path(&dir, key, ".wgsl");
                let meta_wgsl = cache_entry_path(&dir, key, ".wgsl.toml");
                let bin_path = cache_entry_path(&dir, key, ".pipeline.bin");
                let meta_bin = cache_entry_path(&dir, key, ".pipeline.toml");

                remove_cache_entry_file(&wgsl_path)?;
                remove_cache_entry_file(&meta_wgsl)?;
                remove_cache_entry_file(&bin_path)?;
                remove_cache_entry_file(&meta_bin)?;
            }
        }
    }
    Ok(())
}

fn remove_cache_entry_file(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(std::io::Error::new(
            error.kind(),
            format!(
                "Fix: failed to remove invalidated WGPU pipeline cache file `{}`: {error}",
                path.display()
            ),
        )),
    }
}

pub(crate) fn cache_entry_path(dir: &Path, key: &str, suffix: &str) -> PathBuf {
    let mut file_name = String::with_capacity(key.len() + suffix.len());
    file_name.push_str(key);
    file_name.push_str(suffix);
    dir.join(file_name)
}

pub(crate) fn disk_pipeline_cache_dir() -> PathBuf {
    std::env::var_os("VYRE_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".cache")
                .join("vyre")
        })
        .join("pipeline")
}

#[derive(serde::Deserialize, serde::Serialize)]
pub(crate) struct DiskPipelineMetadata {
    pub version: u32,
    pub cache_key: [u8; 32],
    pub wgsl_bytes: usize,
    pub adapter_fingerprint: [u8; 32],
    pub program_abi_version: u32,
    pub naga_version: Cow<'static, str>,
    pub wgsl_lowering_contract: Cow<'static, str>,
    pub policy: String,
    pub wgsl_blake3: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub(crate) struct CompiledPipelineMetadata {
    pub version: u32,
    pub cache_key: [u8; 32],
    pub adapter_fingerprint: [u8; 32],
    pub wgsl_blake3: String,
    pub program_abi_version: u32,
    pub naga_version: Cow<'static, str>,
    pub blob_bytes: usize,
    pub blob_blake3: String,
}
