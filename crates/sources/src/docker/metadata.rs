use super::file_read::read_capped_file;
use super::oci;
use keyhog_core::{Chunk, ChunkMetadata, SourceError};
use std::path::{Component, Path, PathBuf};

#[derive(serde::Deserialize)]
struct DockerArchiveManifestEntry {
    #[serde(rename = "Config")]
    config: String,
    #[serde(rename = "Layers", deserialize_with = "deserialize_docker_layers")]
    layers: Vec<String>,
}

fn deserialize_docker_layers<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let layers = <Option<Vec<String>> as serde::Deserialize>::deserialize(deserializer)?;
    match layers {
        Some(layers) => Ok(layers),
        None => {
            // LAW10: intended default for explicit JSON null as the Docker
            // manifest's zero-layer marker; missing `Layers` still fails closed
            // before this deserializer runs.
            Ok(Vec::new())
        }
    }
}
#[derive(serde::Deserialize)]
struct DockerRootMetadataFiles {
    files: Vec<String>,
}

fn parse_docker_root_metadata_files(raw: &str) -> Result<Vec<String>, String> {
    toml::from_str::<DockerRootMetadataFiles>(raw)
        .map(|parsed| parsed.files)
        .map_err(|error| error.to_string())
}

static DOCKER_ROOT_METADATA_FILES: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| {
        match parse_docker_root_metadata_files(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/rules/docker-root-metadata-files.toml"
        ))) {
            Ok(files) => files,
            Err(error) => panic!(
                "rules/docker-root-metadata-files.toml is invalid: {error}. \
                 Fix the bundled Tier-B docker-root metadata file list."
            ),
        }
    });

pub(super) fn archive_metadata_chunks(
    root_path: &Path,
    image: &str,
    limits: crate::SourceLimits,
) -> Result<Vec<Chunk>, SourceError> {
    let mut chunks = Vec::new();
    for file_name in &*DOCKER_ROOT_METADATA_FILES {
        let metadata_path = root_path.join(file_name);
        if !metadata_path.exists() {
            continue;
        }
        if !metadata_path.is_file() {
            return Err(SourceError::Other(format!(
                "docker metadata file '{}' is not a regular file; docker image metadata was not scanned",
                metadata_path.display()
            )));
        }
        let bytes = read_capped_file(
            &metadata_path,
            "docker metadata file",
            limits.docker_image_config_bytes,
        )?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
            SourceError::Other(format!(
                "invalid docker metadata file '{}': {error}",
                metadata_path.display()
            ))
        })?;
        let data = serde_json::to_string_pretty(&value).map_err(|error| {
            SourceError::Other(format!(
                "failed to serialize docker metadata file '{}' for scanning: {error}",
                metadata_path.display()
            ))
        })?;
        chunks.push(Chunk {
            metadata: ChunkMetadata {
                base_offset: 0,
                base_line: 0,
                source_type: "docker".into(),
                path: Some(format!("{image}:metadata:{file_name}").into()),
                commit: None,
                author: None,
                date: None,
                mtime_ns: None,
                size_bytes: Some(data.len() as u64),
                decoded_span: None,
            },
            data: data.into(),
        });
    }
    Ok(chunks)
}

fn load_manifest_entries(
    root_path: &Path,
    limits: crate::SourceLimits,
) -> Result<Vec<DockerArchiveManifestEntry>, SourceError> {
    let manifest_path = root_path.join("manifest.json");
    if !manifest_path.exists() {
        return Ok(Vec::new());
    }
    if !manifest_path.is_file() {
        return Err(SourceError::Other(format!(
            "docker manifest.json at '{}' is not a regular file; docker image metadata was not scanned",
            manifest_path.display()
        )));
    }
    let manifest = read_capped_file(
        &manifest_path,
        "docker manifest",
        limits.docker_image_config_bytes,
    )?;
    let entries: Vec<DockerArchiveManifestEntry> =
        serde_json::from_slice(&manifest).map_err(|error| {
            SourceError::Other(format!(
                "invalid docker manifest.json at '{}': {error}",
                manifest_path.display()
            ))
        })?;
    if entries.is_empty() {
        return Err(SourceError::Other(format!(
            "docker manifest.json at '{}' contains no image entries",
            manifest_path.display()
        )));
    }
    Ok(entries)
}

pub(super) fn manifest_config_chunks(
    root_path: &Path,
    image: &str,
    limits: crate::SourceLimits,
) -> Result<Vec<Chunk>, SourceError> {
    let entries = load_manifest_entries(root_path, limits)?;
    let mut chunks = Vec::new();
    for (idx, entry) in entries.into_iter().enumerate() {
        let config = entry.config;
        let config_path = resolve_manifest_member_path(root_path, "config", &config)?;
        if !config_path.is_file() {
            return Err(SourceError::Other(format!(
                "docker manifest references missing config '{}'",
                config
            )));
        }
        let bytes = read_capped_file(
            &config_path,
            "docker image config",
            limits.docker_image_config_bytes,
        )?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
            SourceError::Other(format!(
                "invalid docker image config '{}' referenced by manifest entry {idx}: {error}",
                config
            ))
        })?;
        let data = serde_json::to_string_pretty(&value).map_err(|error| {
            SourceError::Other(format!(
                "failed to serialize docker image config '{}' for scanning: {error}",
                config
            ))
        })?;
        chunks.push(Chunk {
            metadata: ChunkMetadata {
                base_offset: 0,
                base_line: 0,
                source_type: "docker".into(),
                path: Some(format!("{image}:manifest[{idx}]:{config}").into()),
                commit: None,
                author: None,
                date: None,
                mtime_ns: None,
                size_bytes: Some(data.len() as u64),
                decoded_span: None,
            },
            data: data.into(),
        });
    }
    chunks.extend(oci::config_chunks(root_path, image, limits)?);
    if chunks.is_empty() {
        chunks.extend(find_fallback_config_chunks(root_path, image, limits)?);
    }
    Ok(chunks)
}

fn find_fallback_config_chunks(
    root_path: &Path,
    image: &str,
    limits: crate::SourceLimits,
) -> Result<Vec<Chunk>, SourceError> {
    let mut config_paths = Vec::new();
    let walker = super::exhaustive_archive_walker(root_path);

    for entry in walker.walk_iter() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                return Err(SourceError::Other(format!(
                    "failed to inspect docker image archive while discovering metadata-less config JSON: {error}; docker image metadata was not fully scanned"
                )));
            }
        };
        if is_fallback_config_path(&entry.path) {
            config_paths.push(entry.path);
        }
    }
    config_paths.sort();
    config_paths.dedup();

    let mut chunks = Vec::new();
    for (idx, config_path) in config_paths.into_iter().enumerate() {
        let bytes = read_capped_file(
            &config_path,
            "metadata-less docker image config",
            limits.docker_image_config_bytes,
        )?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
            let _event =
                crate::record_skip_event(crate::SourceSkipEvent::StructuredSourceParseFailure);
            SourceError::Other(format!(
                "invalid metadata-less docker image config '{}': {error}",
                config_path.display()
            ))
        })?;
        let data = serde_json::to_string_pretty(&value).map_err(|error| {
            SourceError::Other(format!(
                "failed to serialize metadata-less docker image config '{}' for scanning: {error}",
                config_path.display()
            ))
        })?;
        let label = config_path.strip_prefix(root_path).map_err(|error| {
            SourceError::Other(format!(
                "metadata-less docker image config '{}' is outside docker archive root '{}': {error}; docker image metadata was not fully scanned",
                config_path.display(),
                root_path.display()
            ))
        })?;
        let label = docker_relative_path_label(label);
        chunks.push(Chunk {
            metadata: ChunkMetadata {
                base_offset: 0,
                base_line: 0,
                source_type: "docker".into(),
                path: Some(format!("{image}:fallback-config[{idx}]:{label}").into()),
                commit: None,
                author: None,
                date: None,
                mtime_ns: None,
                size_bytes: Some(data.len() as u64),
                decoded_span: None,
            },
            data: data.into(),
        });
    }
    Ok(chunks)
}

fn docker_relative_path_label(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn is_fallback_config_path(path: &Path) -> bool {
    if !path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
    {
        return false;
    }
    !matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("manifest.json" | "index.json")
    )
}

pub(super) fn manifest_layer_archives(
    root_path: &Path,
    limits: crate::SourceLimits,
) -> Result<Vec<PathBuf>, SourceError> {
    let entries = load_manifest_entries(root_path, limits)?;
    let mut layers = Vec::new();
    for entry in entries {
        for layer in entry.layers {
            let layer_path = resolve_manifest_member_path(root_path, "layer", &layer)?;
            if !layer_path.is_file() {
                return Err(SourceError::Other(format!(
                    "docker manifest references missing layer '{}'",
                    layer
                )));
            }
            layers.push(layer_path);
        }
    }
    layers.extend(oci::layer_archives(root_path, limits)?);
    layers.sort();
    layers.dedup();
    Ok(layers)
}

fn resolve_manifest_member_path(
    root_path: &Path,
    kind: &str,
    member: &str,
) -> Result<PathBuf, SourceError> {
    let relative = Path::new(member);
    if member.is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(SourceError::Other(format!(
            "docker manifest references unsafe {kind} path '{}'",
            member
        )));
    }
    Ok(root_path.join(relative))
}
