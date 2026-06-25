use super::archive::unpack_layer_archive;
use super::metadata::manifest_layer_archives as find_manifest_layer_archives;
use super::{create_private_directory_all, DockerScanWorkspace};
use codewalk::{CodeWalker, WalkConfig};
use keyhog_core::{Chunk, Source, SourceError};
use std::path::{Path, PathBuf};

use crate::FilesystemSource;

pub(super) fn collect_docker_layer_chunks(
    workspace: &DockerScanWorkspace,
    image: &str,
    limits: crate::SourceLimits,
) -> Vec<Result<Chunk, SourceError>> {
    let layer_archives = match find_layer_archives(workspace.root_path(), limits) {
        Ok(layer_archives) => layer_archives,
        Err(error) => return vec![Err(error)],
    };
    let mut rows = Vec::new();
    for layer_tar in layer_archives {
        match scan_docker_layer(workspace, image, &layer_tar, limits) {
            Ok(layer_rows) => rows.extend(layer_rows),
            Err(error) => rows.push(Err(error)),
        }
    }
    rows
}

pub(super) fn find_layer_archives(
    root_path: &Path,
    limits: crate::SourceLimits,
) -> Result<Vec<PathBuf>, SourceError> {
    let manifest_layers = find_manifest_layer_archives(root_path, limits)?;
    if !manifest_layers.is_empty() {
        return Ok(manifest_layers);
    }

    let mut layers = Vec::new();
    let walker = CodeWalker::new(
        root_path,
        WalkConfig::default()
            .follow_symlinks(false)
            .respect_gitignore(false)
            .skip_hidden(false)
            .skip_binary(false)
            .max_file_size(0),
    );

    for entry in walker.walk_iter() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                return Err(SourceError::Other(format!(
                    "failed to inspect docker image archive while discovering layer archives: {error}; docker image archive was not fully scanned"
                )));
            }
        };
        if is_fallback_layer_archive_path(&entry.path) {
            layers.push(entry.path);
        }
    }
    layers.sort();
    layers.dedup();
    Ok(layers)
}

pub(super) fn rewrite_layer_chunks<I>(
    input_chunks: I,
    image: &str,
    layer_root: &Path,
    layer_name: &str,
) -> Result<Vec<Chunk>, SourceError>
where
    I: IntoIterator<Item = Result<Chunk, SourceError>>,
{
    let mut rewritten = Vec::new();
    for chunk in input_chunks {
        match chunk {
            Ok(chunk) => rewritten.push(rewrite_chunk(chunk, image, layer_root, layer_name)?),
            Err(error) => {
                return Err(SourceError::Other(format!(
                    "docker layer {layer_name} scan failed: {error}"
                )));
            }
        }
    }
    Ok(rewritten)
}

pub(super) fn sanitize_layer_name(layer_name: &str) -> String {
    layer_name.replace('/', "_")
}

fn scan_docker_layer(
    workspace: &DockerScanWorkspace,
    image: &str,
    layer_tar: &Path,
    limits: crate::SourceLimits,
) -> Result<Vec<Result<Chunk, SourceError>>, SourceError> {
    let layer_name = docker_layer_name(layer_tar, workspace.root_path());
    let layer_dir = workspace.layer_dir(&layer_name);
    create_private_directory_all(&layer_dir)?;
    let error_rows = unpack_layer_archive(layer_tar, &layer_dir, limits)?.into_rows();
    let mut rows = Vec::new();

    match rewrite_layer_chunks(
        FilesystemSource::new(layer_dir.clone()).chunks(),
        image,
        &layer_dir,
        &layer_name,
    ) {
        Ok(chunks) => rows.extend(chunks.into_iter().map(Ok)),
        Err(error) => rows.push(Err(error)),
    }
    rows.extend(error_rows);
    Ok(rows)
}

fn docker_layer_name(layer_tar: &Path, root_path: &Path) -> String {
    layer_tar
        .strip_prefix(root_path)
        .ok() // LAW10: a non-prefixed path falls back to the full display path below — both are valid scannable labels, no layer is dropped
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| layer_tar.display().to_string()) // LAW10: display-label fallback only; the layer is still unpacked + scanned
}

fn is_fallback_layer_archive_path(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("layer.tar" | "layer.tar.gz" | "layer.tgz" | "layer.tar.zst" | "layer.tar.zstd")
    )
}

fn rewrite_chunk(
    mut chunk: Chunk,
    image: &str,
    layer_root: &Path,
    layer_name: &str,
) -> Result<Chunk, SourceError> {
    let source_path = chunk.metadata.path.as_deref().ok_or_else(|| {
        SourceError::Other(format!(
            "docker layer {layer_name} produced a chunk without a file path"
        ))
    })?;
    let relative_path = layer_relative_path(source_path, layer_root)?;

    chunk.metadata.source_type = "docker".into();
    chunk.metadata.path = Some(format!("{image}:{layer_name}:{relative_path}"));
    chunk.metadata.commit = None;
    chunk.metadata.author = None;
    chunk.metadata.date = None;
    Ok(chunk)
}

fn layer_relative_path(path: &str, layer_root: &Path) -> Result<String, SourceError> {
    let raw_path = Path::new(path);
    let candidate = if raw_path.is_absolute() {
        raw_path.to_path_buf()
    } else {
        layer_root.join(raw_path)
    };
    let normalized_path = std::fs::canonicalize(&candidate).map_err(|error| {
        SourceError::Other(format!(
            "docker layer chunk path '{}' cannot be canonicalized: {error}",
            candidate.display()
        ))
    })?;
    let normalized_root = std::fs::canonicalize(layer_root).map_err(|error| {
        SourceError::Other(format!(
            "docker layer root '{}' cannot be canonicalized: {error}",
            layer_root.display()
        ))
    })?;
    let relative = normalized_path
        .strip_prefix(&normalized_root)
        .map_err(|_| {
            SourceError::Other(format!(
                "docker layer chunk path '{}' is outside layer root '{}'",
                normalized_path.display(),
                normalized_root.display()
            ))
        })?
        .to_path_buf();
    Ok(relative.to_string_lossy().replace('\\', "/"))
}
