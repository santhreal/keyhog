use super::archive::{unpack_layer_archive, DockerUnpackBudget};
use super::metadata::manifest_layer_archives as find_manifest_layer_archives;
use super::{create_private_directory_all, DockerScanWorkspace};
use keyhog_core::{Chunk, Source, SourceError};
use std::path::{Path, PathBuf};

use crate::FilesystemSource;

pub(super) fn stream_docker_layer_chunks(
    workspace: &DockerScanWorkspace,
    image: &str,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
    budget: &DockerUnpackBudget,
    emit: &mut impl FnMut(Result<Chunk, SourceError>) -> bool,
) -> bool {
    let layer_archives = match find_layer_archives(workspace.root_path(), limits) {
        Ok(layer_archives) => layer_archives,
        Err(error) => return emit(Err(error)),
    };
    for layer_tar in layer_archives {
        match scan_docker_layer(
            workspace,
            image,
            &layer_tar,
            limits,
            respect_default_excludes,
            budget,
            emit,
        ) {
            Ok(true) => {}
            Ok(false) => return false,
            Err(error) => {
                if !emit(Err(error)) {
                    return false;
                }
            }
        }
    }
    true
}

pub(super) fn find_layer_archives(
    root_path: &Path,
    limits: crate::SourceLimits,
) -> Result<Vec<PathBuf>, SourceError> {
    let manifest_layers = find_manifest_layer_archives(root_path, limits)?;
    if !manifest_layers.is_empty() {
        return Ok(manifest_layers);
    }

    let walker = super::exhaustive_archive_walker(root_path);
    Ok(collect_fallback_layer_archives(
        walker
            .walk_iter()
            .map(|entry| entry.map(|entry| entry.path)),
    ))
}

pub(super) fn collect_fallback_layer_archives<I, E>(entries: I) -> Vec<PathBuf>
where
    I: IntoIterator<Item = Result<PathBuf, E>>,
    E: std::fmt::Display,
{
    let mut layers = Vec::new();
    for entry in entries {
        match entry {
            Ok(path) if is_fallback_layer_archive_path(&path) => layers.push(path),
            Ok(_) => {}
            Err(error) => {
                // KH-1446: one unreadable walk entry must not abort layer
                // discovery for the rest of the image archive.
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                tracing::warn!(
                    error = %error,
                    "failed to inspect one docker image archive entry while discovering layer archives; continuing"
                );
            }
        }
    }
    layers.sort();
    layers.dedup();
    layers
}

pub(super) fn rewrite_layer_chunks<I>(
    input_chunks: I,
    image: &str,
    layer_root: &Path,
    layer_name: &str,
) -> Result<Vec<Result<Chunk, SourceError>>, SourceError>
where
    I: IntoIterator<Item = Result<Chunk, SourceError>>,
{
    let mut rewritten = Vec::new();
    stream_rewritten_layer_chunks(input_chunks, image, layer_root, layer_name, &mut |row| {
        rewritten.push(row);
        true
    })?;
    Ok(rewritten)
}

fn stream_rewritten_layer_chunks<I>(
    input_chunks: I,
    image: &str,
    layer_root: &Path,
    layer_name: &str,
    emit: &mut impl FnMut(Result<Chunk, SourceError>) -> bool,
) -> Result<bool, SourceError>
where
    I: IntoIterator<Item = Result<Chunk, SourceError>>,
{
    let normalized_root = std::fs::canonicalize(layer_root).map_err(|error| {
        SourceError::Other(format!(
            "docker layer root '{}' cannot be canonicalized: {error}",
            layer_root.display()
        ))
    })?;
    for chunk in input_chunks {
        let row = match chunk {
            Ok(chunk) => rewrite_chunk(chunk, image, &normalized_root, layer_name),
            Err(error) => Err(SourceError::Other(format!(
                "docker layer {layer_name} scan failed: {error}"
            ))),
        };
        if !emit(row) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn sanitize_layer_name(layer_name: &str) -> String {
    layer_name.replace('/', "_")
}

fn scan_docker_layer(
    workspace: &DockerScanWorkspace,
    image: &str,
    layer_tar: &Path,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
    budget: &DockerUnpackBudget,
    emit: &mut impl FnMut(Result<Chunk, SourceError>) -> bool,
) -> Result<bool, SourceError> {
    let layer_name = docker_layer_name(layer_tar, workspace.root_path());
    let layer_dir = workspace.layer_dir(&layer_name);
    create_private_directory_all(&layer_dir)?;
    let error_rows = match unpack_layer_archive(layer_tar, &layer_dir, limits, budget) {
        Ok(report) => report.into_rows(),
        Err(error) => vec![Err(error)],
    };

    if !stream_rewritten_layer_chunks(
        FilesystemSource::new(layer_dir.clone())
            .with_default_excludes(respect_default_excludes)
            .chunks(),
        image,
        &layer_dir,
        &layer_name,
        emit,
    )? {
        return Ok(false);
    }
    for row in error_rows {
        if !emit(row) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn docker_layer_name(layer_tar: &Path, root_path: &Path) -> String {
    layer_tar
        .strip_prefix(root_path)
        .ok() // LAW10: a non-prefixed path falls back to the full display path below, both are valid scannable labels, no layer is dropped
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
    normalized_root: &Path,
    layer_name: &str,
) -> Result<Chunk, SourceError> {
    let source_path = chunk.metadata.path.as_deref().ok_or_else(|| {
        SourceError::Other(format!(
            "docker layer {layer_name} produced a chunk without a file path"
        ))
    })?;
    let relative_path = layer_relative_path(source_path, normalized_root)?;

    if chunk.metadata.source_type.starts_with("binary:")
        || chunk.metadata.source_type.contains("binary-strings")
        || chunk.metadata.source_type.contains("archive-binary")
    {
        chunk.metadata.source_type = format!("docker/{}", chunk.metadata.source_type).into();
    } else {
        chunk.metadata.source_type = "docker".into();
    }
    chunk.metadata.path = Some(format!("{image}:{layer_name}:{relative_path}").into());
    chunk.metadata.commit = None;
    chunk.metadata.author = None;
    chunk.metadata.date = None;
    Ok(chunk)
}

/// Resolve one chunk's path relative to an ALREADY-canonicalized layer root.
/// The root is canonicalized once by the caller (`rewrite_layer_chunks`) and
/// passed in, so this per-chunk hot path pays only the one unavoidable
/// canonicalize of the chunk's own path.
fn layer_relative_path(path: &str, normalized_root: &Path) -> Result<String, SourceError> {
    let (filesystem_path, virtual_member) = match path.split_once("//") {
        Some((filesystem_path, virtual_member)) => {
            validate_virtual_member_path(virtual_member)?;
            (filesystem_path, Some(virtual_member))
        }
        None => (path, None),
    };
    let raw_path = Path::new(filesystem_path);
    let candidate = if raw_path.is_absolute() {
        raw_path.to_path_buf()
    } else {
        normalized_root.join(raw_path)
    };
    let normalized_path = std::fs::canonicalize(&candidate).map_err(|error| {
        SourceError::Other(format!(
            "docker layer chunk path '{}' cannot be canonicalized: {error}",
            candidate.display()
        ))
    })?;
    let relative = normalized_path
        .strip_prefix(normalized_root)
        .map_err(|_| {
            SourceError::Other(format!(
                "docker layer chunk path '{}' is outside layer root '{}'",
                normalized_path.display(),
                normalized_root.display()
            ))
        })?
        .to_string_lossy()
        .replace('\\', "/");
    Ok(match virtual_member {
        Some(member) => format!("{relative}//{}", member.replace('\\', "/")),
        None => relative,
    })
}

fn validate_virtual_member_path(member: &str) -> Result<(), SourceError> {
    let valid = !member.is_empty()
        && member.split("//").all(|nested_member| {
            let path = Path::new(nested_member);
            !nested_member.is_empty()
                && !path.is_absolute()
                && path
                    .components()
                    .all(|component| matches!(component, std::path::Component::Normal(_)))
        });
    if valid {
        Ok(())
    } else {
        Err(SourceError::Other(format!(
            "docker layer chunk has unsafe virtual archive member path '{member}'"
        )))
    }
}
