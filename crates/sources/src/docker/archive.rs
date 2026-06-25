use keyhog_core::SourceError;
use std::fs::File;
use std::io::{Read, Seek};
use std::path::{Component, Path};

#[derive(Default)]
pub(super) struct DockerExtractReport {
    errors: Vec<SourceError>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DockerArchiveScope {
    ImageArchive,
    LayerArchive,
}

impl DockerExtractReport {
    fn push_error(&mut self, error: SourceError) {
        self.errors.push(error);
    }

    pub(super) fn into_errors(self) -> Vec<SourceError> {
        self.errors
    }

    pub(super) fn into_rows(self) -> Vec<Result<keyhog_core::Chunk, SourceError>> {
        self.errors.into_iter().map(Err).collect()
    }
}

pub(super) fn unpack_tar(
    archive_path: &Path,
    destination: &Path,
    limits: crate::SourceLimits,
) -> Result<DockerExtractReport, SourceError> {
    let file = File::open(archive_path).map_err(SourceError::Io)?;
    unpack_open_tar(file, destination, limits, DockerArchiveScope::ImageArchive)
}

pub(super) fn unpack_layer_archive(
    archive_path: &Path,
    destination: &Path,
    limits: crate::SourceLimits,
) -> Result<DockerExtractReport, SourceError> {
    let mut file = File::open(archive_path).map_err(SourceError::Io)?;
    let encoding = layer_archive_encoding(&mut file)?;
    file.rewind().map_err(SourceError::Io)?;

    match encoding {
        LayerArchiveEncoding::RawTar => {
            unpack_open_tar(file, destination, limits, DockerArchiveScope::LayerArchive)
        }
        LayerArchiveEncoding::GzipTar => {
            validate_tar_reader(
                flate2::read::MultiGzDecoder::new(&mut file),
                limits,
                DockerArchiveScope::LayerArchive,
            )?;

            file.rewind().map_err(SourceError::Io)?;
            unpack_tar_reader(
                flate2::read::MultiGzDecoder::new(&mut file),
                destination,
                limits,
                DockerArchiveScope::LayerArchive,
            )
        }
        LayerArchiveEncoding::ZstdTar => {
            let mut validation_reader =
                zstd::stream::read::Decoder::new(&mut file).map_err(SourceError::Io)?;
            validation_reader
                .window_log_max(crate::compression_limits::zstd_window_log_max_for_budget(
                    limits.docker_tar_total_bytes,
                ))
                .map_err(SourceError::Io)?;
            validate_tar_reader(validation_reader, limits, DockerArchiveScope::LayerArchive)?;

            file.rewind().map_err(SourceError::Io)?;
            let mut extract_reader =
                zstd::stream::read::Decoder::new(&mut file).map_err(SourceError::Io)?;
            extract_reader
                .window_log_max(crate::compression_limits::zstd_window_log_max_for_budget(
                    limits.docker_tar_total_bytes,
                ))
                .map_err(SourceError::Io)?;
            unpack_tar_reader(
                extract_reader,
                destination,
                limits,
                DockerArchiveScope::LayerArchive,
            )
        }
    }
}

pub(super) fn validate_tar_archive_with_total_cap(
    archive_path: &Path,
    total_cap: u64,
) -> Result<(), SourceError> {
    let file = File::open(archive_path).map_err(SourceError::Io)?;
    let mut archive = tar::Archive::new(file);
    let limits = crate::SourceLimits {
        docker_tar_total_bytes: total_cap,
        ..crate::SourceLimits::default()
    };
    validate_extracted_tree_with_limits(&mut archive, limits)
}

fn unpack_open_tar(
    mut file: File,
    destination: &Path,
    limits: crate::SourceLimits,
    scope: DockerArchiveScope,
) -> Result<DockerExtractReport, SourceError> {
    let mut validation_archive = tar::Archive::new(&mut file);
    validate_docker_archive_plan(&mut validation_archive, limits, scope)?;

    file.rewind().map_err(SourceError::Io)?;
    unpack_tar_reader(&mut file, destination, limits, scope)
}

fn validate_tar_reader(
    reader: impl Read,
    limits: crate::SourceLimits,
    scope: DockerArchiveScope,
) -> Result<(), SourceError> {
    let mut archive = tar::Archive::new(reader);
    validate_docker_archive_plan(&mut archive, limits, scope)
}

fn unpack_tar_reader(
    reader: impl Read,
    destination: &Path,
    limits: crate::SourceLimits,
    scope: DockerArchiveScope,
) -> Result<DockerExtractReport, SourceError> {
    let mut archive = tar::Archive::new(reader);
    extract_docker_archive_entries(&mut archive, destination, limits, scope)
}

enum LayerArchiveEncoding {
    RawTar,
    GzipTar,
    ZstdTar,
}

fn layer_archive_encoding(file: &mut File) -> Result<LayerArchiveEncoding, SourceError> {
    let mut magic = [0u8; 4];
    let read = file.read(&mut magic).map_err(SourceError::Io)?;
    let prefix = &magic[..read];
    if crate::magic::starts_with_gzip(prefix) {
        return Ok(LayerArchiveEncoding::GzipTar);
    }
    if crate::magic::starts_with_zstd_frame(prefix) {
        return Ok(LayerArchiveEncoding::ZstdTar);
    }
    Ok(LayerArchiveEncoding::RawTar)
}

fn validate_extracted_tree_with_limits<R: Read>(
    archive: &mut tar::Archive<R>,
    limits: crate::SourceLimits,
) -> Result<(), SourceError> {
    let mut cumulative_bytes: u64 = 0;
    for entry in archive.entries().map_err(SourceError::Io)? {
        let entry = entry.map_err(SourceError::Io)?;
        let path = entry.path().map_err(SourceError::Io)?;
        let size = entry.header().entry_size().map_err(SourceError::Io)?;
        let file_type = entry.header().entry_type();
        validate_docker_archive_entry(&path, file_type)?;
        if size > limits.docker_tar_entry_bytes {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            return Err(docker_archive_entry_over_entry_cap_error(
                &path,
                size,
                limits.docker_tar_entry_bytes,
            ));
        }

        cumulative_bytes = cumulative_bytes.saturating_add(size);
        if cumulative_bytes > limits.docker_tar_total_bytes {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::ArchiveTruncated);
            return Err(SourceError::Other(format!(
                "docker archive cumulative size exceeds {} bytes at entry '{}' \
                 (likely zip-bomb)",
                limits.docker_tar_total_bytes,
                path.display(),
            )));
        }
    }

    Ok(())
}

fn validate_docker_archive_plan<R: Read>(
    archive: &mut tar::Archive<R>,
    limits: crate::SourceLimits,
    scope: DockerArchiveScope,
) -> Result<(), SourceError> {
    let mut cumulative_bytes: u64 = 0;
    for entry in archive.entries().map_err(SourceError::Io)? {
        let entry = entry.map_err(SourceError::Io)?;
        let path = entry.path().map_err(SourceError::Io)?;
        let size = entry.header().entry_size().map_err(SourceError::Io)?;
        let file_type = entry.header().entry_type();
        validate_docker_archive_entry(&path, file_type)?;

        if docker_archive_entry_exceeds_scan_cap(file_type, size, limits, scope) {
            continue;
        }

        cumulative_bytes = cumulative_bytes.saturating_add(size);
        if cumulative_bytes > limits.docker_tar_total_bytes {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::ArchiveTruncated);
            return Err(SourceError::Other(format!(
                "docker archive cumulative size exceeds {} bytes at entry '{}' \
                 (likely zip-bomb)",
                limits.docker_tar_total_bytes,
                path.display(),
            )));
        }
    }

    Ok(())
}

fn extract_docker_archive_entries<R: Read>(
    archive: &mut tar::Archive<R>,
    destination: &Path,
    limits: crate::SourceLimits,
    scope: DockerArchiveScope,
) -> Result<DockerExtractReport, SourceError> {
    let mut cumulative_bytes: u64 = 0;
    let mut report = DockerExtractReport::default();
    for entry in archive.entries().map_err(SourceError::Io)? {
        let mut entry = entry.map_err(SourceError::Io)?;
        let path = entry.path().map_err(SourceError::Io)?.into_owned();
        let size = entry.header().entry_size().map_err(SourceError::Io)?;
        validate_docker_archive_entry(&path, entry.header().entry_type())?;

        if docker_archive_entry_exceeds_scan_cap(entry.header().entry_type(), size, limits, scope) {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            report.push_error(docker_archive_entry_over_entry_cap_error(
                &path,
                size,
                limits.docker_tar_entry_bytes,
            ));
            continue;
        }

        cumulative_bytes = cumulative_bytes.saturating_add(size);
        if cumulative_bytes > limits.docker_tar_total_bytes {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::ArchiveTruncated);
            return Err(SourceError::Other(format!(
                "docker archive cumulative size exceeds {} bytes at entry '{}' \
                 (likely zip-bomb)",
                limits.docker_tar_total_bytes,
                path.display(),
            )));
        }

        let unpacked_inside_destination = entry.unpack_in(destination).map_err(SourceError::Io)?;
        if !unpacked_inside_destination {
            return Err(SourceError::Other(format!(
                "docker archive entry '{}' could not be safely unpacked inside '{}'",
                path.display(),
                destination.display()
            )));
        }
    }

    Ok(report)
}

fn validate_docker_archive_entry(
    path: &Path,
    file_type: tar::EntryType,
) -> Result<(), SourceError> {
    if file_type.is_symlink() || file_type.is_hard_link() {
        return Err(SourceError::Other(format!(
            "docker archive contains forbidden link '{}'",
            path.display()
        )));
    }

    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(SourceError::Other(format!(
            "docker archive contains unsafe path '{}'",
            path.display()
        )));
    }

    Ok(())
}

fn docker_archive_entry_over_entry_cap_error(
    path: &Path,
    entry_size: u64,
    entry_cap: u64,
) -> SourceError {
    SourceError::Other(format!(
        "docker archive entry '{}': uncompressed size {} exceeds per-file cap {}; entry was not scanned",
        path.display(),
        entry_size,
        entry_cap
    ))
}

fn docker_archive_entry_exceeds_scan_cap(
    file_type: tar::EntryType,
    size: u64,
    limits: crate::SourceLimits,
    scope: DockerArchiveScope,
) -> bool {
    scope == DockerArchiveScope::LayerArchive
        && file_type.is_file()
        && size > limits.docker_tar_entry_bytes
}
