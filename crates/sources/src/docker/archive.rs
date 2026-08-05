use keyhog_core::SourceError;
use std::fs::File;
use std::io::{Read, Seek};
use std::path::{Component, Path};

/// Hard ceiling on the number of tar entries KeyHog will walk in one docker
/// archive or layer.
///
/// The `docker_tar_total_bytes` bomb guard sums `entry_size`, so it only bounds
/// archives whose entries carry PAYLOAD. A tar built purely from directory or
/// zero-length entries adds 0 to that sum on every iteration, so the byte guard
/// never trips no matter how many entries arrive. Layers are gzip/zstd streams,
/// so the header run itself decompresses with high amplification (a ~4 MB gzip
/// expands to 2M entries, ~229x), and each entry costs a `mkdir`/`create`
/// syscall under `unpack_in`. That is inode exhaustion and an effective hang
/// from a tiny input, so entry COUNT needs its own cap alongside the byte cap.
///
/// This is a safety invariant rather than an operator knob (a real image layer
/// is orders of magnitude below it), so it stays a compiled constant instead of
/// a `SourceLimits` field, which is where the tunable BYTE caps live.
const MAX_DOCKER_TAR_ENTRIES: usize = 500_000;

/// Coverage-gap error for an archive that exceeded [`MAX_DOCKER_TAR_ENTRIES`].
///
/// Law 10: entries past the cap are NOT scanned, so this is surfaced and
/// counted rather than silently truncating the walk.
fn docker_archive_entry_count_error(archive_kind: &str) -> SourceError {
    let _event = crate::record_skip_event(crate::SourceSkipEvent::ArchiveTruncated);
    SourceError::Other(format!(
        "docker archive {archive_kind} exceeds the {MAX_DOCKER_TAR_ENTRIES}-entry cap \
         (likely a tar-header bomb); remaining entries were not scanned"
    ))
}

#[derive(Default)]
pub(super) struct DockerExtractReport {
    errors: Vec<SourceError>,
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
    unpack_open_tar(file, destination, limits, false)
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
        LayerArchiveEncoding::RawTar => unpack_open_tar(file, destination, limits, true),
        LayerArchiveEncoding::GzipTar => {
            validate_tar_reader(flate2::read::MultiGzDecoder::new(&mut file), limits, true)?;

            file.rewind().map_err(SourceError::Io)?;
            unpack_tar_reader(
                flate2::read::MultiGzDecoder::new(&mut file),
                destination,
                limits,
                true,
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
            validate_tar_reader(validation_reader, limits, true)?;

            file.rewind().map_err(SourceError::Io)?;
            let mut extract_reader =
                zstd::stream::read::Decoder::new(&mut file).map_err(SourceError::Io)?;
            extract_reader
                .window_log_max(crate::compression_limits::zstd_window_log_max_for_budget(
                    limits.docker_tar_total_bytes,
                ))
                .map_err(SourceError::Io)?;
            unpack_tar_reader(extract_reader, destination, limits, true)
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
    enforce_per_file_cap: bool,
) -> Result<DockerExtractReport, SourceError> {
    let mut validation_archive = tar::Archive::new(&mut file);
    validate_docker_archive_plan(&mut validation_archive, limits, enforce_per_file_cap)?;

    file.rewind().map_err(SourceError::Io)?;
    unpack_tar_reader(&mut file, destination, limits, enforce_per_file_cap)
}

fn validate_tar_reader(
    reader: impl Read,
    limits: crate::SourceLimits,
    enforce_per_file_cap: bool,
) -> Result<(), SourceError> {
    let mut archive = tar::Archive::new(reader);
    validate_docker_archive_plan(&mut archive, limits, enforce_per_file_cap)
}

fn unpack_tar_reader(
    reader: impl Read,
    destination: &Path,
    limits: crate::SourceLimits,
    enforce_per_file_cap: bool,
) -> Result<DockerExtractReport, SourceError> {
    let mut archive = tar::Archive::new(reader);
    extract_docker_archive_entries(&mut archive, destination, limits, enforce_per_file_cap)
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
    for (entry_index, entry) in archive.entries().map_err(SourceError::Io)?.enumerate() {
        if entry_index >= MAX_DOCKER_TAR_ENTRIES {
            return Err(docker_archive_entry_count_error("extracted tree"));
        }
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
    enforce_per_file_cap: bool,
) -> Result<(), SourceError> {
    let mut cumulative_bytes: u64 = 0;
    for (entry_index, entry) in archive.entries().map_err(SourceError::Io)?.enumerate() {
        if entry_index >= MAX_DOCKER_TAR_ENTRIES {
            return Err(docker_archive_entry_count_error("plan"));
        }
        let entry = entry.map_err(SourceError::Io)?;
        let path = entry.path().map_err(SourceError::Io)?;
        let size = entry.header().entry_size().map_err(SourceError::Io)?;
        let file_type = entry.header().entry_type();
        validate_docker_archive_entry(&path, file_type)?;

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

        if enforce_per_file_cap && docker_archive_entry_exceeds_scan_cap(file_type, size, limits) {
            continue;
        }
    }

    Ok(())
}

fn extract_docker_archive_entries<R: Read>(
    archive: &mut tar::Archive<R>,
    destination: &Path,
    limits: crate::SourceLimits,
    enforce_per_file_cap: bool,
) -> Result<DockerExtractReport, SourceError> {
    let mut cumulative_bytes: u64 = 0;
    let mut report = DockerExtractReport::default();
    for (entry_index, entry) in archive.entries().map_err(SourceError::Io)?.enumerate() {
        if entry_index >= MAX_DOCKER_TAR_ENTRIES {
            return Err(docker_archive_entry_count_error("entry stream"));
        }
        let mut entry = entry.map_err(SourceError::Io)?;
        let path = entry.path().map_err(SourceError::Io)?.into_owned();
        let size = entry.header().entry_size().map_err(SourceError::Io)?;
        validate_docker_archive_entry(&path, entry.header().entry_type())?;

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

        if enforce_per_file_cap
            && docker_archive_entry_exceeds_scan_cap(entry.header().entry_type(), size, limits)
        {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            report.push_error(docker_archive_entry_over_entry_cap_error(
                &path,
                size,
                limits.docker_tar_entry_bytes,
            ));
            continue;
        }

        let file_type = entry.header().entry_type();
        if !file_type.is_file() && !file_type.is_dir() {
            continue;
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
    _file_type: tar::EntryType,
) -> Result<(), SourceError> {
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
) -> bool {
    file_type.is_file() && size > limits.docker_tar_entry_bytes
}
