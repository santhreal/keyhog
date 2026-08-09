use keyhog_core::{Chunk, SourceError};
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

/// Remaining unpack budget shared by EVERY tar in one image.
///
/// `docker_tar_total_bytes` was enforced with a fresh accumulator per tar, so
/// it bounded one tar and nothing bounded their SUM. An image is an outer tar
/// plus one tar per layer, and Docker permits 127 layers, so the 8 GiB default
/// admitted ~1 TiB of unpacking per image with every individual check passing
/// and no operator knob that said otherwise. Measured on a 2-layer image:
/// `--limit-docker-tar-total-bytes 5104B` unpacked 5104 + 4161 + 4096 = 13361
/// bytes with no truncation, because each tar restarted the count at zero.
///
/// One cell, decremented across every tar in the image, makes the declared cap
/// mean what its name says. `AtomicU64` rather than `&mut` so layers may be
/// walked concurrently without threading a lock through the unpack path.
pub(super) struct DockerUnpackBudget {
    remaining: std::sync::atomic::AtomicU64,
}

impl DockerUnpackBudget {
    pub(super) fn new(total_bytes: u64) -> Self {
        Self {
            remaining: std::sync::atomic::AtomicU64::new(total_bytes),
        }
    }

    /// Charge `bytes` against the image budget. `false` means the image-scoped
    /// ceiling is spent and the caller must stop unpacking.
    fn charge(&self, bytes: u64) -> bool {
        use std::sync::atomic::Ordering;
        self.remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                left.checked_sub(bytes)
            })
            .is_ok()
    }

    /// Bytes still available to this image across all remaining tars.
    fn remaining(&self) -> u64 {
        self.remaining.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Coverage-gap error for an image that exhausted [`DockerUnpackBudget`].
fn docker_image_budget_error(path: &Path, total_bytes: u64) -> SourceError {
    let _event = crate::record_skip_event(crate::SourceSkipEvent::ArchiveTruncated);
    SourceError::Other(format!(
        "docker image unpack exceeded the {total_bytes}-byte image-wide budget at entry '{}' \
         (likely zip-bomb); remaining entries were not scanned",
        path.display()
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

    pub(super) fn into_rows(self) -> Vec<Result<Chunk, SourceError>> {
        self.errors.into_iter().map(Err).collect()
    }
}

pub(super) fn unpack_tar(
    archive_path: &Path,
    destination: &Path,
    limits: crate::SourceLimits,
    budget: &DockerUnpackBudget,
) -> Result<DockerExtractReport, SourceError> {
    let file = File::open(archive_path).map_err(SourceError::Io)?;
    // Disk unpack keeps validate-before-write so a tar-header bomb cannot create
    // entries before the cap refuses the archive. Production layer scanning uses
    // `stream_layer_archive_chunks` instead and never materializes members.
    unpack_open_tar(file, destination, limits, false, budget)
}

pub(super) fn unpack_layer_archive(
    archive_path: &Path,
    destination: &Path,
    limits: crate::SourceLimits,
    budget: &DockerUnpackBudget,
) -> Result<DockerExtractReport, SourceError> {
    let mut file = File::open(archive_path).map_err(SourceError::Io)?;
    let encoding = layer_archive_encoding(&mut file)?;
    file.rewind().map_err(SourceError::Io)?;

    match encoding {
        LayerArchiveEncoding::RawTar => unpack_open_tar(file, destination, limits, true, budget),
        LayerArchiveEncoding::GzipTar => {
            validate_tar_reader(
                flate2::read::MultiGzDecoder::new(&mut file),
                limits,
                true,
                budget,
            )?;
            file.rewind().map_err(SourceError::Io)?;
            unpack_tar_reader(
                flate2::read::MultiGzDecoder::new(&mut file),
                destination,
                limits,
                true,
                budget,
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
            validate_tar_reader(validation_reader, limits, true, budget)?;

            file.rewind().map_err(SourceError::Io)?;
            let mut extract_reader =
                zstd::stream::read::Decoder::new(&mut file).map_err(SourceError::Io)?;
            extract_reader
                .window_log_max(crate::compression_limits::zstd_window_log_max_for_budget(
                    limits.docker_tar_total_bytes,
                ))
                .map_err(SourceError::Io)?;
            unpack_tar_reader(extract_reader, destination, limits, true, budget)
        }
    }
}

/// Stream one layer archive into scannable chunks without materializing files.
///
/// Whiteout markers (`.wh.<name>`) and opaque-dir markers (`.wh..wh..opq`) are
/// ordinary tar members here: they are scanned when they carry bytes and never
/// suppress members from earlier layers. That matches the product contract that
/// every layer is examined independently, including files a later layer deletes.
///
/// Returns `Ok(false)` when the consumer stops; hard bomb/path failures return
/// `Err` so the image cannot report clean coverage after a truncated unpack.
pub(super) fn stream_layer_archive_chunks(
    archive_path: &Path,
    limits: crate::SourceLimits,
    budget: &DockerUnpackBudget,
    respect_default_excludes: bool,
    emit: &mut impl FnMut(Result<Chunk, SourceError>) -> bool,
) -> Result<bool, SourceError> {
    let mut file = File::open(archive_path).map_err(SourceError::Io)?;
    let encoding = layer_archive_encoding(&mut file)?;
    file.rewind().map_err(SourceError::Io)?;

    match encoding {
        LayerArchiveEncoding::RawTar => {
            stream_layer_tar_reader(file, limits, budget, respect_default_excludes, emit)
        }
        LayerArchiveEncoding::GzipTar => stream_layer_tar_reader(
            flate2::read::MultiGzDecoder::new(file),
            limits,
            budget,
            respect_default_excludes,
            emit,
        ),
        LayerArchiveEncoding::ZstdTar => {
            let mut reader = zstd::stream::read::Decoder::new(file).map_err(SourceError::Io)?;
            reader
                .window_log_max(crate::compression_limits::zstd_window_log_max_for_budget(
                    limits.docker_tar_total_bytes,
                ))
                .map_err(SourceError::Io)?;
            stream_layer_tar_reader(reader, limits, budget, respect_default_excludes, emit)
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
    validate_extracted_tree_with_limits(&mut archive, limits, &DockerUnpackBudget::new(total_cap))
}

fn unpack_open_tar(
    mut file: File,
    destination: &Path,
    limits: crate::SourceLimits,
    enforce_per_file_cap: bool,
    budget: &DockerUnpackBudget,
) -> Result<DockerExtractReport, SourceError> {
    let mut validation_archive = tar::Archive::new(&mut file);
    validate_docker_archive_plan(
        &mut validation_archive,
        limits,
        enforce_per_file_cap,
        budget,
    )?;

    file.rewind().map_err(SourceError::Io)?;
    unpack_tar_reader(&mut file, destination, limits, enforce_per_file_cap, budget)
}

fn validate_tar_reader(
    reader: impl Read,
    limits: crate::SourceLimits,
    enforce_per_file_cap: bool,
    budget: &DockerUnpackBudget,
) -> Result<(), SourceError> {
    let mut archive = tar::Archive::new(reader);
    validate_docker_archive_plan(&mut archive, limits, enforce_per_file_cap, budget)
}

fn unpack_tar_reader(
    reader: impl Read,
    destination: &Path,
    limits: crate::SourceLimits,
    enforce_per_file_cap: bool,
    budget: &DockerUnpackBudget,
) -> Result<DockerExtractReport, SourceError> {
    let mut archive = tar::Archive::new(reader);
    extract_docker_archive_entries(
        &mut archive,
        destination,
        limits,
        enforce_per_file_cap,
        budget,
    )
}

fn stream_layer_tar_reader(
    reader: impl Read,
    limits: crate::SourceLimits,
    budget: &DockerUnpackBudget,
    respect_default_excludes: bool,
    emit: &mut impl FnMut(Result<Chunk, SourceError>) -> bool,
) -> Result<bool, SourceError> {
    let mut archive = tar::Archive::new(reader);
    for (entry_index, entry) in archive.entries().map_err(SourceError::Io)?.enumerate() {
        if entry_index >= MAX_DOCKER_TAR_ENTRIES {
            return Err(docker_archive_entry_count_error("layer stream"));
        }
        let mut entry = entry.map_err(SourceError::Io)?;
        let path = entry.path().map_err(SourceError::Io)?.into_owned();
        let size = entry.header().entry_size().map_err(SourceError::Io)?;
        let file_type = entry.header().entry_type();
        validate_docker_archive_entry(&path, file_type)?;

        if !budget.charge(size) {
            return Err(docker_image_budget_error(
                &path,
                limits.docker_tar_total_bytes,
            ));
        }

        if !file_type.is_file() {
            // Directories are structural. Symlinks/hardlinks/devices are ignored
            // without following or materializing host targets (same as unpack).
            continue;
        }

        // Keep the streaming path's effective per-file ceiling aligned with
        // FilesystemSource (`DEFAULT_MAX_FILE_SIZE_BYTES`, 100 MiB) even when the
        // docker tar entry bomb cap is higher (128 MiB). Otherwise large members
        // that the unpack+walk path refused are buffered whole into RAM here.
        let member_scan_cap = limits
            .docker_tar_entry_bytes
            .min(keyhog_core::DEFAULT_MAX_FILE_SIZE_BYTES);
        if file_type.is_file() && size > member_scan_cap {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            if !emit(Err(docker_archive_entry_over_entry_cap_error(
                &path,
                size,
                member_scan_cap,
            ))) {
                return Ok(false);
            }
            continue;
        }

        // Match FilesystemSource walk accounting: every admitted file member is an
        // input unit even when a later Binary/image/PDF route skips emission.
        crate::profile::add_input_units(1);
        crate::profile::add_input_bytes(size);

        let entry_name = path.to_string_lossy().replace('\\', "/");
        if respect_default_excludes && crate::filesystem::is_default_excluded_path(&entry_name) {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Excluded);
            continue;
        }

        let ext = Path::new(&entry_name)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("");
        let skip_extension = !ext.is_empty() && crate::filesystem::is_default_skip_extension(ext);
        let may_image = layer_member_may_carry_image_metadata(ext);
        // Non-image skip-extensions match FilesystemSource: counted Binary and
        // never read. Image extensions (including TIFF, which is not on the skip
        // list) still need their bytes for metadata.
        if skip_extension && !may_image {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
            continue;
        }

        let read = crate::capped_read::read_to_cap(&mut entry, member_scan_cap, Some(size))
            .map_err(SourceError::Io)?;
        if read.truncated {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            if !emit(Err(docker_archive_entry_over_entry_cap_error(
                &path,
                size.max(member_scan_cap.saturating_add(1)),
                member_scan_cap,
            ))) {
                return Ok(false);
            }
            continue;
        }

        if may_image {
            match crate::filesystem::try_emit_image_metadata_member(
                &entry_name,
                &read.bytes,
                ext,
                emit,
            )? {
                Some(false) => return Ok(false),
                Some(true) => continue,
                None => {
                    if skip_extension {
                        let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
                        continue;
                    }
                }
            }
        }

        // Extensionless members: same container-or-binary sniff as process_entry.
        // Sniff only the opening prefix (FilesystemSource uses
        // EXTENSIONLESS_BINARY_PREFIX_SNIFF_BYTES == 1024). looks_binary_prefix
        // trips on any 4-byte NUL run in the slice it is given; feeding the
        // whole member would drop ordinary text that happens to contain NULs
        // later (false Binary skip, silent miss).
        if ext.is_empty() {
            if layer_member_looks_like_container(&read.bytes) {
                // Fall through to the shared archive dispatcher.
            } else {
                const EXTENSIONLESS_BINARY_PREFIX_SNIFF_BYTES: usize = 1024;
                let prefix = &read.bytes[..read.bytes.len().min(EXTENSIONLESS_BINARY_PREFIX_SNIFF_BYTES)];
                if crate::filesystem::looks_binary_prefix(prefix) {
                    let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
                    continue;
                }
            }
        }

        // PDF keeps the dedicated extractor FilesystemSource used after unpack.
        if ext.eq_ignore_ascii_case("pdf") {
            if !crate::filesystem::try_emit_pdf_member(&entry_name, read.bytes, emit) {
                return Ok(false);
            }
            continue;
        }

        // 7z/RAR have no in-memory extractor on this path; record the coverage gap
        // the way emit_archive_leaf_member does for magic-matched containers so the
        // miss cannot read as a silent clean.
        if ext.eq_ignore_ascii_case("7z") || ext.eq_ignore_ascii_case("rar") {
            let format = if ext.eq_ignore_ascii_case("7z") {
                "7z"
            } else {
                "RAR"
            };
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            if !emit(Err(SourceError::Other(format!(
                "embedded {format} container '{entry_name}' has no in-memory extractor; its entries were not scanned"
            )))) {
                return Ok(false);
            }
            continue;
        }

        if !crate::filesystem::emit_in_memory_member(
            &entry_name,
            read.bytes,
            &entry_name,
            keyhog_core::DEFAULT_MAX_FILE_SIZE_BYTES,
            respect_default_excludes,
            emit,
        ) {
            return Ok(false);
        }
    }

    Ok(true)
}

fn layer_member_may_carry_image_metadata(ext: &str) -> bool {
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "png" | "jpg" | "jpeg" | "tif" | "tiff" | "webp"
    )
}

fn layer_member_looks_like_container(bytes: &[u8]) -> bool {
    crate::magic::starts_with_gzip(bytes)
        || crate::magic::starts_with_zstd_frame(bytes)
        || crate::magic::starts_with_lz4_frame(bytes)
        || crate::magic::starts_with_snappy_frame(bytes)
        || crate::magic::has_bzip2_header(bytes)
        || crate::magic::starts_with_xz_stream(bytes)
        || crate::magic::starts_with_zip_container_prefix(bytes)
        || bytes.starts_with(crate::magic::SEVEN_ZIP_PREFIX)
        || bytes.starts_with(crate::magic::RAR_PREFIX)
        || (bytes.len() > 262 && &bytes[257..262] == b"ustar")
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
    budget: &DockerUnpackBudget,
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

        // Checked against what the IMAGE has left, not against the per-tar cap,
        // so a later layer cannot restart the count at zero.
        cumulative_bytes = cumulative_bytes.saturating_add(size);
        if cumulative_bytes > budget.remaining() {
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
    budget: &DockerUnpackBudget,
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
        if cumulative_bytes > budget.remaining() {
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
    budget: &DockerUnpackBudget,
) -> Result<DockerExtractReport, SourceError> {
    let mut report = DockerExtractReport::default();
    for (entry_index, entry) in archive.entries().map_err(SourceError::Io)?.enumerate() {
        if entry_index >= MAX_DOCKER_TAR_ENTRIES {
            return Err(docker_archive_entry_count_error("entry stream"));
        }
        let mut entry = entry.map_err(SourceError::Io)?;
        let path = entry.path().map_err(SourceError::Io)?.into_owned();
        let size = entry.header().entry_size().map_err(SourceError::Io)?;
        validate_docker_archive_entry(&path, entry.header().entry_type())?;

        // The one site that SPENDS the image budget for disk unpack. Streaming
        // layer scans charge through `stream_layer_tar_reader` instead.
        if !budget.charge(size) {
            return Err(docker_image_budget_error(
                &path,
                limits.docker_tar_total_bytes,
            ));
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
