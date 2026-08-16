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
        "docker archive {archive_kind} exceeds the {MAX_DOCKER_TAR_ENTRIES}-entry cap (likely a tar-header bomb); remaining entries were not scanned"
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
        "docker image unpack exceeded the {total_bytes}-byte image-wide budget at entry '{}' (likely zip-bomb); remaining entries were not scanned",
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

        // process_entry order: exclude + skip-extension/LFS before OverMaxSize so
        // large vendored/binary members stay quiet Excluded/Binary skips instead
        // of coverage-gap Err rows that flip the scan to partial.
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
        // process_entry probes Git-LFS for EVERY skip-extension first (including
        // logo.png placeholders), then only non-pointers may take image metadata
        // or Binary skip. Match that order here.
        let mut prebuffered: Option<Vec<u8>> = None;
        const GIT_LFS_POINTER_MAX_BYTES: u64 = 1024;
        if skip_extension {
            if size <= GIT_LFS_POINTER_MAX_BYTES {
                let mut bytes = vec![0_u8; size as usize];
                if size > 0 {
                    entry.read_exact(&mut bytes).map_err(SourceError::Io)?;
                }
                if keyhog_core::git_lfs::is_git_lfs_pointer(&bytes) {
                    let _event = crate::record_skip_event(crate::SourceSkipEvent::GitLfsPointer);
                    continue;
                }
                if !may_image {
                    let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
                    continue;
                }
                // Image-shaped skip-extension that is not an LFS pointer: reuse
                // the already-read bytes for metadata extraction below.
                prebuffered = Some(bytes);
            } else if !may_image {
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
                continue;
            }
        }

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

        // Large plain members: stream ~1 MiB windows from the tar entry instead
        // of buffering up to the 100 MiB member-scan cap (restores near-window
        // peak RSS vs the prior unpack+mmap path).
        let window_size = 1024 * 1024; // matches filesystem::reader::DEFAULT_WINDOW_SIZE
        let window_overlap = 128 * 1024; // matches filesystem::reader::DEFAULT_WINDOW_OVERLAP

        // Extensionless: sniff a bounded prefix first (process_entry parity) so a
        // large ELF/Mach-O/PE is not buffered up to the 100 MiB scan cap only to
        // be discarded as Binary. Containers still need a full buffer.
        // Keep parity with FilesystemSource process_entry (extract.rs = 512).
        const EXTENSIONLESS_BINARY_PREFIX_SNIFF_BYTES: usize = 512;
        if ext.is_empty() {
            let prefix_len = std::cmp::min(
                EXTENSIONLESS_BINARY_PREFIX_SNIFF_BYTES as u64,
                size.min(member_scan_cap),
            ) as usize;
            let mut prefix = vec![0_u8; prefix_len];
            if prefix_len > 0 {
                entry.read_exact(&mut prefix).map_err(SourceError::Io)?;
            }
            let after_prefix = size.saturating_sub(prefix_len as u64);
            if layer_member_looks_like_container(&prefix) {
                prebuffered = Some(finish_buffered_layer_member(
                    &mut entry,
                    prefix,
                    after_prefix,
                )?);
            } else if crate::filesystem::has_utf16_bom_prefix(&prefix) {
                // looks_binary_prefix deliberately admits UTF-16 BOM text. Large
                // extensionless UTF-16 must whole-member decode (emit_archive_leaf
                // path); lossy plain windows would garble every other byte and
                // miss secrets.
                prebuffered = Some(finish_buffered_layer_member(
                    &mut entry,
                    prefix,
                    after_prefix,
                )?);
            } else if crate::filesystem::looks_binary_prefix(&prefix) {
                // Magic/NUL-run extensionless binaries match process_entry: Binary
                // skip (no printable-string mining of ELF/PE payloads).
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
                drain_layer_member_remainder(&mut entry, after_prefix)?;
                continue;
            } else if crate::filesystem::looks_binary(&prefix) {
                // C0-density binary without a confident magic/NUL prefix: buffer
                // for archive-binary / printable-strings. Do NOT lossy-window as
                // text (junk matches); this matches the extensioned sniff arm.
                prebuffered = Some(finish_buffered_layer_member(
                    &mut entry,
                    prefix,
                    after_prefix,
                )?);
            } else if size > window_size as u64 {
                let stream_size = size.min(member_scan_cap);
                if !stream_plain_layer_member_windows(
                    &mut entry,
                    stream_size,
                    &entry_name,
                    window_size,
                    window_overlap,
                    prefix,
                    emit,
                )? {
                    return Ok(false);
                }
                let leftover = size.saturating_sub(stream_size);
                if leftover > 0 {
                    drain_layer_member_remainder(&mut entry, leftover)?;
                    let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
                    if !emit(Err(docker_archive_entry_over_entry_cap_error(
                        &path,
                        size,
                        member_scan_cap,
                    ))) {
                        return Ok(false);
                    }
                }
                continue;
            } else {
                prebuffered = Some(finish_buffered_layer_member(
                    &mut entry,
                    prefix,
                    after_prefix,
                )?);
            }
        }

        if prebuffered.is_none()
            && size > window_size as u64
            && !layer_member_requires_full_buffer(ext)
        {
            // Prefix-sniff before lossy UTF-8 windows so control-heavy / magic
            // binaries with a non-skip extension do not produce junk matches.
            // Binary members fall through to the buffered emit_in_memory path
            // (archive-binary / printable strings), matching extract.rs.
            const PREFIX_SNIFF_BYTES: usize = 1024;
            let sniff_len =
                std::cmp::min(PREFIX_SNIFF_BYTES as u64, size.min(member_scan_cap)) as usize;
            let mut prefix = vec![0_u8; sniff_len];
            if sniff_len > 0 {
                entry.read_exact(&mut prefix).map_err(SourceError::Io)?;
            }
            let after_prefix = size.saturating_sub(sniff_len as u64);
            if crate::filesystem::looks_binary_prefix(&prefix)
                || crate::filesystem::looks_binary(&prefix)
            {
                prebuffered = Some(finish_buffered_layer_member(
                    &mut entry,
                    prefix,
                    after_prefix,
                )?);
            } else {
                let stream_size = size.min(member_scan_cap);
                if !stream_plain_layer_member_windows(
                    &mut entry,
                    stream_size,
                    &entry_name,
                    window_size,
                    window_overlap,
                    prefix,
                    emit,
                )? {
                    return Ok(false);
                }
                let leftover = size.saturating_sub(stream_size);
                if leftover > 0 {
                    drain_layer_member_remainder(&mut entry, leftover)?;
                    let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
                    if !emit(Err(docker_archive_entry_over_entry_cap_error(
                        &path,
                        size,
                        member_scan_cap,
                    ))) {
                        return Ok(false);
                    }
                }
                continue;
            }
        }

        let read_bytes = if let Some(bytes) = prebuffered {
            bytes
        } else {
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
            read.bytes
        };

        if may_image {
            match crate::filesystem::try_emit_image_metadata_member(
                &entry_name,
                &read_bytes,
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

        // PDF keeps the dedicated extractor FilesystemSource used after unpack.
        if ext.eq_ignore_ascii_case("pdf") {
            if !crate::filesystem::try_emit_pdf_member(&entry_name, read_bytes, emit) {
                return Ok(false);
            }
            continue;
        }

        // Top-level layer 7z/RAR (by extension or content sniff) uses the shared
        // in-memory extractors, matching process_entry coverage after unpack.
        // Require matching magic so a text file named keys.7z still leaf-scans.
        let sniffed = crate::filesystem::container_extension_from_prefix(&read_bytes);
        let archive_kind = match sniffed {
            Some("7z") if ext.is_empty() || ext.eq_ignore_ascii_case("7z") => Some("7z"),
            Some("rar") if ext.is_empty() || ext.eq_ignore_ascii_case("rar") => Some("rar"),
            _ => None,
        };
        if let Some(archive_kind) = archive_kind {
            if !crate::filesystem::emit_top_level_seven_zip_or_rar_member(
                archive_kind,
                read_bytes,
                &entry_name,
                keyhog_core::DEFAULT_MAX_FILE_SIZE_BYTES,
                respect_default_excludes,
                emit,
            ) {
                return Ok(false);
            }
            continue;
        }

        // Zip-family openpack (jar/zip/apk/…) uses the EOCD-capable in-memory
        // ZipArchive reader so launcher-prefixed Spring Boot jars and SFX zips
        // still unpack. CRX/Cr24 that ZipArchive cannot open fail closed as
        // Unreadable coverage gaps (no in-memory openpack path yet).
        if crate::filesystem::is_openpack_archive_ext(ext) {
            if !crate::filesystem::emit_in_memory_zip_member(
                &entry_name,
                read_bytes,
                keyhog_core::DEFAULT_MAX_FILE_SIZE_BYTES,
                respect_default_excludes,
                emit,
            ) {
                return Ok(false);
            }
            continue;
        }

        // HAR expansion stays on the Docker streaming boundary so nested
        // .har members inside ordinary zip/tar/7z/RAR keep the historical
        // filesystem/archive leaf identity. Layer .har files still match
        // process_entry-after-unpack coverage (wire:har:*).
        if ext.eq_ignore_ascii_case("har") {
            let _decode = crate::profile::decode_span();
            match crate::har::try_expand_har(
                &read_bytes,
                &entry_name,
                keyhog_core::DEFAULT_MAX_FILE_SIZE_BYTES,
            ) {
                Some(har_chunks) => {
                    let mut derived_bytes = 0_u64;
                    for chunk in har_chunks {
                        if let Ok(chunk_ok) = &chunk {
                            derived_bytes =
                                derived_bytes.saturating_add(chunk_ok.data.len() as u64);
                        }
                        if !emit(chunk) {
                            crate::profile::add_derived_bytes(derived_bytes);
                            return Ok(false);
                        }
                    }
                    crate::profile::add_derived_bytes(derived_bytes);
                    continue;
                }
                None => {
                    tracing::info!(
                        path = entry_name.as_str(),
                        "HAR parse failed; scanning as plain layer member"
                    );
                }
            }
        }

        if !crate::filesystem::emit_in_memory_member(
            &entry_name,
            read_bytes,
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

fn drain_layer_member_remainder<R: Read>(entry: &mut R, remaining: u64) -> Result<(), SourceError> {
    if remaining == 0 {
        return Ok(());
    }
    let mut take = Read::take(entry, remaining);
    std::io::copy(&mut take, &mut std::io::sink()).map_err(SourceError::Io)?;
    Ok(())
}

fn layer_member_requires_full_buffer(ext: &str) -> bool {
    // Extensionless members are prefix-sniffed by the caller so large binaries are
    // not buffered whole only to be discarded. lz4/sz must be here: they are real
    // compressed formats in CompressedFormat::from_ext, and routing them to the
    // plain UTF-8 window path would silently miss secrets in their payloads.
    if crate::filesystem::is_openpack_archive_ext(ext) {
        return true;
    }
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "pdf"
            | "har"
            | "7z"
            | "rar"
            | "zip"
            | "jar"
            | "war"
            | "ear"
            | "apk"
            | "ipa"
            | "whl"
            | "tar"
            | "tgz"
            | "tbz"
            | "tbz2"
            | "txz"
            | "gz"
            | "bz2"
            | "xz"
            | "zst"
            | "zstd"
            | "lz4"
            | "sz"
            | "png"
            | "jpg"
            | "jpeg"
            | "tif"
            | "tiff"
            | "webp"
    )
}

/// Stream a large plain UTF-8 layer member in ~1 MiB windows from the tar entry
/// so peak RAM stays near one window instead of the full member-scan cap.
/// Finish buffering a layer member after a prefix sniff.
///
/// Callers only reach this after the `size > member_scan_cap` admit guard, so
/// the unread remainder always fits in the scan cap (no leftover drain).
fn finish_buffered_layer_member<R: Read>(
    entry: &mut R,
    mut bytes: Vec<u8>,
    after_prefix: u64,
) -> Result<Vec<u8>, SourceError> {
    if after_prefix > 0 {
        let mut take = Read::take(entry, after_prefix);
        take.read_to_end(&mut bytes).map_err(SourceError::Io)?;
    }
    Ok(bytes)
}

fn stream_plain_layer_member_windows<R: Read>(
    entry: &mut R,
    size: u64,
    entry_name: &str,
    window_size: usize,
    window_overlap: usize,
    initial: Vec<u8>,
    emit: &mut dyn FnMut(Result<keyhog_core::Chunk, SourceError>) -> bool,
) -> Result<bool, SourceError> {
    use keyhog_core::{Chunk, ChunkMetadata};

    let initial_len = initial.len() as u64;
    if initial_len > size {
        return Err(SourceError::Other(
            "layer member prefix longer than declared size".into(),
        ));
    }
    let mut carry: Vec<u8> = initial;
    let mut absolute_offset: usize = 0;
    let mut base_line: usize = 0;
    let mut remaining = size - initial_len;
    loop {
        let need = window_size.saturating_sub(carry.len());
        let mut buf = carry;
        if need > 0 && remaining > 0 {
            let to_read = std::cmp::min(need as u64, remaining) as usize;
            let start = buf.len();
            buf.resize(start + to_read, 0);
            // `Read::read` may legally return fewer bytes than requested without
            // being at EOF (gzip/zstd inflate does this on nearly every call), so
            // fill the window in a loop. Only a 0-byte read is real EOF; treating
            // a short read as EOF silently dropped the rest of the member.
            let mut got = 0usize;
            while got < to_read {
                let n = entry
                    .read(&mut buf[start + got..])
                    .map_err(SourceError::Io)?;
                if n == 0 {
                    break;
                }
                got += n;
            }
            buf.truncate(start + got);
            if got < to_read {
                // Real EOF before declared size (truncated layer).
                // - got==0 and absolute_offset>0: buf is overlap carry already
                //   emitted as the tail of the previous window; do not re-emit.
                // - got==0 and absolute_offset==0: buf still holds the never-
                //   emitted sniff prefix; fall through and emit it once.
                // - got>0: emit the truncated window that includes new bytes.
                remaining = 0;
                if got == 0 && absolute_offset > 0 {
                    return Ok(true);
                }
            } else {
                remaining = remaining.saturating_sub(got as u64);
            }
        }
        if buf.is_empty() {
            return Ok(true);
        }
        // Lossy decode matches the filesystem window path: a multi-byte UTF-8
        // sequence split across a window boundary must not abandon streaming or
        // reset base_offset/base_line via emit_in_memory_member.
        let text = String::from_utf8_lossy(&buf);
        if !text.is_empty()
            && !emit(Ok(Chunk {
                data: text.into_owned().into(),
                metadata: ChunkMetadata {
                    source_type: keyhog_core::intern_source_type("filesystem/archive"),
                    path: Some(entry_name.to_owned().into()),
                    base_offset: absolute_offset,
                    base_line,
                    size_bytes: Some(size),
                    decoded_span: None,
                    ..Default::default()
                },
            }))
        {
            return Ok(false);
        }
        if remaining == 0 {
            return Ok(true);
        }
        let overlap = std::cmp::min(window_overlap, buf.len().saturating_sub(1));
        let keep_from = buf.len().saturating_sub(overlap);
        base_line += buf[..keep_from].iter().filter(|&&b| b == b'\n').count();
        absolute_offset += keep_from;
        carry = buf[keep_from..].to_vec();
    }
}

fn layer_member_may_carry_image_metadata(ext: &str) -> bool {
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "png" | "jpg" | "jpeg" | "tif" | "tiff" | "webp"
    )
}

fn layer_member_looks_like_container(bytes: &[u8]) -> bool {
    // Reuse the filesystem extensionless-container detector so tar/gzip/zip/
    // classification cannot drift from emit_archive_member / process_entry.
    crate::filesystem::container_extension_from_prefix(bytes).is_some()
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
                "docker archive cumulative size exceeds {} bytes at entry '{}' (likely zip-bomb)",
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
                "docker archive cumulative size exceeds {} bytes at entry '{}' (likely zip-bomb)",
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
