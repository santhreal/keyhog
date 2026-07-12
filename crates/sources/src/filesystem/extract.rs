use super::display_path;
use super::filter::{is_default_excluded, is_skip_extension};
use super::read;
use keyhog_core::MerkleIndex;
use keyhog_core::{Chunk, ChunkMetadata, SourceError};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

mod archive;
mod compressed;
mod hexnib;
mod pdf;
#[cfg(fuzzing)]
pub use pdf::fuzz_extract_pdf_text;
mod rar;
mod seven_zip;

// Re-export the archive entry-name path-traversal validator so the crate-root
// test facade (`testing::SourceTestApi`) can pin its security contract directly,
// keeping the unit coverage under `tests/` rather than an inline test module in
// this always-on source (the filesystem no-inline-tests folder contract).
pub(crate) use archive::validate_scan_archive_entry_name;

/// Aggregate decoded-byte ceiling used when `--max-file-size 0` removes the
/// per-file cap. Extraction/decoding still needs a hard bomb guard so an archive,
/// compressed stream, or PDF cannot expand without bound.
pub(super) const UNCAPPED_ARCHIVE_BUDGET: u64 = 1024 * 1024 * 1024;
const EXTENSIONLESS_BINARY_PREFIX_SNIFF_BYTES: usize = 1024;

/// Upper bound on a Git-LFS pointer file's size. A canonical pointer is the
/// three short lines `version …` / `oid sha256:…` / `size …` (~130 bytes; a few
/// hundred with optional `ext-*` lines), always well under 1 KiB. Gating the
/// whole-content pointer check on this bound means a large text file never pays
/// the pointer scan (Law 7) — only genuinely pointer-sized files are examined.
const GIT_LFS_POINTER_MAX_BYTES: usize = 1024;

/// Bounded, no-follow probe: is the file at `path` a Git-LFS pointer? Reads at
/// most one pointer's worth of bytes through the same `O_NOFOLLOW` safe open the
/// real content reader uses, so it cannot be redirected by a symlink swap. The
/// caller MUST have already confirmed the file is pointer-sized, so this never
/// reads a large asset — the read is a rounding error (Law 7). A probe that
/// fails to open/read returns `false`, so the caller falls through to its normal
/// (loud, counted) skip path rather than silently dropping the file (Law 10).
fn file_is_git_lfs_pointer(path: &Path) -> bool {
    let mut buf = [0u8; GIT_LFS_POINTER_MAX_BYTES];
    match read::read_file_prefix_safe(path, &mut buf) {
        Ok(n) => keyhog_core::git_lfs::is_git_lfs_pointer(&buf[..n]),
        Err(_read_error) => false,
    }
}

pub(crate) fn extraction_total_budget(max_size: u64) -> u64 {
    if max_size == 0 {
        UNCAPPED_ARCHIVE_BUDGET
    } else {
        max_size.saturating_mul(4)
    }
}

pub(super) fn extraction_total_budget_usize(max_size: u64) -> usize {
    match usize::try_from(extraction_total_budget(max_size)) {
        Ok(value) => value,
        Err(_error) => usize::MAX,
    }
}

pub(crate) fn duplicate_zip_central_entries_error_for_test(path: &Path) -> Result<String, String> {
    archive::duplicate_zip_central_entries_error_for_test(path)
}

pub(crate) fn duplicate_zip_local_entry_data_error_for_test(
    path: &Path,
    compressed_size: u64,
) -> Result<String, String> {
    archive::duplicate_zip_local_entry_data_error_for_test(path, compressed_size)
}

pub(crate) fn duplicate_zip_reopen_error_for_test(path: &Path) -> Option<String> {
    archive::duplicate_zip_reopen_error_for_test(path)
}

/// Test whether `path` is a symlink. No cache: the walker visits each
/// path exactly once, so a process-lifetime `DashMap<PathBuf, bool>`
/// only ever sees a single lookup per key and retained one PathBuf per
/// file for the whole scan (1GB+ on a multi-million-file tree) while
/// providing a ~0% hit rate. A bare `symlink_metadata` stat is the
/// single-pass-correct choice. (Was KH-41 SYMLINK_CACHE; removed - the
/// cache was pure retained-forever overhead on single-pass walks.)
fn is_symlink(path: &Path) -> bool {
    // stat failure => treated as non-symlink (the file is still walked/read).
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .map_or(false, |is_link| is_link)
}

/// True when `path` begins with a UTF-16 byte-order mark (`FF FE` LE / `FE FF`
/// BE). Used to keep large UTF-16 files off the raw-byte windowed/mmap path,
/// which would NUL-interleave their ASCII secrets and mis-count their lines
/// (see the call site in `process_entry`). The probe is a no-follow-safe
/// 2-byte prefix read.
///
/// LAW10: a failed or short prefix probe returns `false` (not a skip); the
/// windowed path still runs and any unreadable file is surfaced and recorded
/// there as a counted skip, so this classifier never yields a silent false-clean.
fn file_starts_with_utf16_bom(path: &Path) -> bool {
    let mut bom = [0u8; 2];
    matches!(read::read_file_prefix_safe(path, &mut bom), Ok(2))
        && (bom == [0xFF, 0xFE] || bom == [0xFE, 0xFF])
}

pub(super) fn record_binary_without_printable_strings(path: &str) {
    let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
    tracing::warn!(
        path,
        "binary content yielded no printable strings; NOT scanned"
    );
}

pub(super) fn record_default_excluded_archive_entry(archive_display: &str, entry_name: &str) {
    let _event = crate::record_skip_event(crate::SourceSkipEvent::Excluded);
    // LAW10: default-excluded archive entries are counted in SourceSkipEvent
    // telemetry and reported in scan coverage summaries.
    tracing::debug!(
        archive = archive_display,
        entry = entry_name,
        "skipping archive entry: default-excluded path; NOT scanned"
    );
}

/// Decode an extracted archive/compressed entry's bytes into a chunk using the
/// SAME canonical decoder as the filesystem read path
/// (`decode_text_file_owned_or_bytes`), so a UTF-16-BOM entry — a Windows
/// config/log/transcript packed inside a zip / tar / 7z / gz — is transcoded to
/// contiguous UTF-8 and its ASCII secrets stay scannable. Raw `String::from_utf8`
/// fails on the `FF FE` BOM, and the NUL-separated ASCII bytes (`g\0h\0p\0…`)
/// can't reform an 8-char printable run, so the secret vanished as a silent
/// false "clean". Returns:
///   * `Some(Ok(text chunk))` tagged `text_source_type`;
///   * `Some(Ok(printable-strings chunk))` tagged `binary_source_type` when the
///     entry is genuine binary yet holds >=8-char printable runs;
///   * `None` for an empty entry, or for a binary entry with no printable run —
///     the latter recorded as a binary coverage skip so it is never a silent
///     clean (LAW10).
///
/// One canonical decoder replaces five divergent `String::from_utf8` entry
/// decoders across the zip / tar / 7z / compressed extractors (NO DUPLICATION,
/// Law 10 recall parity with the walker read path).
pub(super) fn chunk_from_extracted_entry(
    content: Vec<u8>,
    entry_path: String,
    text_source_type: &str,
    binary_source_type: &str,
) -> Option<Result<Chunk, SourceError>> {
    match read::decode_text_file_owned_or_bytes(content) {
        Ok(text) if !text.is_empty() => Some(Ok(Chunk {
            data: text.into(),
            metadata: ChunkMetadata {
                source_type: text_source_type.into(),
                path: Some(entry_path.into()),
                ..Default::default()
            },
        })),
        Ok(_) => None, // empty entry: nothing to scan, not a coverage gap
        Err(bytes) => {
            let strings = crate::strings::extract_printable_strings(
                &bytes,
                crate::strings::MIN_PRINTABLE_STRING_LEN,
            );
            if strings.is_empty() {
                record_binary_without_printable_strings(&entry_path);
                None
            } else {
                tracing::info!(
                    entry = %entry_path,
                    "archive/compressed entry is not decodable text; scanning printable strings"
                );
                Some(Ok(Chunk {
                    data: crate::strings::join_sensitive_strings(&strings, "\n"),
                    metadata: ChunkMetadata {
                        source_type: binary_source_type.into(),
                        path: Some(entry_path.into()),
                        ..Default::default()
                    },
                }))
            }
        }
    }
}

/// Maximum archive-within-archive nesting any extractor will descend. Shared by
/// the canonical member dispatcher below so tar/zip/7z all cap nesting at the
/// same depth (each extractor previously hard-coded its own `= 8`).
pub(super) const MAX_NESTED_ARCHIVE_DEPTH: usize = 8;

/// Canonical re-dispatch for an archive MEMBER already read into memory: untar a
/// tar, unzip a zip-family container, decompress a single-stream compressed file
/// (then untar or scan its true bytes), else leaf-scan the bytes with the shared
/// UTF-16-aware decoder. EVERY container extractor (tar, zip, 7z, ...) routes its
/// members through here, so a nested archive's contents are scanned no matter
/// which outer format carried it -- one dispatch point, not one copy per
/// extractor.
///
/// LAW10: before this existed, a compressed/archived member (`tar//x.gz`,
/// `app.7z//layer.tar`, ...) fell through to the printable-strings leaf and a
/// secret in its payload was a SILENT false-clean. Recursion is bounded by
/// `nested_depth` (cap [`MAX_NESTED_ARCHIVE_DEPTH`]) and the shared
/// `total_uncompressed` archive-bomb budget; the depth-exceeded case is surfaced
/// and counted, never a silent clean. Returns false when the consumer stopped.
#[allow(clippy::too_many_arguments)]
pub(super) fn emit_archive_member(
    entry_name: &str,
    content: Vec<u8>,
    member_display: &str,
    max_size: u64,
    total_uncompressed: &mut u64,
    nested_depth: usize,
    respect_default_excludes: bool,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) -> bool {
    let is_tar = compressed::entry_is_embedded_tar(entry_name, &content);
    let is_zip = !is_tar && archive::member_is_embedded_zip(entry_name, &content);
    let compressed_format = if is_tar || is_zip {
        None
    } else {
        compressed::compressed_member_format(entry_name)
    };

    if (is_tar || is_zip || compressed_format.is_some()) && nested_depth >= MAX_NESTED_ARCHIVE_DEPTH
    {
        // LAW10: a nested archive we refuse to descend is NOT scanned -- surface
        // and count it so the depth cap can never read as a silent clean.
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        return emit(Err(SourceError::Other(format!(
            "failed to scan embedded archive '{member_display}': maximum nested archive depth {MAX_NESTED_ARCHIVE_DEPTH} exceeded; embedded archive was not scanned"
        ))));
    }

    if is_tar {
        compressed::emit_tar_entries_with_state(
            &content,
            member_display,
            max_size,
            total_uncompressed,
            nested_depth + 1,
            respect_default_excludes,
            emit,
        );
        return true;
    }
    if is_zip {
        return archive::emit_embedded_zip_member(
            content,
            member_display,
            max_size,
            total_uncompressed,
            nested_depth,
            respect_default_excludes,
            emit,
        );
    }
    if let Some(format) = compressed_format {
        return compressed::emit_decompressed_member(
            format,
            &content,
            member_display,
            max_size,
            total_uncompressed,
            nested_depth,
            respect_default_excludes,
            emit,
        );
    }

    match chunk_from_extracted_entry(
        content,
        member_display.to_string(),
        "filesystem/archive",
        "filesystem/archive-binary",
    ) {
        Some(chunk) => emit(chunk),
        None => true,
    }
}

pub(super) fn report_archive_truncation(
    archive_display: &str,
    attempted_total: u64,
    total_budget: u64,
) -> SourceError {
    eprintln!(
        "keyhog: WARNING: aborting archive extraction of {archive_display} at {attempted_total} bytes \
         (> {total_budget} = 4x --max-file-size; archive-bomb guard) - remaining entries were \
         NOT scanned."
    );
    let _event = crate::record_skip_event(crate::SourceSkipEvent::ArchiveTruncated);
    SourceError::Other(format!(
        "archive extraction of '{archive_display}' was truncated at {attempted_total} bytes by the archive-bomb guard (budget {total_budget}); remaining entries were not scanned"
    ))
}

fn filesystem_over_max_size_error(path: &Path, size_bytes: u64, max_size: u64) -> SourceError {
    SourceError::Other(format!(
        "failed to scan filesystem file '{}': size {size_bytes} exceeds --max-file-size cap {max_size}; file was not scanned",
        display_path(path)
    ))
}

/// Minimum file size to use memory mapping. The crossover point is
/// platform-specific:
///
///   * Linux / macOS: mmap setup is sub-microsecond and avoids the
///     `read(2)` copy from kernel page cache to userland buffer. Worth
///     it as soon as the file is at least one page (4 KiB) - pick
///     64 KiB to keep tiny-config-file scans on the buffered path
///     where the syscall floor dominates either way.
///   * Windows: `MapViewOfFile` has more setup cost (security tokens,
///     section-object routing) and the `ReadFile` path is already
///     well-optimised by the OS for buffered I/O. Keep the historical
///     1 MiB threshold here to avoid regressing typical source-tree
///     scans.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const MMAP_THRESHOLD: u64 = 64 * 1024;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const MMAP_THRESHOLD: u64 = 1024 * 1024;

#[derive(Clone, Copy)]
struct FileLiveMetadata {
    mtime_ns: Option<u64>,
    size_bytes: u64,
    is_symlink: bool,
}

/// Per-entry chunk extraction. Reads the file, archive, or compressed
/// stream and feeds each resulting `Chunk` to `emit` as it is produced.
#[allow(clippy::too_many_arguments)]
pub(super) fn process_entry(
    entry: codewalk::FileEntry,
    merkle: &Option<Arc<MerkleIndex>>,
    skipped: &Arc<AtomicUsize>,
    default_exclude_root: &Path,
    max_size: u64,
    window_size: usize,
    window_overlap: usize,
    respect_default_excludes: bool,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) {
    let path = entry.path;

    // Built-in exclusion list (lock/minified/bundled/vendored). Gated on
    // `respect_default_excludes` so `--no-default-excludes` actually reaches this
    // in-process filter, not just the codewalk glob layer — otherwise a secret in
    // `package-lock.json` stays silently excluded even with the flag set (KH-55).
    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or(""); // LAW10: missing/non-string field => empty/placeholder; recall-safe
    let default_exclude_path = match path.strip_prefix(default_exclude_root) {
        Ok(relative) => relative.to_string_lossy(),
        Err(_) => std::borrow::Cow::Borrowed(filename), // LAW10: root-prefix mismatch uses basename-only default-exclude classification to avoid parent-directory false exclusions; recall-preserving
    };
    if respect_default_excludes && is_default_excluded(&default_exclude_path) {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Excluded);
        return;
    }
    // Minified/bundled exclusion (`.min.`/`.bundle.` infixes + `.chunk.js` suffix)
    // is now owned by the Tier-B `default_excludes.toml` and applied by the
    // `is_default_excluded` check above (DR-056) — no separate inline gate.

    let live_metadata = file_live_metadata(&path);
    let file_size = live_metadata.map_or(entry.size, |meta| meta.size_bytes);
    let live_mtime_ns = live_metadata.and_then(|meta| meta.mtime_ns);
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or(""); // LAW10: missing/non-string field => empty/placeholder; recall-safe

    // Compile the SKIP_EXTENSIONS array into a fast HashSet at startup to accelerate file-type screening (KH-45)
    if is_skip_extension(ext) {
        // A skip-extension file is normally dropped unread as binary. But Git-LFS
        // commits a pointer file that KEEPS the tracked asset's (binary)
        // extension — `logo.png`, `model.bin` — while its content is the tiny
        // text pointer, not the asset. So a skip-extension file that is
        // pointer-sized may be an unmaterialised LFS pointer whose real blob was
        // never on disk to scan. Probe only pointer-sized files (a real asset is
        // far larger) so the common LFS case is recorded with its precise remedy
        // (`git lfs pull`) instead of being mis-attributed to a plain binary
        // skip. The probe is prefix-only and gated on size, so it stays a
        // rounding error on a path that is otherwise read-free (Law 7).
        if file_size <= GIT_LFS_POINTER_MAX_BYTES as u64 && file_is_git_lfs_pointer(&path) {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::GitLfsPointer);
            return;
        }
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
        return;
    }

    if max_size > 0 && file_size > max_size {
        tracing::warn!(
            path = %path.display(),
            size_bytes = file_size,
            max_size,
            "skipping file: size exceeds --max-file-size cap"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
        if !emit(Err(filesystem_over_max_size_error(
            &path, file_size, max_size,
        ))) {
            return;
        }
        return;
    }

    if let (Some(idx), Some(meta)) = (merkle.as_ref(), live_metadata) {
        if !meta.is_symlink {
            if let Some(mtime_ns) = meta.mtime_ns {
                if idx.metadata_unchanged(&path, mtime_ns, meta.size_bytes) {
                    skipped.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        }
    }

    if ext.is_empty() {
        // Sniff a small structural prefix of files without extensions to quickly
        // skip binary structures without full content reads (KH-50). Use the same
        // no-follow safe open as the real file reader: an extensionless symlink
        // must not get a pre-guard `File::open` of its target just because this
        // is only a header sniff.
        let mut buf = [0u8; EXTENSIONLESS_BINARY_PREFIX_SNIFF_BYTES];
        if let Ok(n) = read::read_file_prefix_safe(&path, &mut buf) {
            // LAW10: failed prefix probe leaves binary hint false; the full safe read path below is the loud, recall-preserving path that still surfaces unreadable files.
            let head = &buf[..n];
            if read::looks_binary_prefix(head) {
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
                return;
            }
        }
    }

    if ext.eq_ignore_ascii_case("pdf") {
        pdf::extract_pdf_chunks(&path, file_size, live_mtime_ns, max_size, emit);
        return;
    } else if ext.eq_ignore_ascii_case("7z") {
        seven_zip::extract_seven_zip_chunks(&path, max_size, respect_default_excludes, emit);
        return;
    } else if ext.eq_ignore_ascii_case("rar") {
        rar::extract_rar_chunks(&path, max_size, respect_default_excludes, emit);
        return;
    } else if archive::is_openpack_archive_ext(ext) {
        archive::extract_openpack_archive(&path, ext, max_size, respect_default_excludes, emit);
        return;
    } else if ext.eq_ignore_ascii_case("tar") {
        // Bare (uncompressed) `.tar`: unpack per-entry exactly as the zip
        // branch does, so a secret committed inside a tarball (docker layer
        // export, helm chart, source tarball — the dominant Linux/cloud
        // archive) is found just like one inside a `.zip`. `emit_tar_entries`
        // enforces the same per-entry size cap and 4x total-uncompressed
        // (tar-bomb) budget as the zip branch.
        if is_symlink(&path) {
            // Law 10: refused symlink => this .tar path is NOT scanned; count it.
            tracing::warn!(
                archive = %path.display(),
                "refusing to open archive at a symlink path - \
                 prevents the link-swap attack class"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            if !emit(Err(SourceError::Other(format!(
                "failed to scan tar file '{}': refusing to open archive at a symlink path; tar file was not scanned",
                display_path(&path)
            )))) {
                return;
            }
            return;
        }
        // `read_file_safe` opens with `O_NOFOLLOW` on Unix / `symlink_metadata`
        // refusal on Windows, so an `--include`d `bundle.tar -> ~/.aws/...`
        // symlink can't redirect the read to an off-tree target.
        match read::read_file_safe(&path, file_size) {
            Ok(bytes) => {
                // Guard against a non-tar file with a `.tar` extension: only untar
                // when the ustar/GNU magic is actually present, otherwise fall
                // through to the normal scan path so the bytes are still examined.
                if compressed::looks_like_tar(&bytes) {
                    compressed::emit_tar_entries(
                        &bytes,
                        &display_path(&path),
                        max_size,
                        respect_default_excludes,
                        emit,
                    );
                    return;
                }
                tracing::info!(
                    archive = %path.display(),
                    "file has .tar extension but is not a tar archive; scanning as plain file"
                );
            }
            Err(error) => {
                tracing::warn!(
                    archive = %path.display(),
                    %error,
                    "cannot read tar file; skipping"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                if !emit(Err(SourceError::Other(format!(
                    "failed to scan tar file '{}': cannot read tar file ({error}); tar file was not scanned",
                    display_path(&path)
                )))) {
                    return;
                }
                return;
            }
        }
    } else if compressed::is_compressed_ext(ext) {
        // `.gz` / `.tar.gz` (ext `gz`) / `.tgz` / `.zst` / `.lz4` / `.sz` /
        // `.bz2` / `.xz`: fully decompress, then untar per-entry if the
        // decompressed stream is a tar container, else scan the real
        // decompressed bytes. These extensions are removed from SKIP_EXTENSIONS
        // so they reach this branch.
        compressed::extract_compressed_chunks(&path, ext, max_size, respect_default_excludes, emit);
        return;
    } else if ext.eq_ignore_ascii_case("har") {
        // Route the HAR read through the same no-follow-symlink guard
        // every other content path uses (`read_file_safe` -> `open_file_safe`
        // with `O_NOFOLLOW` on Unix / `symlink_metadata` refusal on Windows).
        // The old `std::fs::read` followed symlinks, so an explicitly
        // `--include`d `creds.har -> ~/.aws/credentials` symlink (include
        // paths use `is_file()`, which follows links) would be read and its
        // target's bytes scanned - the exact link-swap class the archive
        // branch's guard at the top of this function defends against. (M17)
        match read::read_file_safe(&path, file_size) {
            Ok(bytes) => {
                let path_str = display_path(&path);
                match crate::har::try_expand_har(&bytes, &path_str, max_size) {
                    Some(har_chunks) => {
                        for chunk in har_chunks {
                            if !emit(chunk) {
                                return;
                            }
                        }
                        return;
                    }
                    None => {
                        tracing::info!(
                            path = %path.display(),
                            "HAR parse failed; scanning as plain file"
                        );
                    }
                }
            }
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    %error,
                    "cannot read HAR file; skipping"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                if !emit(Err(SourceError::Other(format!(
                    "failed to scan HAR file '{}': cannot read HAR file ({error}); HAR file was not scanned",
                    display_path(&path)
                )))) {
                    return;
                }
                return;
            }
        }
    }

    // No-follow guard for the GENERAL content read below. The archive/compressed
    // branches above each refuse a symlink path and `return`; the `.har` branch
    // reads via the `O_NOFOLLOW` `read_file_safe` but FALLS THROUGH to here when
    // the no-follow open failed or the target is not valid HAR — which is exactly
    // what an `--include`d `creds.har -> ~/.aws/credentials` symlink does: include
    // paths are admitted with `is_file()` (follows links), `O_NOFOLLOW` then
    // rejects the link so the HAR read yields nothing, and control reaches the
    // general read whose `read_file_windowed_mmap` / `File::open(&path)` DO follow
    // the link and would scan the victim's bytes. Refuse symlinks here so no read
    // path follows a link-swap target (M17 regression: the guard existed only on
    // the HAR-specific read, not on the fall-through). Same defense + style as the
    // archive-branch guards above.
    if live_metadata.map_or_else(|| is_symlink(&path), |meta| meta.is_symlink) {
        // Law 10: refusing to follow the symlink means this explicitly-included
        // path is NOT scanned. Count it (as unreadable) so end-of-scan coverage
        // reflects the drop — a refused symlink is a deliberate non-scan, but
        // the operator must still see the path was skipped, not silently treated
        // as clean.
        tracing::warn!(
            path = %path.display(),
            "refusing to read content at a symlink path - prevents the link-swap attack class"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        if !emit(Err(SourceError::Other(format!(
            "failed to scan filesystem file '{}': refusing to read content at a symlink path; file was not scanned",
            display_path(&path)
        )))) {
            return;
        }
        return;
    }

    // A file that begins with a UTF-16 BOM (`FF FE`/`FE FF`) must NOT take the
    // raw-byte windowed/mmap path below: that path decodes each window with
    // `from_utf8_lossy`, which leaves a UTF-16 ASCII secret NUL-interleaved
    // (`g\0h\0p\0…`) so no detector matches it, and counts `\n` on raw UTF-16
    // bytes so line attribution drifts. The cross-window stitch invariant
    // (`base_offset + data.len()` gapless; see engine::boundary) is raw-byte
    // based, so windows cannot be transcoded in place without breaking it.
    // `file_starts_with_utf16_bom` short-circuits those files out of the windowed
    // branch (the `&&` only pays the probe syscall when the file is large enough
    // to reach it), letting them fall through to the single-chunk
    // `read_file_mmap` path below — which runs `decode_text_file` over the whole
    // mapping (correct UTF-16 decode + exact line/col), is bounded by the same
    // 2 GiB mmap sanity cap (an over-cap or TOCTOU-grown file is a loud counted
    // skip), and routes a non-UTF-16 buffer that merely starts with the BOM bytes
    // to printable-string scanning. LAW10: routes UTF-16 to the single-chunk
    // decode so its ASCII secrets are scanned, not dropped -- the prior raw-byte
    // windowed path silently lost them (false clean); recall is preserved.
    if file_size > window_size as u64 && !file_starts_with_utf16_bom(&path) {
        let display = display_path(&path);
        let mut consumer_stopped = false;
        let windowed_mmap_outcome = read::for_each_file_windowed_mmap(
            &path,
            window_size,
            window_overlap,
            |row| match row {
                Ok(w) => {
                    let chunk = Ok(Chunk {
                        data: w.text.into(),
                        metadata: ChunkMetadata {
                            source_type: "filesystem/windowed".into(),
                            path: Some(display.clone().into()),
                            base_offset: w.offset,
                            base_line: w.base_line,
                            mtime_ns: live_mtime_ns,
                            size_bytes: Some(file_size),
                            decoded_span: None,
                            ..Default::default()
                        },
                    });
                    if !emit(chunk) {
                        consumer_stopped = true;
                        return false;
                    }
                    true
                }
                Err(error) => {
                    if !emit(Err(error)) {
                        consumer_stopped = true;
                        return false;
                    }
                    true
                }
            },
        );
        match windowed_mmap_outcome {
            read::WindowedMmapOutcome::Consumed => {
                if consumer_stopped {
                    return;
                }
                return;
            }
            read::WindowedMmapOutcome::Fallback(mut file) => {
                match file.metadata() {
                    Ok(meta) if meta.len() > read::MMAP_TOCTOU_SANITY_CAP_BYTES => {
                        tracing::warn!(
                            path = %path.display(),
                            live_size = meta.len(),
                            cap = read::MMAP_TOCTOU_SANITY_CAP_BYTES,
                            "refusing large-file buffered fallback: live size exceeds mmap sanity cap"
                        );
                        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
                        if !emit(Err(SourceError::Other(format!(
                            "failed to scan filesystem file '{}': live size {} exceeded the {}-byte large-file fallback sanity cap; file was not scanned",
                            display_path(&path),
                            meta.len(),
                            read::MMAP_TOCTOU_SANITY_CAP_BYTES
                        )))) {
                            return;
                        }
                        return;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(
                            path = %path.display(),
                            %error,
                            "cannot stat large file for buffered fallback sanity cap; skipping"
                        );
                        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                        if !emit(Err(SourceError::Io(error))) {
                            return;
                        }
                        return;
                    }
                }
                #[cfg(unix)]
                {
                    use std::os::unix::io::AsRawFd;
                    let fd = file.as_raw_fd();
                    // SAFETY: advisory shared lock on the already-open
                    // no-follow descriptor. If another process owns an
                    // exclusive lock, do not scan an unlocked buffered fallback
                    // after the mmap path already refused the same file.
                    if unsafe { libc::flock(fd, libc::LOCK_SH | libc::LOCK_NB) } != 0 {
                        tracing::warn!(
                            path = %path.display(),
                            "large file is locked by another process; skipping buffered fallback to avoid scanning a torn write"
                        );
                        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                        let error = std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "large file is locked by another process",
                        );
                        let _ = emit(Err(keyhog_core::SourceError::Io(error))); // LAW10: locked fallback is visible partial coverage, not a silent clean file
                        return;
                    }
                }

                let mut current_offset = 0;
                // Newlines in the file before `current_offset` - the absolute
                // base line of the window about to be emitted, advanced in
                // lockstep with `current_offset` so reported lines are absolute
                // (the line analog of `base_offset`).
                let mut current_base_line = 0usize;
                let mut buffer = vec![0u8; window_size];
                loop {
                    // Fill the window with a `read_exact`-style loop. `Read::read`
                    // is permitted to return fewer bytes than requested without
                    // being at EOF (a short read in the middle of a multi-MiB
                    // file); the old `if n < window_size { break }` treated any
                    // short read as EOF and silently dropped the rest of the file,
                    // missing every secret past that point. Only a 0-byte read is
                    // true EOF here. (M15)
                    let mut filled = 0;
                    let mut hit_eof = false;
                    while filled < window_size {
                        match file.read(&mut buffer[filled..]) {
                            Ok(0) => {
                                hit_eof = true;
                                break;
                            }
                            Ok(n) => filled += n,
                            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                            Err(error) => {
                                // A hard read error mid-file: stop scanning this
                                // file rather than emit a torn window with a wrong
                                // offset. Anything already emitted is correct.
                                tracing::warn!(
                                    path = %path.display(),
                                    %error,
                                    "cannot read large file; stopping scan of this file"
                                );
                                let _event =
                                    crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                                let _ = emit(Err(keyhog_core::SourceError::Io(error))); // LAW10: unused-binding marker; no runtime effect, not a fallback
                                return;
                            }
                        }
                    }
                    if filled == 0 {
                        break;
                    }
                    let data = String::from_utf8_lossy(&buffer[..filled]).into_owned();
                    let chunk = Ok(Chunk {
                        data: data.into(),
                        metadata: ChunkMetadata {
                            source_type: "filesystem/windowed".into(),
                            path: Some(display.clone().into()),
                            base_offset: current_offset,
                            base_line: current_base_line,
                            mtime_ns: live_mtime_ns,
                            size_bytes: Some(file_size),
                            decoded_span: None,
                            ..Default::default()
                        },
                    });
                    if !emit(chunk) {
                        return;
                    }
                    if hit_eof || filled < window_size {
                        break;
                    }
                    // Rewind by the overlap so a secret straddling the window cut
                    // is scanned whole in the next window. If the seek fails the
                    // stream position has NOT moved back, so `current_offset` must
                    // track the real position (advance by the full `filled`) to
                    // keep `base_offset` metadata consistent with the bytes we
                    // actually read - otherwise reported finding locations drift.
                    // (M15)
                    match file.seek(SeekFrom::Current(-(window_overlap as i64))) {
                        Ok(_) => {
                            let advanced = filled - window_overlap;
                            current_base_line +=
                                memchr::memchr_iter(b'\n', &buffer[..advanced]).count();
                            current_offset += advanced;
                        }
                        Err(_error) => {
                            // Law 10: seek-back failed => advance offset by full `filled` to keep base_offset metadata consistent; accounting-only, recall-neutral
                            current_base_line +=
                                memchr::memchr_iter(b'\n', &buffer[..filled]).count();
                            current_offset += filled;
                        }
                    }
                }
            }
        }
        return;
    }

    let content_source = if file_size >= MMAP_THRESHOLD {
        read::read_file_mmap(&path)
    } else {
        read::read_file_buffered(&path, file_size)
    };

    let (content, source_type) = match content_source {
        Some(read::BufferedFileRead::Text(text)) if text.is_empty() => return,
        Some(read::BufferedFileRead::Text(text)) => (text.into(), "filesystem"),
        Some(read::BufferedFileRead::Bytes(bytes)) => {
            let strings = crate::strings::extract_printable_strings(
                &bytes,
                crate::strings::MIN_PRINTABLE_STRING_LEN,
            );
            if strings.is_empty() {
                record_binary_without_printable_strings(&display_path(&path));
                return;
            }
            tracing::info!(
                path = %path.display(),
                "file is not valid text; scanning printable strings only"
            );
            (
                crate::strings::join_sensitive_strings(&strings, "\n"),
                "filesystem:binary-strings",
            )
        }
        Some(read::BufferedFileRead::Mmap(mmap)) => {
            let strings = crate::strings::extract_printable_strings(
                &mmap,
                crate::strings::MIN_PRINTABLE_STRING_LEN,
            );
            if strings.is_empty() {
                record_binary_without_printable_strings(&display_path(&path));
                return;
            }
            tracing::info!(
                path = %path.display(),
                "file is not valid text; scanning mmap-backed printable strings only"
            );
            (
                crate::strings::join_sensitive_strings(&strings, "\n"),
                "filesystem:binary-strings",
            )
        }
        _ => {
            if !emit(Err(keyhog_core::SourceError::Other(format!(
                "failed to scan filesystem file '{}': primary read path refused the file; file was not scanned",
                display_path(&path)
            )))) {
                return;
            }
            return;
        }
    };

    // Git-LFS pointer coverage (Law 10): if this small text file is actually a
    // Git-LFS pointer, the blob it references lives in LFS storage and is not on
    // disk — the pointer text is scanned below (and its content-hash `oid`
    // suppressed by the scanner), but the real content was NOT. Record the
    // coverage gap so an unmaterialised-pointer repo is not reported as a
    // false-clean. Bounded to pointer-sized files so a large text file never
    // pays the whole-content scan (Law 7). This is additive: the chunk is still
    // emitted and scanned. A pointer smaller than one window always reaches this
    // single-chunk path (a real pointer is ~130 bytes).
    if content.len() <= GIT_LFS_POINTER_MAX_BYTES
        && keyhog_core::git_lfs::is_git_lfs_pointer(content.as_bytes())
    {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::GitLfsPointer);
    }

    if !emit(Ok(Chunk {
        data: content,
        metadata: ChunkMetadata {
            source_type: source_type.into(),
            path: Some(display_path(&path).into()),
            mtime_ns: live_mtime_ns,
            size_bytes: Some(file_size),
            decoded_span: None,
            ..Default::default()
        },
    })) {
        tracing::debug!("filesystem chunk consumer stopped before final chunk");
    }
}

/// Read live metadata via a single no-follow `stat`.
/// Size remains authoritative even when the platform/filesystem does not expose
/// a usable modified time; in that case only the cache fast-path is disabled.
fn file_live_metadata(path: &Path) -> Option<FileLiveMetadata> {
    let meta = std::fs::symlink_metadata(path).ok()?; // LAW10: malformed input => None (fail-closed at the boundary), recall-safe
    let file_type = meta.file_type();
    let mtime_ns = meta
        .modified()
        .ok() // LAW10: missing platform mtime disables only Merkle fast-path; live size and scan still proceed; recall-safe
        .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok()) // LAW10: pre-epoch mtime disables only Merkle fast-path; live size and scan still proceed; recall-safe
        .map(|dur| {
            let nanos = dur.as_secs() as u128 * 1_000_000_000 + dur.subsec_nanos() as u128;
            // mtime is a Merkle cache key only; saturating past u64::MAX ns
            // (unreachable before year 2554) cannot affect scan recall.
            u64::try_from(nanos).map_or(u64::MAX, |nanos| nanos)
        });
    Some(FileLiveMetadata {
        mtime_ns,
        size_bytes: meta.len(),
        is_symlink: file_type.is_symlink(),
    })
}
