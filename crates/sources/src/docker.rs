//! Docker image source: exports an image with `docker image save`, unpacks each
//! layer, and reuses the filesystem source to scan extracted files safely.

use codewalk::{CodeWalker, WalkConfig};
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use regex::Regex;
use wait_timeout::ChildExt;

use crate::FilesystemSource;

/// Scan a Docker image by saving it as a tar archive and unpacking each layer.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::Source;
/// use keyhog_sources::DockerImageSource;
///
/// let source = DockerImageSource::new("alpine:latest");
/// assert_eq!(source.name(), "docker");
/// ```
pub struct DockerImageSource {
    image: String,
    limits: crate::SourceLimits,
}

impl DockerImageSource {
    /// Create a Docker image source for `docker image save`-based scanning.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::Source;
    /// use keyhog_sources::DockerImageSource;
    ///
    /// let source = DockerImageSource::new("alpine:latest");
    /// assert_eq!(source.name(), "docker");
    /// ```
    pub fn new(image: impl Into<String>) -> Self {
        Self {
            image: image.into(),
            limits: crate::SourceLimits::default(),
        }
    }

    pub(crate) fn with_limits(mut self, limits: crate::SourceLimits) -> Self {
        self.limits = limits;
        self
    }
}

impl Source for DockerImageSource {
    fn name(&self) -> &str {
        "docker"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        match collect_docker_chunks(&self.image, self.limits) {
            Ok(rows) => Box::new(rows.into_iter()),
            Err(error) => Box::new(std::iter::once(Err(error))),
        }
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn collect_docker_chunks(
    image: &str,
    limits: crate::SourceLimits,
) -> Result<Vec<Result<Chunk, SourceError>>, SourceError> {
    let image = validate_image_name(image)?;
    let workspace = DockerScanWorkspace::new()?;
    let docker_bin = resolve_docker_binary()?;

    export_docker_image_archive(&docker_bin, &image, workspace.archive_path())?;
    let mut rows = Vec::new();
    let mut error_rows =
        unpack_tar(workspace.archive_path(), workspace.root_path(), limits)?.into_rows();

    match find_archive_metadata_chunks(workspace.root_path(), &image, limits) {
        Ok(chunks) => rows.extend(chunks.into_iter().map(Ok)),
        Err(error) => error_rows.push(Err(error)),
    }
    match find_manifest_config_chunks(workspace.root_path(), &image, limits) {
        Ok(chunks) => rows.extend(chunks.into_iter().map(Ok)),
        Err(error) => error_rows.push(Err(error)),
    }
    for row in collect_docker_layer_chunks(&workspace, &image, limits) {
        match row {
            Ok(chunk) => rows.push(Ok(chunk)),
            Err(error) => error_rows.push(Err(error)),
        }
    }
    rows.extend(error_rows);

    Ok(rows)
}

#[derive(Default)]
struct DockerExtractReport {
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

    fn into_errors(self) -> Vec<SourceError> {
        self.errors
    }

    fn into_rows(self) -> Vec<Result<Chunk, SourceError>> {
        self.errors.into_iter().map(Err).collect()
    }
}

struct DockerScanWorkspace {
    tempdir: tempfile::TempDir,
    archive_temppath: tempfile::TempPath,
    root_path: PathBuf,
}

impl DockerScanWorkspace {
    fn new() -> Result<Self, SourceError> {
        let tempdir = tempfile::tempdir().map_err(SourceError::Io)?;
        let archive_temppath = tempfile::Builder::new()
            .prefix("keyhog-image-")
            .suffix(".tar")
            .rand_bytes(8)
            .tempfile_in(tempdir.path())
            .map_err(SourceError::Io)?
            .into_temp_path();
        let root_path = tempdir.path().join("root");
        create_private_directory_all(&root_path)?;
        Ok(Self {
            tempdir,
            archive_temppath,
            root_path,
        })
    }

    fn archive_path(&self) -> &Path {
        self.archive_temppath.as_ref()
    }

    fn root_path(&self) -> &Path {
        &self.root_path
    }

    fn layer_dir(&self, layer_name: &str) -> PathBuf {
        self.tempdir
            .path()
            .join("layers")
            .join(sanitize_layer_name(layer_name))
    }
}

fn resolve_docker_binary() -> Result<PathBuf, SourceError> {
    // SECURITY: kimi-wave1 audit finding 3.PATH-docker. Resolve `docker`
    // to a trusted-system-bin absolute path so a hostile $PATH cannot
    // substitute a binary that receives the image name + archive output
    // location and ships them to an attacker.
    keyhog_core::resolve_safe_bin("docker").ok_or_else(|| {
        SourceError::Other(
            "docker binary not found in trusted system bin dirs (refusing to use $PATH lookup); \
             install docker via your package manager or add its absolute directory to \
             [system].trusted_bin_dirs in .keyhog.toml"
                .into(),
        )
    })
}

fn collect_docker_layer_chunks(
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

fn export_docker_image_archive(
    docker_bin: &Path,
    image: &str,
    archive_path: &Path,
) -> Result<(), SourceError> {
    let mut child = Command::new(docker_bin)
        .args(["image", "save", "-o"])
        .arg(archive_path)
        .arg(image)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(SourceError::Io)?;
    let stderr = child
        .stderr
        .take()
        .map(|pipe| std::thread::spawn(move || crate::process_excerpt::drain_stderr_excerpt(pipe)));
    let timeout = crate::timeouts::DOCKER_EXPORT;
    let status = match child.wait_timeout(timeout) {
        Ok(Some(status)) => status,
        Ok(None) => {
            let cleanup = kill_and_reap_docker_child(&mut child, "docker image export timeout");
            let cleanup_message = match cleanup {
                Ok(()) => String::new(),
                Err(error) => format!("; cleanup failed: {error}"),
            };
            let stderr = if cleanup_message.is_empty() {
                join_docker_stderr(stderr)
            } else {
                String::new()
            };
            return Err(SourceError::Other(format!(
                "docker image export timed out after {}s for {image}{cleanup_message}{}",
                timeout.as_secs(),
                docker_stderr_suffix(&stderr)
            )));
        }
        Err(error) => {
            let cleanup = kill_and_reap_docker_child(&mut child, "docker image export wait error");
            let cleanup_message = match cleanup {
                Ok(()) => String::new(),
                Err(cleanup_error) => format!("; cleanup failed: {cleanup_error}"),
            };
            let stderr = if cleanup_message.is_empty() {
                join_docker_stderr(stderr)
            } else {
                String::new()
            };
            return Err(SourceError::Other(format!(
                "failed to wait for docker image export for {image}: {error}{cleanup_message}{}",
                docker_stderr_suffix(&stderr)
            )));
        }
    };
    let stderr = join_docker_stderr(stderr);
    if status.success() {
        return Ok(());
    }

    Err(SourceError::Other(format!(
        "failed to export docker image: {image}: {}",
        stderr.trim()
    )))
}

fn kill_and_reap_docker_child(child: &mut Child, context: &str) -> std::io::Result<()> {
    let kill_result = child.kill();
    let wait_result = child.wait();
    match (kill_result, wait_result) {
        (Ok(()), Ok(_)) => Ok(()),
        (Err(kill_error), Ok(_)) if kill_error.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
        (Err(kill_error), Ok(status)) => Err(std::io::Error::other(format!(
            "{context}: failed to kill child before reap: {kill_error}; reap status: {status}"
        ))),
        (Ok(()), Err(wait_error)) => Err(std::io::Error::other(format!(
            "{context}: killed child but failed to reap it: {wait_error}"
        ))),
        (Err(kill_error), Err(wait_error)) => Err(std::io::Error::other(format!(
            "{context}: failed to kill child: {kill_error}; failed to reap child: {wait_error}"
        ))),
    }
}

fn join_docker_stderr(stderr: Option<std::thread::JoinHandle<String>>) -> String {
    match stderr {
        Some(handle) => match handle.join() {
            Ok(stderr) => stderr,
            Err(_panic_payload) => {
                eprintln!("keyhog: docker stderr reader panicked during image export");
                tracing::warn!("docker stderr reader panicked during image export");
                "stderr unavailable: docker stderr reader panicked".to_string()
            }
        },
        None => {
            eprintln!("keyhog: docker image export stderr pipe was unavailable");
            tracing::warn!("docker image export stderr pipe was unavailable");
            String::new()
        }
    }
}

fn docker_stderr_suffix(stderr: &str) -> String {
    let stderr = stderr.trim();
    if stderr.is_empty() {
        String::new()
    } else {
        format!(": {stderr}")
    }
}

fn validate_image_name(image: &str) -> Result<String, SourceError> {
    use std::sync::LazyLock;

    let image = image.trim();
    if image.is_empty() || image.starts_with('-') || image.chars().any(char::is_control) {
        return Err(SourceError::Other(
            "docker image contains unsafe characters".into(),
        ));
    }

    // Compiled once - avoids per-call regex compilation overhead.
    // The [-]{0,128} quantifiers are bounded to prevent ReDoS on
    // pathological inputs (previously unbounded [-]*).
    static IMAGE_PATTERN: LazyLock<Option<Regex>> = LazyLock::new(|| {
        Regex::new(
            r"^(?:(?:[a-z0-9]+(?:(?:[._]|__|[-]{0,128})[a-z0-9]+)*)/)*[a-z0-9]+(?:(?:[._]|__|[-]{0,128})[a-z0-9]+)*(?::[\w][\w.\-]{0,127})?(?:@sha256:[a-f0-9]{64})?$",
        )
        .ok() // LAW10: a compile failure of this CONSTANT pattern is caught fail-CLOSED by the `else` arm below, which returns a loud Err — never a silent allow
    });

    let Some(image_pattern) = IMAGE_PATTERN.as_ref() else {
        return Err(SourceError::Other(
            "docker image validator failed to initialize. Fix: report this build-time regex error"
                .into(),
        ));
    };

    if !image_pattern.is_match(image) {
        return Err(SourceError::Other(format!(
            "invalid docker image '{image}'"
        )));
    }

    Ok(image.to_string())
}

fn unpack_tar(
    archive_path: &Path,
    destination: &Path,
    limits: crate::SourceLimits,
) -> Result<DockerExtractReport, SourceError> {
    let file = File::open(archive_path).map_err(SourceError::Io)?;
    unpack_open_tar(file, destination, limits, DockerArchiveScope::ImageArchive)
}

fn unpack_open_tar(
    mut file: File,
    destination: &Path,
    limits: crate::SourceLimits,
    scope: DockerArchiveScope,
) -> Result<DockerExtractReport, SourceError> {
    // Open the archive file exactly once to prevent TOCTOU race conditions.
    // A separate open for validation and extraction would allow the file to
    // be swapped between the two passes.
    let mut validation_archive = tar::Archive::new(&mut file);
    validate_docker_archive_plan(&mut validation_archive, limits, scope)?;

    // Rewind the same file descriptor for extraction - no second open.
    file.rewind().map_err(SourceError::Io)?;
    unpack_tar_reader(&mut file, destination, limits, scope)
}

fn unpack_layer_archive(
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

fn validate_extracted_tree_with_limits<R: std::io::Read>(
    archive: &mut tar::Archive<R>,
    limits: crate::SourceLimits,
) -> Result<(), SourceError> {
    let mut cumulative_bytes: u64 = 0;
    for entry in archive.entries().map_err(SourceError::Io)? {
        let entry = entry.map_err(SourceError::Io)?;
        let path = entry.path().map_err(SourceError::Io)?;
        let size = entry.header().entry_size().map_err(SourceError::Io)?;

        // Security boundary: every extracted member must stay relative to the
        // extraction root. Reject absolute paths, prefixes, and any `..`
        // traversal before `tar` writes to disk.
        //
        // Also reject symlinks and hardlinks in Docker layers. These are
        // frequently used in "link-swap" attacks to write outside the
        // extraction root. Secret scanning doesn't need to resolve links
        // inside the layer - we scan the raw file content anyway.
        let file_type = entry.header().entry_type();
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
        if size > limits.docker_tar_entry_bytes {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            return Err(docker_archive_entry_over_entry_cap_error(
                &path,
                size,
                limits.docker_tar_entry_bytes,
            ));
        }
        // Zip-bomb defense: a malicious archive can ship 1000+ entries
        // each just under the per-entry cap (127 MiB × 1000 = 127 GiB).
        // Each entry passes the per-entry gate but the cumulative
        // unpack exhausts disk. Reject before unpack starts.
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

fn validate_docker_archive_plan<R: std::io::Read>(
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

fn extract_docker_archive_entries<R: std::io::Read>(
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
    // Security boundary: every extracted member must stay relative to the
    // extraction root. Reject absolute paths, prefixes, and any `..`
    // traversal before `tar` writes to disk.
    //
    // Also reject symlinks and hardlinks in Docker layers. These are
    // frequently used in "link-swap" attacks to write outside the
    // extraction root. Secret scanning doesn't need to resolve links
    // inside the layer - we scan the raw file content anyway.
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

fn find_layer_archives(
    root_path: &Path,
    limits: crate::SourceLimits,
) -> Result<Vec<PathBuf>, SourceError> {
    let manifest_layers = find_manifest_layer_archives(root_path, limits)?;
    if !manifest_layers.is_empty() {
        return dedup_layer_archives_by_content(manifest_layers);
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
    dedup_layer_archives_by_content(layers)
}

fn is_fallback_layer_archive_path(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("layer.tar" | "layer.tar.gz" | "layer.tgz" | "layer.tar.zst" | "layer.tar.zstd")
    )
}

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
struct OciIndex {
    #[serde(default)]
    manifests: Vec<OciDescriptor>,
}

#[derive(Clone, serde::Deserialize)]
struct OciDescriptor {
    #[serde(rename = "mediaType", default)]
    _media_type: Option<String>,
    digest: String,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

#[derive(serde::Deserialize)]
struct OciImageManifest {
    config: OciDescriptor,
    #[serde(default)]
    layers: Vec<OciDescriptor>,
}

struct OciLoadedManifest {
    index: usize,
    label: String,
    digest: String,
    manifest: OciImageManifest,
}

const DOCKER_ROOT_METADATA_FILES: &[&str] = &["manifest.json", "index.json", "oci-layout"];

fn find_archive_metadata_chunks(
    root_path: &Path,
    image: &str,
    limits: crate::SourceLimits,
) -> Result<Vec<Chunk>, SourceError> {
    let mut chunks = Vec::new();
    for file_name in DOCKER_ROOT_METADATA_FILES {
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
                path: Some(format!("{image}:metadata:{file_name}")),
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

fn find_manifest_config_chunks(
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
                path: Some(format!("{image}:manifest[{idx}]:{config}")),
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
    chunks.extend(find_oci_config_chunks(root_path, image, limits)?);
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
        chunks.push(Chunk {
            metadata: ChunkMetadata {
                base_offset: 0,
                base_line: 0,
                source_type: "docker".into(),
                path: Some(format!(
                    "{image}:fallback-config[{idx}]:{}",
                    label.display()
                )),
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

fn find_manifest_layer_archives(
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
    layers.extend(find_oci_layer_archives(root_path, limits)?);
    layers.sort();
    layers.dedup();
    Ok(layers)
}

fn load_oci_image_manifests(
    root_path: &Path,
    limits: crate::SourceLimits,
) -> Result<Vec<OciLoadedManifest>, SourceError> {
    let layout_path = root_path.join("oci-layout");
    let index_path = root_path.join("index.json");
    if !layout_path.exists() && !index_path.exists() {
        return Ok(Vec::new());
    }
    if !index_path.is_file() {
        return Err(SourceError::Other(
            "OCI image layout is missing index.json".into(),
        ));
    }
    let index_bytes = read_capped_file(
        &index_path,
        "OCI image index",
        limits.docker_image_config_bytes,
    )?;
    let index: OciIndex = serde_json::from_slice(&index_bytes).map_err(|error| {
        SourceError::Other(format!(
            "invalid OCI image index '{}': {error}",
            index_path.display()
        ))
    })?;
    if index.manifests.is_empty() {
        return Err(SourceError::Other(format!(
            "OCI image index '{}' contains no manifests",
            index_path.display()
        )));
    }

    let mut manifests = Vec::new();
    for (idx, descriptor) in index.manifests.into_iter().enumerate() {
        let manifest_path =
            resolve_oci_blob_digest_path(root_path, "manifest", &descriptor, limits)?;
        verify_oci_blob_sha256(&manifest_path, &descriptor.digest)?;
        let manifest_bytes = read_capped_file(
            &manifest_path,
            "OCI image manifest",
            limits.docker_image_config_bytes,
        )?;
        let manifest: OciImageManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|error| {
                SourceError::Other(format!(
                    "invalid OCI image manifest '{}' from index entry {idx}: {error}",
                    descriptor.digest
                ))
            })?;
        let label = descriptor
            .annotations
            .get("org.opencontainers.image.ref.name")
            .cloned()
            .unwrap_or_else(|| descriptor.digest.clone()); // LAW10: missing OCI ref-name annotation falls back to manifest digest for display metadata only; config/layer blobs are still verified and scanned
        manifests.push(OciLoadedManifest {
            index: idx,
            label,
            digest: descriptor.digest,
            manifest,
        });
    }
    Ok(manifests)
}

fn find_oci_config_chunks(
    root_path: &Path,
    image: &str,
    limits: crate::SourceLimits,
) -> Result<Vec<Chunk>, SourceError> {
    let manifests = load_oci_image_manifests(root_path, limits)?;
    let mut chunks = Vec::new();
    for loaded in manifests {
        let config = loaded.manifest.config;
        let config_path = resolve_oci_blob_digest_path(root_path, "config", &config, limits)?;
        verify_oci_blob_sha256(&config_path, &config.digest)?;
        let bytes = read_capped_file(
            &config_path,
            "OCI image config",
            limits.docker_image_config_bytes,
        )?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
            SourceError::Other(format!(
                "invalid OCI image config '{}' referenced by manifest '{}': {error}",
                config.digest, loaded.digest
            ))
        })?;
        let data = serde_json::to_string_pretty(&value).map_err(|error| {
            SourceError::Other(format!(
                "failed to serialize OCI image config '{}' for scanning: {error}",
                config.digest
            ))
        })?;
        chunks.push(Chunk {
            metadata: ChunkMetadata {
                base_offset: 0,
                base_line: 0,
                source_type: "docker".into(),
                path: Some(format!(
                    "{image}:oci[{idx}]:{label}:config:{digest}",
                    idx = loaded.index,
                    label = loaded.label,
                    digest = config.digest
                )),
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

fn find_oci_layer_archives(
    root_path: &Path,
    limits: crate::SourceLimits,
) -> Result<Vec<PathBuf>, SourceError> {
    let manifests = load_oci_image_manifests(root_path, limits)?;
    let mut layers = Vec::new();
    for loaded in manifests {
        for layer in loaded.manifest.layers {
            let layer_path = resolve_oci_blob_digest_path(root_path, "layer", &layer, limits)?;
            verify_oci_blob_sha256(&layer_path, &layer.digest)?;
            layers.push(layer_path);
        }
    }
    Ok(layers)
}

fn dedup_layer_archives_by_content(layers: Vec<PathBuf>) -> Result<Vec<PathBuf>, SourceError> {
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    for layer in layers {
        let fingerprint = layer_archive_fingerprint(&layer)?;
        if seen.insert(fingerprint) {
            unique.push(layer);
        }
    }
    Ok(unique)
}

fn layer_archive_fingerprint(path: &Path) -> Result<(u64, blake3::Hash), SourceError> {
    let mut file = File::open(path).map_err(SourceError::Io)?;
    let metadata = file.metadata().map_err(SourceError::Io)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buffer[..n]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(SourceError::Io(error)),
        };
    }
    Ok((metadata.len(), hasher.finalize()))
}

fn read_capped_file(path: &Path, kind: &str, cap: u64) -> Result<Vec<u8>, SourceError> {
    let file = File::open(path).map_err(SourceError::Io)?;
    let metadata = file.metadata().map_err(SourceError::Io)?;
    if metadata.len() > cap {
        return Err(SourceError::Other(format!(
            "{kind} '{}' exceeds {} bytes",
            path.display(),
            cap
        )));
    }
    let read = crate::capped_read::read_to_cap(file, cap, Some(metadata.len()))
        .map_err(SourceError::Io)?;
    if read.truncated {
        return Err(SourceError::Other(format!(
            "{kind} '{}' exceeded {} bytes while reading",
            path.display(),
            cap
        )));
    }
    Ok(read.bytes)
}

fn resolve_oci_blob_digest_path(
    root_path: &Path,
    kind: &str,
    descriptor: &OciDescriptor,
    limits: crate::SourceLimits,
) -> Result<PathBuf, SourceError> {
    let hex = parse_oci_sha256_digest(kind, &descriptor.digest)?;
    if let Some(size) = descriptor.size {
        if size > limits.docker_tar_total_bytes {
            return Err(SourceError::Other(format!(
                "OCI {kind} descriptor '{}' declares {} bytes, above {} byte cap",
                descriptor.digest, size, limits.docker_tar_total_bytes
            )));
        }
    }
    let path = root_path.join("blobs").join("sha256").join(hex);
    if !path.is_file() {
        return Err(SourceError::Other(format!(
            "OCI {kind} descriptor references missing blob '{}'",
            descriptor.digest
        )));
    }
    Ok(path)
}

fn parse_oci_sha256_digest<'a>(kind: &str, digest: &'a str) -> Result<&'a str, SourceError> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(SourceError::Other(format!(
            "OCI {kind} descriptor uses unsupported digest '{}'",
            digest
        )));
    };
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(SourceError::Other(format!(
            "OCI {kind} descriptor references unsafe digest '{}'",
            digest
        )));
    }
    Ok(hex)
}

fn verify_oci_blob_sha256(path: &Path, digest: &str) -> Result<(), SourceError> {
    use sha2::{Digest, Sha256};

    let expected = parse_oci_sha256_digest("blob", digest)?;
    let mut file = File::open(path).map_err(SourceError::Io)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buffer[..n]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(SourceError::Io(error)),
        }
    }
    let actual_bytes: [u8; 32] = hasher.finalize().into();
    let actual = keyhog_core::hex_encode(&actual_bytes);
    if actual != expected {
        return Err(SourceError::Other(format!(
            "OCI blob '{}' digest mismatch: expected sha256:{expected}, got sha256:{actual}",
            path.display()
        )));
    }
    Ok(())
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

fn rewrite_layer_chunks<I>(
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

fn sanitize_layer_name(layer_name: &str) -> String {
    layer_name.replace('/', "_")
}

fn create_private_directory_all(path: &Path) -> Result<(), SourceError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(SourceError::Io)
}

pub(crate) fn manifest_layer_archives_for_test(
    root_path: &Path,
) -> Result<Vec<PathBuf>, SourceError> {
    find_layer_archives(root_path, crate::SourceLimits::default())
}

pub(crate) fn export_docker_image_archive_for_test(
    docker_bin: &Path,
    image: &str,
    archive_path: &Path,
) -> Result<(), SourceError> {
    export_docker_image_archive(docker_bin, image, archive_path)
}

pub(crate) fn manifest_config_chunks_for_test(
    root_path: &Path,
    image: &str,
) -> Result<Vec<Chunk>, SourceError> {
    find_manifest_config_chunks(root_path, image, crate::SourceLimits::default())
}

pub(crate) fn archive_metadata_chunks_for_test(
    root_path: &Path,
    image: &str,
) -> Result<Vec<Chunk>, SourceError> {
    find_archive_metadata_chunks(root_path, image, crate::SourceLimits::default())
}

pub(crate) fn unpack_layer_archive_for_test(
    archive_path: &Path,
    destination: &Path,
) -> Result<Vec<SourceError>, SourceError> {
    unpack_layer_archive(archive_path, destination, crate::SourceLimits::default())
        .map(DockerExtractReport::into_errors)
}

pub(crate) fn unpack_layer_archive_with_total_cap_for_test(
    archive_path: &Path,
    destination: &Path,
    total_cap: u64,
) -> Result<Vec<SourceError>, SourceError> {
    let limits = crate::SourceLimits {
        docker_tar_total_bytes: total_cap,
        ..crate::SourceLimits::default()
    };
    unpack_layer_archive(archive_path, destination, limits).map(DockerExtractReport::into_errors)
}

pub(crate) fn unpack_layer_archive_with_entry_cap_for_test(
    archive_path: &Path,
    destination: &Path,
    entry_cap: u64,
) -> Result<Vec<SourceError>, SourceError> {
    let limits = crate::SourceLimits {
        docker_tar_entry_bytes: entry_cap,
        ..crate::SourceLimits::default()
    };
    unpack_layer_archive(archive_path, destination, limits).map(DockerExtractReport::into_errors)
}

pub(crate) fn unpack_image_archive_with_entry_cap_for_test(
    archive_path: &Path,
    destination: &Path,
    entry_cap: u64,
) -> Result<Vec<SourceError>, SourceError> {
    let limits = crate::SourceLimits {
        docker_tar_entry_bytes: entry_cap,
        ..crate::SourceLimits::default()
    };
    unpack_tar(archive_path, destination, limits).map(DockerExtractReport::into_errors)
}

pub(crate) fn rewrite_layer_chunks_for_test<I>(
    chunks: I,
    image: &str,
    layer_root: &Path,
    layer_name: &str,
) -> Result<Vec<Chunk>, SourceError>
where
    I: IntoIterator<Item = Result<Chunk, SourceError>>,
{
    rewrite_layer_chunks(chunks, image, layer_root, layer_name)
}

pub(crate) fn validate_tar_archive_for_test(archive_path: &Path) -> Result<(), SourceError> {
    validate_tar_archive_with_total_cap_for_test(
        archive_path,
        crate::SourceLimits::default().docker_tar_total_bytes,
    )
}

pub(crate) fn validate_tar_archive_with_total_cap_for_test(
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
