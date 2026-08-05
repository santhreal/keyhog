//! Docker image source: exports an image with `docker image save`, unpacks each
//! layer, and reuses the filesystem source to scan extracted files safely.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use keyhog_core::{Chunk, Source, SourceError};
use regex::Regex;
use wait_timeout::ChildExt;

mod archive;
mod file_read;
mod layer;
mod metadata;
// `pub(crate)` so the testing facade can reach `oci::descriptor_points_to_index_for_test`
// from the crate root (the OCI classification coverage lives in `tests/`).
pub(crate) mod oci;
use codewalk::{CodeWalker, WalkConfig};
use metadata::{
    archive_metadata_chunks as find_archive_metadata_chunks,
    manifest_config_chunks as find_manifest_config_chunks,
};

/// Build a [`CodeWalker`] that traverses EVERY entry under a docker image
/// archive's unpacked tree with no filtering, no gitignore, no hidden/binary
/// skipping, no size cap. Both the layer-archive discovery (`layer`) and the
/// metadata-less config-JSON fallback (`metadata`) need this identical
/// exhaustive walk; keeping the [`WalkConfig`] in ONE place stops the two sites
/// from silently drifting (e.g. one gaining a size cap the other lacks).
pub(super) fn exhaustive_archive_walker(root_path: &Path) -> CodeWalker {
    CodeWalker::new(
        root_path,
        WalkConfig::default()
            .follow_symlinks(false)
            .respect_gitignore(false)
            .skip_hidden(false)
            .skip_binary(false)
            .max_file_size(0),
    )
}

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
    respect_default_excludes: bool,
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
            respect_default_excludes: true,
        }
    }

    pub(crate) fn with_limits(mut self, limits: crate::SourceLimits) -> Self {
        self.limits = limits;
        self
    }

    pub(crate) fn with_default_excludes(mut self, respect_default_excludes: bool) -> Self {
        self.respect_default_excludes = respect_default_excludes;
        self
    }
}

impl Source for DockerImageSource {
    fn name(&self) -> &str {
        "docker"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        // Hold the scan read lease across collection so a counter-asserting test's
        // exclusive scope serializes this source's skip recording (unreadable
        // layers / manifests). `collect_docker_chunks` is synchronous, so the
        // lease covers its whole recording window. A no-op in production where the
        // gate is never armed; see `skip::gate_scan`.
        crate::gate_scan(|| {
            match collect_docker_chunks(&self.image, self.limits, self.respect_default_excludes) {
                Ok(rows) => Box::new(rows.into_iter()),
                Err(error) => Box::new(std::iter::once(Err(error))),
            }
        })
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn collect_docker_chunks(
    image: &str,
    limits: crate::SourceLimits,
    respect_default_excludes: bool,
) -> Result<Vec<Result<Chunk, SourceError>>, SourceError> {
    let image = validate_image_name(image)?;
    let workspace = DockerScanWorkspace::new()?;
    let docker_bin = resolve_docker_binary()?;

    // Container export is the acquisition boundary for this adapter.
    let archive_path = {
        let _export = crate::profile::acquire_span();
        acquire_docker_image_archive(&docker_bin, &image, &workspace)?
    };
    let mut rows = Vec::new();
    // Archive unpack + metadata enumeration walk the exported image layout.
    let _enumerate = crate::profile::walk_span();
    // ONE budget for the whole image: the outer tar and every layer tar draw
    // from this cell, so `docker_tar_total_bytes` bounds the image rather than
    // resetting per tar.
    let unpack_budget = archive::DockerUnpackBudget::new(limits.docker_tar_total_bytes);
    // Never discard what already unpacked. A refused entry (entry-count cap,
    // per-entry cap, image budget) aborts the REST of the outer tar, but the
    // layers already written are real scannable content, so the refusal becomes
    // a gap row carried alongside them rather than a `?` that drops the whole
    // image. These caps are deliberate one-shot refusals of hostile input and
    // are never retried; retrying a bomb is how a DoS defense becomes a DoS.
    let mut error_rows = match archive::unpack_tar(
        &archive_path,
        workspace.root_path(),
        limits,
        &unpack_budget,
    ) {
        Ok(report) => report.into_rows(),
        Err(error) => vec![Err(error)],
    };

    match find_archive_metadata_chunks(workspace.root_path(), &image, limits) {
        Ok(chunks) => {
            // Input accounting: layer payloads are counted by the inner
            // per-layer FilesystemSource walks, so only the metadata chunks
            // this adapter synthesizes itself are recorded (no double count).
            crate::profile::add_input_units(chunks.len() as u64);
            crate::profile::add_input_bytes(
                chunks.iter().map(|chunk| chunk.data.len() as u64).sum(),
            );
            rows.extend(chunks.into_iter().map(Ok))
        }
        Err(error) => error_rows.push(Err(error)),
    }
    match find_manifest_config_chunks(workspace.root_path(), &image, limits) {
        Ok(chunks) => {
            crate::profile::add_input_units(chunks.len() as u64);
            crate::profile::add_input_bytes(
                chunks.iter().map(|chunk| chunk.data.len() as u64).sum(),
            );
            rows.extend(chunks.into_iter().map(Ok))
        }
        Err(error) => error_rows.push(Err(error)),
    }
    // Layer traversal (per-layer unpack, dedup, and scan) is the walk
    // boundary; per-layer reads record through the inner FilesystemSource.
    drop(_enumerate);
    let _layer_walk = crate::profile::walk_span();
    for row in layer::collect_docker_layer_chunks(
        &workspace,
        &image,
        limits,
        respect_default_excludes,
        &unpack_budget,
    ) {
        match row {
            Ok(chunk) => rows.push(Ok(chunk)),
            Err(error) => error_rows.push(Err(error)),
        }
    }
    rows.extend(error_rows);

    Ok(rows)
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
            .join(layer::sanitize_layer_name(layer_name))
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

fn acquire_docker_image_archive(
    docker_bin: &Path,
    image: &str,
    workspace: &DockerScanWorkspace,
) -> Result<PathBuf, SourceError> {
    export_docker_image_archive(docker_bin, image, workspace.archive_path())?;
    Ok(workspace.archive_path().to_path_buf())
}

fn export_docker_image_archive(
    docker_bin: &Path,
    image: &str,
    archive_path: &Path,
) -> Result<(), SourceError> {
    let mut child = Command::new(docker_bin)
        .args(["image", "save", "-o"])
        .arg(archive_path)
        // `--` terminates docker's option parsing so an image reference that
        // begins with `-` (or otherwise looks like a flag) is always taken as
        // the positional image argument, never mis-parsed as a `save` option.
        .arg("--")
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
        .ok() // LAW10: a compile failure of this CONSTANT pattern is caught fail-CLOSED by the `else` arm below, which returns a loud Err, never a silent allow
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
    layer::find_layer_archives(root_path, crate::SourceLimits::default())
}

pub(crate) fn fallback_layer_archives_from_rows_for_test(
    rows: Vec<Result<PathBuf, SourceError>>,
) -> Vec<PathBuf> {
    layer::collect_fallback_layer_archives(rows)
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
    archive::unpack_layer_archive(
        archive_path,
        destination,
        crate::SourceLimits::default(),
        &archive::DockerUnpackBudget::new(
            crate::SourceLimits::default().docker_tar_total_bytes,
        ),
    )
        .map(archive::DockerExtractReport::into_errors)
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
    archive::unpack_layer_archive(
        archive_path,
        destination,
        limits,
        &archive::DockerUnpackBudget::new(limits.docker_tar_total_bytes),
    )
        .map(archive::DockerExtractReport::into_errors)
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
    archive::unpack_layer_archive(
        archive_path,
        destination,
        limits,
        &archive::DockerUnpackBudget::new(limits.docker_tar_total_bytes),
    )
        .map(archive::DockerExtractReport::into_errors)
}

pub(crate) fn unpack_layer_archive_with_caps_for_test(
    archive_path: &Path,
    destination: &Path,
    entry_cap: u64,
    total_cap: u64,
) -> Result<Vec<SourceError>, SourceError> {
    let limits = crate::SourceLimits {
        docker_tar_entry_bytes: entry_cap,
        docker_tar_total_bytes: total_cap,
        ..crate::SourceLimits::default()
    };
    archive::unpack_layer_archive(
        archive_path,
        destination,
        limits,
        &archive::DockerUnpackBudget::new(limits.docker_tar_total_bytes),
    )
        .map(archive::DockerExtractReport::into_errors)
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
    archive::unpack_tar(
        archive_path,
        destination,
        limits,
        &archive::DockerUnpackBudget::new(limits.docker_tar_total_bytes),
    )
        .map(archive::DockerExtractReport::into_errors)
}

/// Unpack several layer tars through ONE image-scoped budget, the way a real
/// multi-layer image does, so the image-wide ceiling can be exercised without a
/// docker daemon. Returns the error rows from every tar in order.
pub(crate) fn unpack_layers_with_shared_budget_for_test(
    archives: &[(&Path, &Path)],
    total_cap: u64,
) -> Result<Vec<SourceError>, SourceError> {
    let limits = crate::SourceLimits {
        docker_tar_total_bytes: total_cap,
        ..crate::SourceLimits::default()
    };
    let budget = archive::DockerUnpackBudget::new(total_cap);
    let mut errors = Vec::new();
    for (archive_path, destination) in archives {
        errors.extend(
            archive::unpack_layer_archive(archive_path, destination, limits, &budget)?
                .into_errors(),
        );
    }
    Ok(errors)
}

pub(crate) fn rewrite_layer_chunks_for_test<I>(
    chunks: I,
    image: &str,
    layer_root: &Path,
    layer_name: &str,
) -> Result<Vec<Result<Chunk, SourceError>>, SourceError>
where
    I: IntoIterator<Item = Result<Chunk, SourceError>>,
{
    layer::rewrite_layer_chunks(chunks, image, layer_root, layer_name)
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
    archive::validate_tar_archive_with_total_cap(archive_path, total_cap)
}
