//! Docker image source: exports an image with `docker image save`, unpacks each
//! layer, and reuses the filesystem source to scan extracted files safely.

use codewalk::{CodeWalker, WalkConfig};
use std::fs::File;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use regex::Regex;

use crate::FilesystemSource;

const MAX_TAR_ENTRY_BYTES: u64 = 128 * 1024 * 1024;

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
        }
    }
}

impl Source for DockerImageSource {
    fn name(&self) -> &str {
        "docker"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        match collect_docker_chunks(&self.image) {
            Ok(chunks) => Box::new(chunks.into_iter().map(Ok)),
            Err(error) => Box::new(std::iter::once(Err(error))),
        }
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn collect_docker_chunks(image: &str) -> Result<Vec<Chunk>, SourceError> {
    let image = validate_image_name(image)?;
    let tempdir = tempfile::tempdir().map_err(SourceError::Io)?;
    // Store the temp path in a binding so RAII deletes the archive on scope exit
    // (including panics). The old `.keep()` call disabled auto-cleanup — a crash
    // after `docker image save` would leak multi-gigabyte tar files in /tmp.
    let archive_temppath = tempfile::Builder::new()
        .prefix("keyhog-image-")
        .suffix(".tar")
        .rand_bytes(8)
        .tempfile_in(tempdir.path())
        .map_err(SourceError::Io)?
        .into_temp_path();
    let archive_path = archive_temppath.to_path_buf();
    let root_path = tempdir.path().join("root");
    create_private_directory_all(&root_path)?;

    // SECURITY: kimi-wave1 audit finding 3.PATH-docker. Resolve `docker`
    // to a trusted-system-bin absolute path so a hostile $PATH cannot
    // substitute a binary that receives the image name + archive output
    // location and ships them to an attacker.
    let docker_bin = keyhog_core::safe_bin::resolve_safe_bin("docker").ok_or_else(|| {
        SourceError::Other(
            "docker binary not found in trusted system bin dirs (refusing to use $PATH lookup); \
             install docker via your package manager or set KEYHOG_TRUSTED_BIN_DIR"
                .into(),
        )
    })?;
    let output = Command::new(&docker_bin)
        .args(["image", "save", "-o"])
        .arg(&archive_path)
        .arg(&image)
        .output()
        .map_err(SourceError::Io)?;

    if !output.status.success() {
        return Err(SourceError::Other(format!(
            "failed to export docker image: {image}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    unpack_tar(&archive_path, &root_path)?;

    let mut chunks = Vec::new();
    for layer_tar in find_layer_archives(&root_path)? {
        let layer_name = layer_tar
            .strip_prefix(&root_path)
            .ok()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| layer_tar.display().to_string());
        let layer_dir = tempdir
            .path()
            .join("layers")
            .join(sanitize_layer_name(&layer_name));
        create_private_directory_all(&layer_dir)?;
        unpack_tar(&layer_tar, &layer_dir)?;

        for chunk in FilesystemSource::new(layer_dir.clone()).chunks().flatten() {
            chunks.push(rewrite_chunk(chunk, &image, &layer_dir, &layer_name));
        }
    }

    Ok(chunks)
}

fn validate_image_name(image: &str) -> Result<String, SourceError> {
    use std::sync::LazyLock;

    let image = image.trim();
    if image.is_empty() || image.starts_with('-') || image.chars().any(char::is_control) {
        return Err(SourceError::Other(
            "docker image contains unsafe characters".into(),
        ));
    }

    // Compiled once — avoids per-call regex compilation overhead.
    // The [-]{0,128} quantifiers are bounded to prevent ReDoS on
    // pathological inputs (previously unbounded [-]*).
    static IMAGE_PATTERN: LazyLock<Option<Regex>> = LazyLock::new(|| {
        Regex::new(
            r"^(?:(?:[a-z0-9]+(?:(?:[._]|__|[-]{0,128})[a-z0-9]+)*)/)*[a-z0-9]+(?:(?:[._]|__|[-]{0,128})[a-z0-9]+)*(?::[\w][\w.\-]{0,127})?(?:@sha256:[a-f0-9]{64})?$",
        )
        .ok()
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

fn unpack_tar(archive_path: &Path, destination: &Path) -> Result<(), SourceError> {
    use std::io::Seek;
    // Open the archive file exactly once to prevent TOCTOU race conditions.
    // A separate open for validation and extraction would allow the file to
    // be swapped between the two passes.
    let mut file = File::open(archive_path).map_err(SourceError::Io)?;
    let mut validation_archive = tar::Archive::new(&mut file);
    validate_extracted_tree(&mut validation_archive)?;

    // Rewind the same file descriptor for extraction — no second open.
    file.rewind().map_err(SourceError::Io)?;
    let mut extract_archive = tar::Archive::new(&mut file);
    extract_archive.unpack(destination).map_err(SourceError::Io)
}

fn validate_extracted_tree<R: std::io::Read>(
    archive: &mut tar::Archive<R>,
) -> Result<(), SourceError> {
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
        // inside the layer — we scan the raw file content anyway.
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
        if size > MAX_TAR_ENTRY_BYTES {
            return Err(SourceError::Other(format!(
                "docker archive entry '{}' exceeds {} bytes",
                path.display(),
                MAX_TAR_ENTRY_BYTES
            )));
        }
    }

    Ok(())
}

fn find_layer_archives(root_path: &Path) -> Result<Vec<PathBuf>, SourceError> {
    let mut layers = Vec::new();

    let walker = CodeWalker::new(
        root_path,
        WalkConfig::default()
            .follow_symlinks(false)
            .respect_gitignore(false)
            .skip_hidden(false)
            .skip_binary(false)
            .max_file_size(0),
    )
    .walk()
    .map_err(|error| SourceError::Other(error.to_string()))?;

    for entry in walker {
        if entry.path.file_name().and_then(|name| name.to_str()) == Some("layer.tar") {
            layers.push(entry.path);
        }
    }
    Ok(layers)
}

fn rewrite_chunk(mut chunk: Chunk, image: &str, layer_root: &Path, layer_name: &str) -> Chunk {
    let relative_path = chunk
        .metadata
        .path
        .as_ref()
        .and_then(|path| {
            PathBuf::from(path)
                .strip_prefix(layer_root)
                .ok()
                .map(PathBuf::from)
        })
        .map(|path| path.display().to_string());

    chunk.metadata = ChunkMetadata {
                    base_offset: 0,
        source_type: "docker".into(),
        path: relative_path.map(|path| format!("{image}:{layer_name}:{path}")),
        commit: None,
        author: None,
        date: None,
    };
    chunk
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
