//! Docker image source: exports an image with `docker image save`, unpacks each
//! layer, and reuses the filesystem source to scan extracted files safely.

use codewalk::{CodeWalker, WalkConfig};
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use regex::Regex;

use crate::FilesystemSource;

const MAX_TAR_ENTRY_BYTES: u64 = 128 * 1024 * 1024;
const MAX_IMAGE_CONFIG_BYTES: u64 = 16 * 1024 * 1024;

/// Cumulative cap across ALL entries in one Docker archive. The
/// per-entry [`MAX_TAR_ENTRY_BYTES`] cap alone is bypassed by a
/// zip-bomb that ships thousands of entries each just under 128 MiB:
/// the validator passed every entry individually and unpack()
/// happily wrote N × 128 MiB to disk. With this aggregate cap the
/// validator rejects the archive before unpack starts.
///
/// 8 GiB is generous for any real Docker image (the biggest common
/// base images max out around 1 GiB) but small enough that a 1000-
/// entry × 127 MiB ≈ 127 GiB zip-bomb is rejected on entry ~64. Kimi
/// sources-audit finding #docker-zip-bomb.
const MAX_TAR_TOTAL_BYTES: u64 = 8 * 1024 * 1024 * 1024;

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
    // (including panics). The old `.keep()` call disabled auto-cleanup - a crash
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
    chunks.extend(find_manifest_config_chunks(&root_path, &image)?);
    for layer_tar in find_layer_archives(&root_path)? {
        let layer_name = layer_tar
            .strip_prefix(&root_path)
            .ok() // LAW10: a non-prefixed path falls back to the full display path below — both are valid scannable labels, no layer is dropped
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| layer_tar.display().to_string()); // LAW10: display-label fallback only; the layer is still unpacked + scanned
        let layer_dir = tempdir
            .path()
            .join("layers")
            .join(sanitize_layer_name(&layer_name));
        create_private_directory_all(&layer_dir)?;
        unpack_layer_archive(&layer_tar, &layer_dir)?;

        chunks.extend(rewrite_layer_chunks(
            FilesystemSource::new(layer_dir.clone()).chunks(),
            &image,
            &layer_dir,
            &layer_name,
        )?);
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

fn unpack_tar(archive_path: &Path, destination: &Path) -> Result<(), SourceError> {
    // Open the archive file exactly once to prevent TOCTOU race conditions.
    // A separate open for validation and extraction would allow the file to
    // be swapped between the two passes.
    let mut file = File::open(archive_path).map_err(SourceError::Io)?;
    let mut validation_archive = tar::Archive::new(&mut file);
    validate_extracted_tree(&mut validation_archive)?;

    // Rewind the same file descriptor for extraction - no second open.
    file.rewind().map_err(SourceError::Io)?;
    let mut extract_archive = tar::Archive::new(&mut file);
    extract_archive.unpack(destination).map_err(SourceError::Io)
}

fn unpack_layer_archive(archive_path: &Path, destination: &Path) -> Result<(), SourceError> {
    match layer_archive_encoding(archive_path)? {
        LayerArchiveEncoding::RawTar => unpack_tar(archive_path, destination),
        LayerArchiveEncoding::GzipTar => {
            let validation_file = File::open(archive_path).map_err(SourceError::Io)?;
            validate_tar_reader(flate2::read::GzDecoder::new(validation_file))?;

            let extract_file = File::open(archive_path).map_err(SourceError::Io)?;
            unpack_tar_reader(flate2::read::GzDecoder::new(extract_file), destination)
        }
        LayerArchiveEncoding::ZstdTar => {
            let validation_file = File::open(archive_path).map_err(SourceError::Io)?;
            let validation_reader =
                zstd::stream::read::Decoder::new(validation_file).map_err(SourceError::Io)?;
            validate_tar_reader(validation_reader)?;

            let extract_file = File::open(archive_path).map_err(SourceError::Io)?;
            let extract_reader =
                zstd::stream::read::Decoder::new(extract_file).map_err(SourceError::Io)?;
            unpack_tar_reader(extract_reader, destination)
        }
    }
}

fn validate_tar_reader(reader: impl Read) -> Result<(), SourceError> {
    let mut archive = tar::Archive::new(reader);
    validate_extracted_tree(&mut archive)
}

fn unpack_tar_reader(reader: impl Read, destination: &Path) -> Result<(), SourceError> {
    let mut archive = tar::Archive::new(reader);
    archive.unpack(destination).map_err(SourceError::Io)
}

enum LayerArchiveEncoding {
    RawTar,
    GzipTar,
    ZstdTar,
}

fn layer_archive_encoding(archive_path: &Path) -> Result<LayerArchiveEncoding, SourceError> {
    let mut file = File::open(archive_path).map_err(SourceError::Io)?;
    let mut magic = [0u8; 4];
    let read = file.read(&mut magic).map_err(SourceError::Io)?;
    if read >= 2 && magic[..2] == [0x1f, 0x8b] {
        return Ok(LayerArchiveEncoding::GzipTar);
    }
    if read == 4 && magic == [0x28, 0xb5, 0x2f, 0xfd] {
        return Ok(LayerArchiveEncoding::ZstdTar);
    }
    Ok(LayerArchiveEncoding::RawTar)
}

fn validate_extracted_tree<R: std::io::Read>(
    archive: &mut tar::Archive<R>,
) -> Result<(), SourceError> {
    validate_extracted_tree_with_total_cap(archive, MAX_TAR_TOTAL_BYTES)
}

fn validate_extracted_tree_with_total_cap<R: std::io::Read>(
    archive: &mut tar::Archive<R>,
    total_cap: u64,
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
        if size > MAX_TAR_ENTRY_BYTES {
            return Err(SourceError::Other(format!(
                "docker archive entry '{}' exceeds {} bytes",
                path.display(),
                MAX_TAR_ENTRY_BYTES
            )));
        }
        // Zip-bomb defense: a malicious archive can ship 1000+ entries
        // each just under MAX_TAR_ENTRY_BYTES (127 MiB × 1000 = 127 GiB).
        // Each entry passes the per-entry gate but the cumulative
        // unpack exhausts disk. Reject before unpack starts.
        cumulative_bytes = cumulative_bytes.saturating_add(size);
        if cumulative_bytes > total_cap {
            return Err(SourceError::Other(format!(
                "docker archive cumulative size exceeds {} bytes at entry '{}' \
                 (likely zip-bomb)",
                total_cap,
                path.display(),
            )));
        }
    }

    Ok(())
}

fn find_layer_archives(root_path: &Path) -> Result<Vec<PathBuf>, SourceError> {
    let manifest_layers = find_manifest_layer_archives(root_path)?;
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
    )
    .walk()
    .map_err(|error| SourceError::Other(error.to_string()))?;

    for entry in walker {
        if entry.path.file_name().and_then(|name| name.to_str()) == Some("layer.tar") {
            layers.push(entry.path);
        }
    }
    dedup_layer_archives_by_content(layers)
}

#[derive(serde::Deserialize)]
struct DockerArchiveManifestEntry {
    #[serde(rename = "Config")]
    config: String,
    #[serde(rename = "Layers", default)]
    layers: Option<Vec<String>>,
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

fn load_manifest_entries(root_path: &Path) -> Result<Vec<DockerArchiveManifestEntry>, SourceError> {
    let manifest_path = root_path.join("manifest.json");
    if !manifest_path.is_file() {
        return Ok(Vec::new());
    }
    let manifest = read_capped_file(&manifest_path, "docker manifest", MAX_IMAGE_CONFIG_BYTES)?;
    serde_json::from_slice(&manifest).map_err(|error| {
        SourceError::Other(format!(
            "invalid docker manifest.json at '{}': {error}",
            manifest_path.display()
        ))
    })
}

fn find_manifest_config_chunks(root_path: &Path, image: &str) -> Result<Vec<Chunk>, SourceError> {
    let entries = load_manifest_entries(root_path)?;
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
        let bytes = read_capped_file(&config_path, "docker image config", MAX_IMAGE_CONFIG_BYTES)?;
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
    chunks.extend(find_oci_config_chunks(root_path, image)?);
    Ok(chunks)
}

fn find_manifest_layer_archives(root_path: &Path) -> Result<Vec<PathBuf>, SourceError> {
    let entries = load_manifest_entries(root_path)?;
    let mut layers = Vec::new();
    for entry in entries {
        let entry_layers = match entry.layers {
            Some(layers) => layers,
            None => Vec::new(),
        };
        for layer in entry_layers {
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
    layers.extend(find_oci_layer_archives(root_path)?);
    layers.sort();
    layers.dedup();
    Ok(layers)
}

fn load_oci_image_manifests(root_path: &Path) -> Result<Vec<OciLoadedManifest>, SourceError> {
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
    let index_bytes = read_capped_file(&index_path, "OCI image index", MAX_IMAGE_CONFIG_BYTES)?;
    let index: OciIndex = serde_json::from_slice(&index_bytes).map_err(|error| {
        SourceError::Other(format!(
            "invalid OCI image index '{}': {error}",
            index_path.display()
        ))
    })?;

    let mut manifests = Vec::new();
    for (idx, descriptor) in index.manifests.into_iter().enumerate() {
        let manifest_path = resolve_oci_blob_digest_path(root_path, "manifest", &descriptor)?;
        verify_oci_blob_sha256(&manifest_path, &descriptor.digest)?;
        let manifest_bytes =
            read_capped_file(&manifest_path, "OCI image manifest", MAX_IMAGE_CONFIG_BYTES)?;
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

fn find_oci_config_chunks(root_path: &Path, image: &str) -> Result<Vec<Chunk>, SourceError> {
    let manifests = load_oci_image_manifests(root_path)?;
    let mut chunks = Vec::new();
    for loaded in manifests {
        let config = loaded.manifest.config;
        let config_path = resolve_oci_blob_digest_path(root_path, "config", &config)?;
        verify_oci_blob_sha256(&config_path, &config.digest)?;
        let bytes = read_capped_file(&config_path, "OCI image config", MAX_IMAGE_CONFIG_BYTES)?;
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

fn find_oci_layer_archives(root_path: &Path) -> Result<Vec<PathBuf>, SourceError> {
    let manifests = load_oci_image_manifests(root_path)?;
    let mut layers = Vec::new();
    for loaded in manifests {
        for layer in loaded.manifest.layers {
            let layer_path = resolve_oci_blob_digest_path(root_path, "layer", &layer)?;
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
    let mut bytes = Vec::with_capacity(metadata.len().min(cap) as usize);
    file.take(cap.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(SourceError::Io)?;
    if bytes.len() as u64 > cap {
        return Err(SourceError::Other(format!(
            "{kind} '{}' exceeded {} bytes while reading",
            path.display(),
            cap
        )));
    }
    Ok(bytes)
}

fn resolve_oci_blob_digest_path(
    root_path: &Path,
    kind: &str,
    descriptor: &OciDescriptor,
) -> Result<PathBuf, SourceError> {
    let hex = parse_oci_sha256_digest(kind, &descriptor.digest)?;
    if let Some(size) = descriptor.size {
        if size > MAX_TAR_TOTAL_BYTES {
            return Err(SourceError::Other(format!(
                "OCI {kind} descriptor '{}' declares {} bytes, above {} byte cap",
                descriptor.digest, size, MAX_TAR_TOTAL_BYTES
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

#[doc(hidden)]
pub(crate) fn manifest_layer_archives_for_test(
    root_path: &Path,
) -> Result<Vec<PathBuf>, SourceError> {
    find_layer_archives(root_path)
}

#[doc(hidden)]
pub(crate) fn manifest_config_chunks_for_test(
    root_path: &Path,
    image: &str,
) -> Result<Vec<Chunk>, SourceError> {
    find_manifest_config_chunks(root_path, image)
}

#[doc(hidden)]
pub(crate) fn unpack_layer_archive_for_test(
    archive_path: &Path,
    destination: &Path,
) -> Result<(), SourceError> {
    unpack_layer_archive(archive_path, destination)
}

#[doc(hidden)]
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

#[doc(hidden)]
pub(crate) fn validate_tar_archive_for_test(archive_path: &Path) -> Result<(), SourceError> {
    validate_tar_archive_with_total_cap_for_test(archive_path, MAX_TAR_TOTAL_BYTES)
}

#[doc(hidden)]
pub(crate) fn validate_tar_archive_with_total_cap_for_test(
    archive_path: &Path,
    total_cap: u64,
) -> Result<(), SourceError> {
    let file = File::open(archive_path).map_err(SourceError::Io)?;
    let mut archive = tar::Archive::new(file);
    validate_extracted_tree_with_total_cap(&mut archive, total_cap)
}
