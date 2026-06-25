use super::file_read::read_capped_file;
use keyhog_core::{Chunk, ChunkMetadata, SourceError};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Maximum image-index nesting the OCI reader will follow. One level covers the
/// common BuildKit layout (index.json → image index → manifests); the bound
/// stops a maliciously self-referential or pathologically deep image from
/// driving unbounded blob reads.
const MAX_OCI_INDEX_DEPTH: u32 = 8;

#[derive(serde::Deserialize)]
struct OciIndex {
    #[serde(default)]
    manifests: Vec<OciDescriptor>,
}

#[derive(Clone, serde::Deserialize)]
struct OciDescriptor {
    #[serde(rename = "mediaType", default)]
    media_type: Option<String>,
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

pub(super) fn config_chunks(
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

pub(super) fn layer_archives(
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

    // Each top-level index entry may point either at an image manifest (carries
    // a `config`) or at a NESTED image index / manifest-list (carries
    // `manifests`). `docker build` with BuildKit emits the latter for
    // multi-platform images and for the attestation manifests it attaches, so a
    // single-platform `FROM scratch` build still nests one level. Follow nested
    // indexes (bounded depth) down to the real image manifests instead of
    // mis-parsing an index blob as a manifest and failing with "missing field
    // config". Entries are processed in their original top-level order.
    let mut manifests = Vec::new();
    let mut work: Vec<(u32, usize, OciDescriptor)> = index
        .manifests
        .into_iter()
        .enumerate()
        .map(|(idx, descriptor)| (0u32, idx, descriptor))
        .rev()
        .collect();
    while let Some((depth, idx, descriptor)) = work.pop() {
        let manifest_path =
            resolve_oci_blob_digest_path(root_path, "manifest", &descriptor, limits)?;
        verify_oci_blob_sha256(&manifest_path, &descriptor.digest)?;
        let manifest_bytes = read_capped_file(
            &manifest_path,
            "OCI image manifest",
            limits.docker_image_config_bytes,
        )?;
        if descriptor_points_to_index(&descriptor, &manifest_bytes) {
            if depth >= MAX_OCI_INDEX_DEPTH {
                return Err(SourceError::Other(format!(
                    "OCI image index nesting exceeded {MAX_OCI_INDEX_DEPTH} levels at \
                     entry {idx}; refusing to follow further"
                )));
            }
            let nested: OciIndex = serde_json::from_slice(&manifest_bytes).map_err(|error| {
                SourceError::Other(format!(
                    "invalid nested OCI image index '{}' from index entry {idx}: {error}",
                    descriptor.digest
                ))
            })?;
            // Preserve original order: push reversed so the first nested entry
            // is popped first.
            for nested_descriptor in nested.manifests.into_iter().rev() {
                work.push((depth + 1, idx, nested_descriptor));
            }
            continue;
        }
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

/// Whether an index entry points at a nested image index / manifest-list rather
/// than an image manifest. The declared `mediaType` is authoritative when
/// present; otherwise the blob is classified structurally — an image index
/// carries `manifests` and no `config`, an image manifest the reverse.
fn descriptor_points_to_index(descriptor: &OciDescriptor, bytes: &[u8]) -> bool {
    if let Some(media_type) = descriptor.media_type.as_deref() {
        if media_type.contains("image.index") || media_type.contains("manifest.list") {
            return true;
        }
        if media_type.contains("image.manifest")
            || media_type.ends_with("distribution.manifest.v2+json")
        {
            return false;
        }
    }
    #[derive(serde::Deserialize)]
    struct Shape {
        #[serde(default)]
        manifests: Option<serde_json::Value>,
        #[serde(default)]
        config: Option<serde_json::Value>,
    }
    match serde_json::from_slice::<Shape>(bytes) {
        Ok(shape) => shape.config.is_none() && shape.manifests.is_some(),
        // LAW10: an unparseable blob is classified as not-an-index, so the caller
        // parses it as an image manifest and surfaces a loud parse error for the
        // entry — the descriptor is never silently skipped.
        Err(_) => false,
    }
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

/// Test accessor: classify a descriptor with the given media type + body
/// exactly as the extractor does, without exposing the private `OciDescriptor`.
/// Drives the integration coverage in `tests/` so the Santh "no inline tests"
/// contract for `src/docker/**` holds.
pub(crate) fn descriptor_points_to_index_for_test(media_type: Option<&str>, body: &[u8]) -> bool {
    descriptor_points_to_index(
        &OciDescriptor {
            media_type: media_type.map(str::to_owned),
            digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            size: None,
            annotations: BTreeMap::new(),
        },
        body,
    )
}
