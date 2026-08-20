use crate::args::CompileGpuLiteralsArgs;
use anyhow::{bail, Context, Result};
use keyhog_scanner::{
    compile_gpu_literal_artifacts_default, gpu_literal_artifact_cache_dir, GpuLiteralArtifact,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Pinned by `manifest.json` consumers, so a shape change is a version bump.
const MANIFEST_FORMAT_VERSION: u32 = 1;

#[derive(Serialize)]
struct ArtifactManifest {
    format_version: u32,
    keyhog_version: &'static str,
    detector_source: &'static str,
    detector_count: usize,
    detector_set_sha256: String,
    artifacts: Vec<ArtifactManifestEntry>,
}

#[derive(Serialize)]
struct ArtifactManifestEntry {
    kind: &'static str,
    cache_key: String,
    file_name: String,
    pattern_count: usize,
    byte_len: usize,
    wire_magic_hex: String,
    wire_version: u32,
}

/// Compile the detector corpus embedded in THIS binary into the GPU literal
/// matcher artifacts the scanner otherwise builds on first use.
///
/// The installer calls this so a host always has the artifacts. Before it
/// existed the only producer was `keyhog-scanner-artifacts`, a development
/// binary that is not shipped, and the installer required the artifacts as a
/// sidecar tarball beside the binary. Nothing produced that tarball outside CI
/// and test fixtures, so every `--from-file` install failed closed, and
/// `--from-file` is the only install mode.
pub(crate) fn run(args: CompileGpuLiteralsArgs) -> Result<()> {
    let out_dir = match args.output_dir {
        Some(dir) => dir,
        None => gpu_literal_artifact_cache_dir()
            .context("resolving the host GPU literal artifact cache directory")?,
    };
    let detectors = keyhog_core::load_embedded_detectors_or_fail()
        .context("loading embedded detectors for GPU literal compilation")?;
    let detector_set_sha256 = detector_set_sha256(&detectors)?;
    let artifacts = compile_gpu_literal_artifacts_default(&detectors)
        .map_err(anyhow::Error::new)
        .context("compiling GPU literal matcher artifacts")?;

    fs::create_dir_all(&out_dir).with_context(|| {
        format!(
            "creating GPU literal artifact directory {}",
            out_dir.display()
        )
    })?;

    let mut entries = Vec::new();
    if let Some(artifact) = artifacts.literal {
        entries.push(write_artifact(&out_dir, "literal", artifact)?);
    }
    if let Some(artifact) = artifacts.positioned_literal {
        entries.push(write_artifact(&out_dir, "positioned_literal", artifact)?);
    }
    if entries.is_empty() {
        // Fail closed: an empty publish would leave the scanner compiling
        // matchers at runtime while the installer reported success.
        bail!("the embedded detector corpus produced no GPU literal artifacts");
    }

    let manifest = ArtifactManifest {
        format_version: MANIFEST_FORMAT_VERSION,
        keyhog_version: env!("CARGO_PKG_VERSION"),
        detector_source: "embedded",
        detector_count: detectors.len(),
        detector_set_sha256,
        artifacts: entries,
    };
    let manifest_path = out_dir.join("manifest.json");
    let manifest_bytes =
        serde_json::to_vec_pretty(&manifest).context("serializing the GPU literal manifest")?;
    write_bytes_atomic(&manifest_path, &manifest_bytes)
        .with_context(|| format!("writing GPU literal manifest {}", manifest_path.display()))?;

    println!("{}", manifest_path.display());
    Ok(())
}

fn detector_set_sha256(detectors: &[keyhog_core::DetectorSpec]) -> Result<String> {
    let mut hasher = Sha256::new();
    for detector in detectors {
        let encoded =
            serde_json::to_vec(detector).context("serializing a detector for the corpus digest")?;
        hasher.update((encoded.len() as u64).to_le_bytes());
        hasher.update(&encoded);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn write_artifact(
    out_dir: &Path,
    kind: &'static str,
    artifact: GpuLiteralArtifact,
) -> Result<ArtifactManifestEntry> {
    let file_name = format!("{}.bin", artifact.cache_key);
    let path = out_dir.join(&file_name);
    write_bytes_atomic(&path, &artifact.bytes)
        .with_context(|| format!("writing GPU literal artifact {}", path.display()))?;
    Ok(ArtifactManifestEntry {
        kind,
        cache_key: artifact.cache_key,
        file_name,
        pattern_count: artifact.pattern_count,
        byte_len: artifact.bytes.len(),
        wire_magic_hex: hex::encode(artifact.wire_magic),
        wire_version: artifact.wire_version,
    })
}

/// Write through a sibling temp file, fsync, then rename. A half-written
/// matcher that the scanner later mmaps is worse than no matcher at all.
fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new(".")); // LAW10: relative path fallback to current directory
    let tmp: PathBuf = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("artifact") // LAW10: temporary file naming fallback
    ));
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)
}
