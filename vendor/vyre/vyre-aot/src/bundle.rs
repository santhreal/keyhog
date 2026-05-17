//! Submission-bundle packager.
//!
//! Takes a [`CompiledArtifact`] + uncompressed weight bytes + a launcher
//! source tree and writes the on-disk submission directory:
//!
//! ```text
//! <bundle_dir>/
//! ├── manifest.json
//! ├── kernel.<ext>.lzma         (LZMA-compressed kernel bytes)
//! ├── weights.brotli            (Brotli-11-compressed weight bytes)
//! ├── pgolf-launcher/           (Rust launcher crate source)
//! │   ├── Cargo.toml
//! │   ├── .cargo/config.toml
//! │   └── src/{main.rs,artifact.rs,...}
//! └── README.md
//! ```
//!
//! The launcher source is shipped *unbuilt* by default. Submission
//! packaging compiles it once on the target hardware (5090 / H100) and
//! ships the static binary in place of the source tree.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::artifact::CompiledArtifact;
use crate::launcher::{emit_launcher_rust, LauncherError, LauncherOpts};
use crate::manifest::Manifest;

/// Produced layout of a bundle.
#[derive(Debug, Clone)]
pub struct Bundle {
    /// Files written to disk relative to bundle root, with absolute paths.
    pub files: Vec<PathBuf>,
}

/// Error variants returned by [`bundle`].
#[derive(Debug, Error)]
pub enum BundleError {
    /// I/O while writing files.
    #[error("vyre-aot bundle: i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization of the manifest failed.
    #[error("vyre-aot bundle: manifest serialization: {0}")]
    Json(#[from] serde_json::Error),

    /// LZMA compression failed.
    #[error("vyre-aot bundle: lzma error: {0}")]
    Lzma(String),

    /// Brotli compression failed.
    #[error("vyre-aot bundle: brotli error: {0}")]
    Brotli(String),

    /// Launcher generation failed.
    #[error(transparent)]
    Launcher(#[from] LauncherError),
}

/// Write the full bundle.
///
/// `weights` is the uncompressed weight bytes (bytes the launcher will
/// upload to the `params` device buffer after Brotli decompression).
pub fn bundle(
    out_dir: &Path,
    artifact: &CompiledArtifact,
    weights: &[u8],
    artifact_name: &str,
    launcher_opts: &LauncherOpts,
    notes: &str,
) -> Result<Bundle, BundleError> {
    fs::create_dir_all(out_dir)?;
    let launcher_tree: BTreeMap<PathBuf, String> = emit_launcher_rust(artifact, launcher_opts)?;

    // 1. Compress kernel bytes via LZMA.
    let kernel_compressed = lzma_compress(&artifact.kernel_bytes)?;
    let kernel_filename = format!("kernel.{}.lzma", artifact.target.extension());
    let kernel_path = out_dir.join(&kernel_filename);
    fs::write(&kernel_path, &kernel_compressed)?;

    // 2. Compress weights via Brotli-11.
    let weights_compressed = brotli_compress(weights)?;
    let weights_filename = "weights.brotli".to_string();
    let weights_path = out_dir.join(&weights_filename);
    fs::write(&weights_path, &weights_compressed)?;

    // 3. Compute hashes of the *uncompressed* bytes for manifest.
    let kernel_sha = sha256_hex(&artifact.kernel_bytes);
    let weights_sha = sha256_hex(weights);

    // 4. Write manifest.
    let manifest = Manifest {
        schema: Manifest::SCHEMA_VERSION.to_string(),
        aot_version: artifact.aot_version.clone(),
        artifact_name: artifact_name.to_string(),
        target: artifact.target,
        entry_point: artifact.entry_point.clone(),
        dispatch: artifact.dispatch,
        kernel_file: kernel_filename.clone(),
        weights_file: weights_filename.clone(),
        kernel_compression: "lzma".to_string(),
        weights_compression: "brotli-11".to_string(),
        buffers: artifact.buffers.clone(),
        kernel_sha256_hex: kernel_sha,
        weights_sha256_hex: weights_sha,
        notes: notes.to_string(),
        vsa_fingerprint: artifact.vsa_fingerprint.clone(),
    };
    let manifest_path = out_dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;

    // 5. Write launcher source tree.
    let launcher_root = out_dir.join(&launcher_opts.crate_name);
    let mut written: Vec<PathBuf> = Vec::with_capacity(launcher_tree.len() + 3);
    for (rel, contents) in launcher_tree {
        let abs = launcher_root.join(rel);
        if let Some(parent) = abs.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&abs, contents)?;
        written.push(abs);
    }

    // 6. Write top-level README.
    let readme = format!(
        "# {artifact_name}\n\n\
        Self-contained vyre-aot bundle.\n\n\
        ## Build the launcher\n\n\
        ```\n\
        cd {crate_name}\n\
        cargo build --release\n\
        ```\n\n\
        ## Run\n\n\
        ```\n\
        {crate_name}/target/release/{crate_name} <bundle_dir>\n\
        ```\n",
        crate_name = launcher_opts.crate_name,
    );
    let readme_path = out_dir.join("README.md");
    fs::write(&readme_path, readme)?;

    written.extend([kernel_path, weights_path, manifest_path, readme_path]);

    Ok(Bundle { files: written })
}

fn lzma_compress(input: &[u8]) -> Result<Vec<u8>, BundleError> {
    let mut out = Vec::with_capacity(input.len() / 2);
    let mut cursor = Cursor::new(input);
    lzma_rs::lzma_compress(&mut cursor, &mut out)
        .map_err(|e| BundleError::Lzma(format!("{e:?}")))?;
    Ok(out)
}

fn brotli_compress(input: &[u8]) -> Result<Vec<u8>, BundleError> {
    let mut out = Vec::with_capacity(input.len() / 2);
    let params = brotli::enc::BrotliEncoderParams {
        quality: 11,
        ..Default::default()
    };
    {
        let mut writer = brotli::CompressorWriter::with_params(&mut out, 4096, &params);
        writer
            .write_all(input)
            .map_err(|e| BundleError::Brotli(format!("{e}")))?;
        writer
            .flush()
            .map_err(|e| BundleError::Brotli(format!("{e}")))?;
    }
    Ok(out)
}

fn sha256_hex(input: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(input);
    let mut s = String::with_capacity(hash.len() * 2);
    for b in hash {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
    }
    s
}
