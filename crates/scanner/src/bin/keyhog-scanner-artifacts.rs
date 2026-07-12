use keyhog_core::DetectorSpec;
use keyhog_scanner::{compile_gpu_literal_artifacts_default, GpuLiteralArtifact};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};

type DynResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
struct Args {
    out_dir: PathBuf,
    detectors: Option<PathBuf>,
}

#[derive(Serialize)]
struct ArtifactManifest {
    format_version: u32,
    keyhog_version: &'static str,
    detector_source: String,
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

fn main() -> DynResult<()> {
    let Some(args) = parse_args()? else {
        return Ok(());
    };

    let (detectors, detector_source) = load_detector_set(args.detectors.as_deref())?;
    let detector_set_sha256 = detector_set_sha256(&detectors)?;
    let artifacts = compile_gpu_literal_artifacts_default(&detectors)?;
    std::fs::create_dir_all(&args.out_dir).map_err(|source| {
        io_error_with_context(
            source,
            format!(
                "failed to create artifact output directory {}",
                args.out_dir.display()
            ),
        )
    })?;

    let mut manifest_entries = Vec::new();
    if let Some(artifact) = artifacts.literal {
        manifest_entries.push(write_artifact(&args.out_dir, "literal", artifact)?);
    }
    if let Some(artifact) = artifacts.positioned_literal {
        manifest_entries.push(write_artifact(
            &args.out_dir,
            "positioned_literal",
            artifact,
        )?);
    }
    if manifest_entries.is_empty() {
        return Err(invalid_input(
            "scanner produced no GPU literal artifacts; detector corpus has no literal rows",
        ));
    }

    let manifest = ArtifactManifest {
        format_version: 1,
        keyhog_version: env!("CARGO_PKG_VERSION"),
        detector_source,
        detector_count: detectors.len(),
        detector_set_sha256,
        artifacts: manifest_entries,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    let manifest_path = args.out_dir.join("manifest.json");
    write_bytes_atomic(&manifest_path, &manifest_bytes).map_err(|source| {
        io_error_with_context(
            source,
            format!(
                "failed to write artifact manifest {}",
                manifest_path.display()
            ),
        )
    })?;
    println!("{}", args.out_dir.join("manifest.json").display());
    Ok(())
}

fn parse_args() -> DynResult<Option<Args>> {
    let mut out_dir = None;
    let mut detectors = None;
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--help" || arg == "-h" {
            print_usage();
            return Ok(None);
        }
        if let Some(value) = split_equals(&arg, "--out-dir") {
            out_dir = Some(PathBuf::from(value));
            continue;
        }
        if let Some(value) = split_equals(&arg, "--detectors") {
            detectors = Some(PathBuf::from(value));
            continue;
        }
        match arg.to_str() {
            Some("--out-dir") => {
                out_dir = Some(PathBuf::from(next_value(&mut args, "--out-dir")?));
            }
            Some("--detectors") => {
                detectors = Some(PathBuf::from(next_value(&mut args, "--detectors")?));
            }
            Some(other) => {
                return Err(invalid_input(format!("unknown argument {other}")));
            }
            None => {
                return Err(invalid_input("arguments must be valid UTF-8 flags"));
            }
        }
    }

    let out_dir = out_dir.ok_or_else(|| invalid_input("missing required --out-dir <DIR>"))?;
    Ok(Some(Args { out_dir, detectors }))
}

fn split_equals(arg: &OsString, flag: &str) -> Option<OsString> {
    split_equals_os(arg.as_os_str(), flag)
}

#[cfg(unix)]
fn split_equals_os(arg: &OsStr, flag: &str) -> Option<OsString> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let prefix = format!("{flag}=");
    let bytes = arg.as_bytes();
    bytes
        .strip_prefix(prefix.as_bytes())
        .map(|value| OsString::from_vec(value.to_vec()))
}

#[cfg(windows)]
fn split_equals_os(arg: &OsStr, flag: &str) -> Option<OsString> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    let mut prefix: Vec<u16> = flag.encode_utf16().collect();
    prefix.push('=' as u16);
    let wide: Vec<u16> = arg.encode_wide().collect();
    wide.strip_prefix(&prefix).map(OsString::from_wide)
}

#[cfg(not(any(unix, windows)))]
fn split_equals_os(arg: &OsStr, flag: &str) -> Option<OsString> {
    let text = arg.to_str()?;
    let prefix = format!("{flag}=");
    text.strip_prefix(&prefix).map(OsString::from)
}

fn next_value(
    args: &mut impl Iterator<Item = OsString>,
    flag: &'static str,
) -> DynResult<OsString> {
    args.next()
        .ok_or_else(|| invalid_input(format!("{flag} requires a value")))
}

fn print_usage() {
    println!(
        "Usage: keyhog-scanner-artifacts --out-dir <DIR> [--detectors <DIR>]\n\
         Writes Vyre GPU literal matcher blobs plus manifest.json."
    );
}

fn load_detector_set(path: Option<&Path>) -> DynResult<(Vec<DetectorSpec>, String)> {
    match path {
        Some(path) => {
            let detectors = keyhog_core::load_detectors(path)?;
            Ok((detectors, path.display().to_string()))
        }
        None => {
            let detectors = keyhog_core::load_embedded_detectors_or_fail()?;
            Ok((detectors, "embedded".to_string()))
        }
    }
}

fn detector_set_sha256(detectors: &[DetectorSpec]) -> DynResult<String> {
    let bytes = serde_json::to_vec(detectors)?;
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    Ok(keyhog_core::hex_encode(&digest))
}

fn write_artifact(
    out_dir: &Path,
    kind: &'static str,
    artifact: GpuLiteralArtifact,
) -> DynResult<ArtifactManifestEntry> {
    let file_name = format!("{}.bin", artifact.cache_key);
    let path = out_dir.join(&file_name);
    write_bytes_atomic(&path, &artifact.bytes).map_err(|source| {
        io_error_with_context(
            source,
            format!("failed to write GPU literal artifact {}", path.display()),
        )
    })?;
    Ok(ArtifactManifestEntry {
        kind,
        cache_key: artifact.cache_key,
        file_name,
        pattern_count: artifact.pattern_count,
        byte_len: artifact.bytes.len(),
        wire_magic_hex: keyhog_core::hex_encode(&artifact.wire_magic),
        wire_version: artifact.wire_version,
    })
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = match path.parent().filter(|path| !path.as_os_str().is_empty()) {
        Some(parent) => parent,
        None => Path::new("."), // LAW10: parentless explicit output names are created relative to the current directory, matching std::fs::write.
    };
    std::fs::create_dir_all(parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map(drop).map_err(|error| error.error)
}

fn invalid_input(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message.into(),
    ))
}

fn io_error_with_context(source: std::io::Error, message: String) -> std::io::Error {
    std::io::Error::new(source.kind(), format!("{message}: {source}"))
}
