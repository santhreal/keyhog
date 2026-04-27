//! Disk-backed WGSL + compiled-pipeline cache for compiled pipeline mode.
//!
//! WGSL source and driver pipeline-cache blobs are persisted separately:
//! shader text is keyed by the compile-relevant program shape, while compiled
//! pipeline blobs are keyed by adapter fingerprint + ABI + WGSL hash + Naga
//! version so a second process can reuse executable pipeline artifacts.
//!
//! # Kill switch
//!
//! `VYRE_PIPELINE_CACHE=off` (case-insensitive) short-circuits both read and
//! write paths and forces a fresh compile every call. Useful when debugging a
//! stale cache entry or when the cache file system is read-only.
//!
//! # Cache directory
//!
//! Override via `VYRE_CACHE_DIR=<path>` (applies the `/pipeline` subdirectory
//! beneath it). Default: `$HOME/.cache/vyre/pipeline`.

use fs2::FileExt;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use vyre_driver::{BackendError, DispatchConfig};
use vyre_foundation::ir::Program;
use vyre_foundation::serial::wire::framing::WIRE_FORMAT_VERSION;
use vyre_foundation::serial::wire::{append_data_type_fingerprint, append_node_list_fingerprint};

const DISK_PIPELINE_CACHE_VERSION: u32 = 4;
const NAGA_VERSION: &str = env!("VYRE_NAGA_VERSION");
const MAX_WGSL_CACHE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_COMPILED_PIPELINE_CACHE_BLOB_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PIPELINE_CACHE_METADATA_BYTES: u64 = 64 * 1024;

pub(crate) struct CompiledPipelineCacheKey {
    pub(crate) hash: [u8; 32],
    adapter_fingerprint: String,
    cache_key: String,
    wgsl_blake3: String,
}

pub(crate) struct PipelineCacheHandle {
    pub(crate) cache: wgpu::PipelineCache,
}

pub(crate) fn load_or_compile_disk_wgsl(
    program: &Program,
    adapter_info: &wgpu::AdapterInfo,
    config: &DispatchConfig,
    enabled_features: &crate::runtime::device::EnabledFeatures,
) -> Result<String, BackendError> {
    let fingerprint = adapter_fingerprint(adapter_info);

    // When the kill switch is set, bypass the cache entirely — still invoke
    // the regular aot compile path so behaviour matches a fresh run.
    if cache_disabled() {
        return lower_wgsl(program, config, enabled_features);
    }

    let norm_digest = normalized_cache_digest(program);
    let cache_key = wgsl_cache_key(&norm_digest, &fingerprint, config);
    let dir = disk_pipeline_cache_dir();
    let wgsl_path = dir.join(format!("{cache_key}.wgsl"));
    let meta_path = dir.join(format!("{cache_key}.wgsl.toml"));
    if let Ok(wgsl) = read_bounded_utf8(&wgsl_path, MAX_WGSL_CACHE_BYTES) {
        if wgsl_metadata_matches(&meta_path, &cache_key, &wgsl, &fingerprint, config) {
            return Ok(wgsl);
        }
    }
    let start = std::time::Instant::now();
    let wgsl = lower_wgsl(program, config, enabled_features)?;
    let elapsed = start.elapsed();
    tracing::info!(
        program_fingerprint = %cache_key,
        elapsed_ms = elapsed.as_secs_f64() * 1000.0,
        "WGSL cache miss — cold cache or program shape changed"
    );
    persist_disk_wgsl(
        &dir,
        &wgsl_path,
        &meta_path,
        &cache_key,
        &wgsl,
        &fingerprint,
        config,
    )?;
    Ok(wgsl)
}

/// Derive a cheap in-memory pipeline-cache key that does not require
/// WGSL source. Consumers check this key *before* any disk I/O or
/// WGSL lowering; a hit short-circuits the entire compile path
/// (VYRE_NAGA_LOWER CRIT-02).
///
/// The key uses `program.fingerprint()` — the lazily cached blake3
/// of the canonical wire-format bytes — so repeated lookups for the
/// same Program are O(1) after the first `to_wire` call.
///
/// The Program fingerprint fully determines the emitted WGSL under
/// a fixed (adapter, wire-format-version, naga-version, config
/// policy) tuple, so a hit on the early key is safe: the compiled
/// pipeline was produced from the exact same inputs.
pub(crate) fn early_pipeline_cache_key(
    program: &Program,
    adapter_info: &wgpu::AdapterInfo,
    config: &DispatchConfig,
) -> [u8; 32] {
    let adapter_fp = adapter_fingerprint(adapter_info);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"vyre-early-pipeline-cache-v1\0program\0");
    hasher.update(&program.fingerprint());
    hasher.update(b"\0adapter\0");
    hasher.update(adapter_fp.as_bytes());
    hasher.update(b"\0abi\0");
    hasher.update(&WIRE_FORMAT_VERSION.to_le_bytes());
    hasher.update(b"\0naga\0");
    hasher.update(NAGA_VERSION.as_bytes());
    hasher.update(b"\0policy\0");
    hasher.update(config_cache_policy(config).as_bytes());
    hasher.update(b"\0workgroup_override\0");
    if let Some(wg) = config.workgroup_override {
        for axis in wg {
            hasher.update(&axis.to_le_bytes());
        }
    }
    *hasher.finalize().as_bytes()
}

pub(crate) fn compiled_pipeline_cache_key(
    adapter_info: &wgpu::AdapterInfo,
    wgsl_source: &str,
) -> CompiledPipelineCacheKey {
    let adapter_fingerprint = adapter_fingerprint(adapter_info);
    let wgsl_blake3 = blake3::hash(wgsl_source.as_bytes()).to_hex().to_string();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"vyre-compiled-pipeline-cache-v1\0");
    hasher.update(adapter_fingerprint.as_bytes());
    hasher.update(b"\0abi\0");
    hasher.update(&WIRE_FORMAT_VERSION.to_le_bytes());
    hasher.update(b"\0wgsl\0");
    hasher.update(wgsl_blake3.as_bytes());
    hasher.update(b"\0naga\0");
    hasher.update(NAGA_VERSION.as_bytes());
    let hash = *hasher.finalize().as_bytes();
    let cache_key = hex_hash(&hash);
    CompiledPipelineCacheKey {
        hash,
        adapter_fingerprint,
        cache_key,
        wgsl_blake3,
    }
}

pub(crate) fn create_compiled_pipeline_cache(
    device: &wgpu::Device,
    key: &CompiledPipelineCacheKey,
) -> Result<PipelineCacheHandle, BackendError> {
    let data = if cache_disabled() {
        None
    } else {
        load_compiled_pipeline_blob(key)?
    };
    let cache = {
        #[allow(unsafe_code)]
        // SAFETY: wgpu validates pipeline-cache descriptor data and owns the created cache.
        unsafe {
            device.create_pipeline_cache(&wgpu::PipelineCacheDescriptor {
                label: Some("vyre persistent compiled pipeline cache"),
                data: data.as_deref(),
                fallback: true,
            })
        }
    };
    Ok(PipelineCacheHandle { cache })
}

pub(crate) fn persist_compiled_pipeline_cache(
    key: &CompiledPipelineCacheKey,
    cache: &wgpu::PipelineCache,
) -> Result<(), BackendError> {
    if cache_disabled() {
        return Ok(());
    }
    let Some(bytes) = cache.get_data() else {
        return Ok(());
    };
    let dir = disk_pipeline_cache_dir();
    let blob_path = dir.join(format!("{}.pipeline.bin", key.cache_key));
    let meta_path = dir.join(format!("{}.pipeline.toml", key.cache_key));
    let metadata = CompiledPipelineMetadata {
        version: DISK_PIPELINE_CACHE_VERSION,
        cache_key: key.cache_key.clone(),
        adapter_fingerprint: key.adapter_fingerprint.clone(),
        wgsl_blake3: key.wgsl_blake3.clone(),
        program_abi_version: u32::from(WIRE_FORMAT_VERSION),
        naga_version: NAGA_VERSION.to_string(),
        blob_bytes: bytes.len(),
        blob_blake3: blake3_hex(&bytes),
    };
    persist_bytes(&dir, &blob_path, &meta_path, &bytes, &metadata)
}

fn cache_disabled() -> bool {
    matches!(
        std::env::var("VYRE_PIPELINE_CACHE").ok().as_deref(),
        Some(value) if value.eq_ignore_ascii_case("off")
            || value.eq_ignore_ascii_case("0")
            || value.eq_ignore_ascii_case("false")
    )
}

fn persist_disk_wgsl(
    dir: &Path,
    wgsl_path: &Path,
    meta_path: &Path,
    cache_key: &str,
    wgsl: &str,
    fingerprint: &str,
    config: &DispatchConfig,
) -> Result<(), BackendError> {
    let metadata = DiskPipelineMetadata {
        version: DISK_PIPELINE_CACHE_VERSION,
        cache_key: cache_key.to_string(),
        wgsl_bytes: wgsl.len(),
        adapter_fingerprint: fingerprint.to_string(),
        program_abi_version: u32::from(WIRE_FORMAT_VERSION),
        naga_version: NAGA_VERSION.to_string(),
        policy: config_cache_policy(config),
        wgsl_blake3: blake3_hex(wgsl.as_bytes()),
    };
    persist_bytes(dir, wgsl_path, meta_path, wgsl.as_bytes(), &metadata)
}

fn wgsl_metadata_matches(
    meta_path: &Path,
    cache_key: &str,
    wgsl: &str,
    fingerprint: &str,
    config: &DispatchConfig,
) -> bool {
    let Ok(metadata) = read_metadata::<DiskPipelineMetadata>(meta_path) else {
        return false;
    };
    metadata.version == DISK_PIPELINE_CACHE_VERSION
        && metadata.cache_key == cache_key
        && metadata.wgsl_bytes == wgsl.len()
        && metadata.adapter_fingerprint == fingerprint
        && metadata.program_abi_version == u32::from(WIRE_FORMAT_VERSION)
        && metadata.naga_version == NAGA_VERSION
        && metadata.policy == config_cache_policy(config)
        && metadata.wgsl_blake3 == blake3_hex(wgsl.as_bytes())
}

fn load_compiled_pipeline_blob(
    key: &CompiledPipelineCacheKey,
) -> Result<Option<Vec<u8>>, BackendError> {
    let dir = disk_pipeline_cache_dir();
    let blob_path = dir.join(format!("{}.pipeline.bin", key.cache_key));
    let meta_path = dir.join(format!("{}.pipeline.toml", key.cache_key));
    let Ok(metadata) = read_metadata::<CompiledPipelineMetadata>(&meta_path) else {
        tracing::warn!(
            adapter_fingerprint = %key.adapter_fingerprint,
            naga_version = %NAGA_VERSION,
            abi_version = %WIRE_FORMAT_VERSION,
            "compiled-pipeline cache miss — pipeline will be rebuilt (10-100 ms)"
        );
        return Ok(None);
    };
    if metadata.version != DISK_PIPELINE_CACHE_VERSION
        || metadata.cache_key != key.cache_key
        || metadata.adapter_fingerprint != key.adapter_fingerprint
        || metadata.wgsl_blake3 != key.wgsl_blake3
        || metadata.program_abi_version != u32::from(WIRE_FORMAT_VERSION)
        || metadata.naga_version != NAGA_VERSION
    {
        tracing::warn!(
            adapter_fingerprint = %key.adapter_fingerprint,
            naga_version = %NAGA_VERSION,
            abi_version = %WIRE_FORMAT_VERSION,
            "compiled-pipeline cache miss — pipeline will be rebuilt (10-100 ms)"
        );
        return Ok(None);
    }
    if metadata.blob_bytes as u64 > MAX_COMPILED_PIPELINE_CACHE_BLOB_BYTES {
        tracing::warn!(
            adapter_fingerprint = %key.adapter_fingerprint,
            naga_version = %NAGA_VERSION,
            abi_version = %WIRE_FORMAT_VERSION,
            "compiled-pipeline cache miss — cached driver blob exceeds the bounded cache contract"
        );
        return Ok(None);
    }
    let bytes = read_bounded_bytes(&blob_path, MAX_COMPILED_PIPELINE_CACHE_BLOB_BYTES).map_err(|error| {
        BackendError::new(format!(
            "failed to read compiled pipeline cache entry {}: {error}. Fix: remove the corrupted cache entry and rerun the shader compile.",
            path_fingerprint(&blob_path)
        ))
    })?;
    if bytes.len() != metadata.blob_bytes || blake3_hex(&bytes) != metadata.blob_blake3 {
        tracing::warn!(
            adapter_fingerprint = %key.adapter_fingerprint,
            naga_version = %NAGA_VERSION,
            abi_version = %WIRE_FORMAT_VERSION,
            "compiled-pipeline cache miss — pipeline will be rebuilt (10-100 ms)"
        );
        return Ok(None);
    }
    Ok(Some(bytes))
}

fn trace_io_err(path: &Path, error: &std::io::Error, context: &str) {
    tracing::error!(
        path_id = %path_fingerprint(path),
        error_kind = ?error.kind(),
        "{context}"
    );
}

fn persist_bytes<T: serde::Serialize>(
    dir: &Path,
    data_path: &Path,
    meta_path: &Path,
    bytes: &[u8],
    metadata: &T,
) -> Result<(), BackendError> {
    fs::create_dir_all(dir).map_err(|error| {
        trace_io_err(dir, &error, "pipeline cache directory is unwritable");
        BackendError::new(format!(
            "failed to create pipeline cache dir {}: {error}. Fix: ensure ~/.cache/vyre/pipeline is writable.",
            path_fingerprint(dir)
        ))
    })?;
    write_atomic(data_path, bytes, "pipeline cache data")?;
    let encoded = toml::to_string(metadata).map_err(|error| {
        BackendError::new(format!(
            "failed to encode pipeline cache metadata: {error}. Fix: report this vyre-wgpu cache bug."
        ))
    })?;
    write_atomic(meta_path, encoded.as_bytes(), "pipeline cache metadata")
}

fn write_atomic(path: &Path, bytes: &[u8], label: &str) -> Result<(), BackendError> {
    static TMP_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let tmp_id = TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp_path = path.with_extension(format!(
        "{}.tmp.{}_{}",
        path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("cache"),
        std::process::id(),
        tmp_id
    ));
    let mut file = File::create(&tmp_path).map_err(|error| {
        trace_io_err(
            &tmp_path,
            &error,
            "pipeline cache temp file creation failed",
        );
        BackendError::new(format!(
            "failed to create {label} {}: {error}. Fix: ensure ~/.cache/vyre/pipeline is writable.",
            path_fingerprint(&tmp_path)
        ))
    })?;
    file.lock_exclusive().map_err(|error| {
        trace_io_err(&tmp_path, &error, &format!("{label} lock failed"));
        BackendError::new(format!("{label} lock failed: {error}"))
    })?;
    file.write_all(bytes).map_err(|error| {
        trace_io_err(&tmp_path, &error, &format!("{label} write failed"));
        BackendError::new(format!(
            "failed to write {label} {}: {error}.",
            path_fingerprint(&tmp_path)
        ))
    })?;
    file.sync_all().map_err(|error| {
        trace_io_err(&tmp_path, &error, &format!("{label} fsync failed"));
        BackendError::new(format!("{label} fsync failed: {error}"))
    })?;
    file.unlock().map_err(|error| {
        trace_io_err(&tmp_path, &error, &format!("{label} unlock failed"));
        BackendError::new(format!("{label} unlock failed: {error}"))
    })?;
    fs::rename(&tmp_path, path).map_err(|error| {
        trace_io_err(path, &error, "pipeline cache file install failed");
        BackendError::new(format!(
            "failed to install {label} {}: {error}. Fix: ensure ~/.cache/vyre/pipeline is writable.",
            path_fingerprint(path)
        ))
    })
}

fn read_metadata<T: serde::de::DeserializeOwned>(meta_path: &Path) -> Result<T, ()> {
    let Ok(mut file) = File::open(meta_path) else {
        return Err(());
    };
    let Ok(metadata) = file.metadata() else {
        return Err(());
    };
    if metadata.len() > MAX_PIPELINE_CACHE_METADATA_BYTES {
        return Err(());
    }
    if file.lock_shared().is_err() {
        return Err(());
    }
    let mut text = String::new();
    let res = file.read_to_string(&mut text);
    if let Err(error) = file.unlock() {
        tracing::warn!(
            error_kind = ?error.kind(),
            "pipeline cache metadata unlock failed"
        );
        return Err(());
    }
    if res.is_err() {
        return Err(());
    }
    toml::from_str::<T>(&text).map_err(|_| ())
}

fn read_bounded_utf8(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    let bytes = read_bounded_bytes(path, max_bytes)?;
    String::from_utf8(bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

fn read_bounded_bytes(path: &Path, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("cache entry exceeds {max_bytes} byte limit"),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// VYRE_NAGA_LOWER MEDIUM (pipeline_disk_cache.rs:346): the
/// previous `normalized_compile_wire` cloned every `BufferDecl`,
/// rebuilt a `Program`, then serialized the whole thing to wire
/// bytes. We still need the runtime-count-insensitive property
/// (two programs with the same body but different storage counts
/// must share a cache entry), but we do it by reusing a single
/// thread-local scratch `Vec<u8>` instead of allocating per call
/// and computing the digest inline. The compile side of the hot
/// path allocates O(1) amortized.
fn normalized_cache_digest(program: &Program) -> [u8; 32] {
    thread_local! {
        static SCRATCH: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(Vec::with_capacity(1024));
    }
    SCRATCH.with(|cell| {
        let mut scratch = cell.borrow_mut();
        scratch.clear();
        // v2: buffer elements + entry use VIR0 encoders, not `Debug` text
        // (Debug formatting is not a stable content-addressing contract).
        scratch.extend_from_slice(b"vyre-pipeline-cache-norm-v2\0wg\0");
        for axis in program.workgroup_size() {
            scratch.extend_from_slice(&axis.to_le_bytes());
        }
        scratch.extend_from_slice(b"\0op\0");
        match program.entry_op_id() {
            Some(op) => scratch.extend_from_slice(op.as_bytes()),
            None => scratch.extend_from_slice(b"<anon>"),
        }
        scratch.extend_from_slice(b"\0v\0");
        scratch.push(u8::from(program.is_structurally_validated()));
        scratch.extend_from_slice(b"\0bufs\0");
        for buffer in program.buffers().iter() {
            // Count-insensitive: name + kind + access + element, no
            // count or output_byte_range.
            scratch.extend_from_slice(buffer.name().as_bytes());
            scratch.push(0);
            scratch.push(buffer.kind() as u8);
            scratch.push(buffer.access() as u8);
            let elem = buffer.element();
            append_data_type_fingerprint(&mut scratch, &elem)
                .expect("Fix: buffer element type must be VIR0-encodable for pipeline cache key.");
            scratch.push(0);
        }
        scratch.extend_from_slice(b"\0body\0");
        append_node_list_fingerprint(&mut scratch, program.entry())
            .expect("Fix: program entry must be VIR0-encodable for pipeline cache key.");
        *blake3::hash(&scratch).as_bytes()
    })
}

fn wgsl_cache_key(norm_digest: &[u8], fingerprint: &str, config: &DispatchConfig) -> String {
    let mut hasher = blake3::Hasher::new();
    // Bumped to v5 to invalidate any v4 blobs on disk: the input
    // to `wire` used to be raw wire bytes; it is now a 32-byte
    // blake3 digest computed by `normalized_cache_digest`. Keeping
    // the v4 tag would let stale entries collide.
    hasher.update(b"vyre-pipeline-cache-v6\0norm\0");
    hasher.update(norm_digest);
    hasher.update(b"\0adapter\0");
    hasher.update(fingerprint.as_bytes());
    hasher.update(b"\0abi\0");
    hasher.update(&WIRE_FORMAT_VERSION.to_le_bytes());
    hasher.update(b"\0naga\0");
    hasher.update(NAGA_VERSION.as_bytes());
    hasher.update(b"\0policy\0");
    hasher.update(config_cache_policy(config).as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn lower_wgsl(
    program: &Program,
    config: &DispatchConfig,
    enabled_features: &crate::runtime::device::EnabledFeatures,
) -> Result<String, BackendError> {
    crate::lowering::lower_with_features(program, config, enabled_features).map_err(|error| {
        BackendError::new(format!(
            "failed to lower vyre IR to WGSL: {error}. Fix: provide a valid Program accepted by the WGSL lowering pipeline."
        ))
    })
}

fn adapter_fingerprint(adapter_info: &wgpu::AdapterInfo) -> String {
    format!(
        "{:?}:{:08x}:{:08x}:{}:{}",
        adapter_info.backend,
        adapter_info.vendor,
        adapter_info.device,
        adapter_info.driver,
        adapter_info.driver_info
    )
}

fn config_cache_policy(config: &DispatchConfig) -> String {
    format!(
        "ulp={:?}:wg={:?}",
        config.ulp_budget, config.workgroup_override
    )
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn path_fingerprint(path: &Path) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"vyre-pipeline-cache-path-v1\0");
    hasher.update(path.as_os_str().as_encoded_bytes());
    let hex = hasher.finalize().to_hex().to_string();
    format!("cache-path:{}", &hex[..16])
}

fn hex_hash(bytes: &[u8; 32]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            let _ = write!(&mut hex, "{byte:02x}");
            hex
        })
}

fn disk_pipeline_cache_dir() -> PathBuf {
    std::env::var_os("VYRE_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".cache")
                .join("vyre")
        })
        .join("pipeline")
}

#[derive(serde::Deserialize, serde::Serialize)]
struct DiskPipelineMetadata {
    version: u32,
    cache_key: String,
    wgsl_bytes: usize,
    adapter_fingerprint: String,
    program_abi_version: u32,
    naga_version: String,
    policy: String,
    wgsl_blake3: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct CompiledPipelineMetadata {
    version: u32,
    cache_key: String,
    adapter_fingerprint: String,
    wgsl_blake3: String,
    program_abi_version: u32,
    naga_version: String,
    blob_bytes: usize,
    blob_blake3: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn kill_switch_recognises_common_falsey_spellings() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        // Table-driven: every variant should disable the cache so a fresh
        // compile path runs even with cached entries on disk.
        for value in ["off", "OFF", "Off", "0", "false", "FALSE", "False"] {
            std::env::set_var("VYRE_PIPELINE_CACHE", value);
            assert!(
                cache_disabled(),
                "expected VYRE_PIPELINE_CACHE={value} to disable the cache"
            );
        }
        // Anything else (including the empty string) should leave the cache on.
        for value in ["on", "1", "true", "", "yes"] {
            std::env::set_var("VYRE_PIPELINE_CACHE", value);
            assert!(
                !cache_disabled(),
                "expected VYRE_PIPELINE_CACHE={value} to leave the cache enabled"
            );
        }
        std::env::remove_var("VYRE_PIPELINE_CACHE");
        assert!(!cache_disabled(), "unset env var must leave cache enabled");
    }

    #[test]
    fn cache_key_isolates_wire_from_adapter() {
        // Two different (wire, fingerprint) pairs whose concatenation would
        // collide under a naïve concat hash must still produce different
        // cache keys because the domain separators intervene.
        let cfg = DispatchConfig::default();
        let k1 = wgsl_cache_key(b"ab", "cd", &cfg);
        let k2 = wgsl_cache_key(b"a", "bcd", &cfg);
        assert_ne!(
            k1, k2,
            "wire/adapter boundaries must not collapse into a single blob"
        );

        // Same (wire, fingerprint) pair must be deterministic across calls.
        let k3 = wgsl_cache_key(b"ab", "cd", &cfg);
        assert_eq!(k1, k3);
    }

    #[test]
    fn adapter_change_invalidates_cache_match() {
        // Given the same wire, a different adapter fingerprint must miss.
        let wire = b"some-wire-bytes".as_slice();
        let cfg = DispatchConfig::default();
        let k_a = wgsl_cache_key(wire, "adapter-alpha", &cfg);
        let k_b = wgsl_cache_key(wire, "adapter-beta", &cfg);
        assert_ne!(k_a, k_b);
    }

    #[test]
    fn content_digest_rejects_corrupted_payload() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let meta_path = dir.path().join("meta.toml");

        let wgsl = "genuine shader content";

        let metadata = DiskPipelineMetadata {
            version: DISK_PIPELINE_CACHE_VERSION,
            cache_key: "key123".to_string(),
            wgsl_bytes: wgsl.len(),
            adapter_fingerprint: "fingerprint".to_string(),
            program_abi_version: u32::from(WIRE_FORMAT_VERSION),
            naga_version: NAGA_VERSION.to_string(),
            policy: config_cache_policy(&DispatchConfig::default()),
            wgsl_blake3: blake3_hex(wgsl.as_bytes()),
        };
        let mut file = std::fs::File::create(&meta_path).unwrap();
        file.write_all(toml::to_string(&metadata).unwrap().as_bytes())
            .unwrap();

        // Exact match -> true
        assert!(wgsl_metadata_matches(
            &meta_path,
            "key123",
            wgsl,
            "fingerprint",
            &DispatchConfig::default()
        ));

        // Match length, but corrupted bytes -> false
        let corrupted_wgsl = "genuine shader corpent";
        assert_eq!(corrupted_wgsl.len(), wgsl.len());
        assert!(!wgsl_metadata_matches(
            &meta_path,
            "key123",
            corrupted_wgsl,
            "fingerprint",
            &DispatchConfig::default()
        ));
    }

    #[test]
    fn normalized_cache_digest_erases_runtime_storage_lengths() {
        let entry = vec![vyre_foundation::ir::Node::return_()];
        let a = Program::wrapped(
            vec![
                vyre_foundation::ir::BufferDecl::read(
                    "haystack",
                    0,
                    vyre_foundation::ir::DataType::U32,
                )
                .with_count(8),
                vyre_foundation::ir::BufferDecl::output(
                    "matches",
                    1,
                    vyre_foundation::ir::DataType::U32,
                )
                .with_count(8)
                .with_output_byte_range(0..32),
            ],
            [64, 1, 1],
            entry.clone(),
        );
        let b = Program::wrapped(
            vec![
                vyre_foundation::ir::BufferDecl::read(
                    "haystack",
                    0,
                    vyre_foundation::ir::DataType::U32,
                )
                .with_count(1024),
                vyre_foundation::ir::BufferDecl::output(
                    "matches",
                    1,
                    vyre_foundation::ir::DataType::U32,
                )
                .with_count(1024)
                .with_output_byte_range(0..4096),
            ],
            [64, 1, 1],
            entry,
        );

        assert_eq!(
            normalized_cache_digest(&a),
            normalized_cache_digest(&b),
            "storage buffer lengths must not perturb the compile fingerprint"
        );
    }

    #[test]
    fn cache_misses_are_traced_on_fresh_temp_dir() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();

        #[derive(Clone)]
        struct StringWriter(Arc<std::sync::Mutex<String>>);
        impl std::io::Write for StringWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if let Ok(mut s) = self.0.lock() {
                    s.push_str(std::str::from_utf8(buf).unwrap_or_default());
                }
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let captured = Arc::new(std::sync::Mutex::new(String::new()));
        let writer = StringWriter(captured.clone());
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_level(true)
            .with_target(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let dir = tempfile::tempdir().unwrap();
        let old_cache_dir = std::env::var_os("VYRE_CACHE_DIR");
        let old_kill = std::env::var_os("VYRE_PIPELINE_CACHE");
        std::env::set_var("VYRE_CACHE_DIR", dir.path());
        std::env::remove_var("VYRE_PIPELINE_CACHE");

        let adapter_info = wgpu::AdapterInfo {
            name: "test-adapter".to_string(),
            vendor: 0x1234,
            device: 0x5678,
            device_type: wgpu::DeviceType::Other,
            driver: "test-driver".to_string(),
            driver_info: "1.0".to_string(),
            backend: wgpu::Backend::Empty,
        };

        let program = Program::wrapped(
            vec![vyre_foundation::ir::BufferDecl::output(
                "out",
                0,
                vyre_foundation::ir::DataType::U32,
            )
            .with_count(1)],
            [1, 1, 1],
            vec![vyre_foundation::ir::Node::store(
                "out",
                vyre_foundation::ir::Expr::u32(0),
                vyre_foundation::ir::Expr::u32(42),
            )],
        );

        let enabled_features = crate::runtime::device::EnabledFeatures::default();
        let wgsl = load_or_compile_disk_wgsl(
            &program,
            &adapter_info,
            &DispatchConfig::default(),
            &enabled_features,
        )
        .expect("lowering must succeed on a trivial program");
        let key = compiled_pipeline_cache_key(&adapter_info, &wgsl);
        let blob = load_compiled_pipeline_blob(&key).expect("blob load must not error");
        assert!(
            blob.is_none(),
            "fresh temp dir must miss compiled pipeline cache"
        );

        let logs = captured.lock().unwrap();
        assert!(
            logs.contains("WGSL cache miss"),
            "expected WGSL cache miss info log, got:\n{logs}"
        );
        assert!(
            logs.contains("compiled-pipeline cache miss"),
            "expected compiled-pipeline cache miss warn log, got:\n{logs}"
        );

        // Restore env
        if let Some(val) = old_cache_dir {
            std::env::set_var("VYRE_CACHE_DIR", val);
        } else {
            std::env::remove_var("VYRE_CACHE_DIR");
        }
        if let Some(val) = old_kill {
            std::env::set_var("VYRE_PIPELINE_CACHE", val);
        } else {
            std::env::remove_var("VYRE_PIPELINE_CACHE");
        }
    }
}
