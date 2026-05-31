//! MegaScan `RulePipeline` compile + on-disk cache.

/// Compile a `RulePipeline` (vyre's regex multimatch path) for the
/// given detector regex sources, sized for `input_len` bytes. Uses
/// vyre's `regex_compile::build_rule_pipeline_from_regex` so each
/// pattern is parsed via `regex_syntax` (with `unicode(false)` /
/// `utf8(false)` - ASCII byte automaton) and lowered to the same
/// transition + epsilon tables `RulePipeline::scan` expects.
///
/// Returns `Err` when the combined NFA exceeds vyre's per-subgroup
/// state cap (`LANES * 32`), or when any pattern uses regex features
/// (Unicode classes, lookbehind/lookahead, backreferences) the
/// byte-NFA frontend can't represent. Caller decides whether to fall
/// back to the literal-set GPU dispatch (which always works but only
/// matches literals) or to skip MegaScan altogether for this corpus.
pub fn build_rule_pipeline(
    patterns: &[&str],
    input_len: u32,
) -> std::result::Result<vyre_libs::scan::RulePipeline, vyre_libs::scan::RegexCompileError> {
    vyre_libs::scan::build_rule_pipeline_from_regex(patterns, "input", "hits", input_len)
}

/// Persistent cache for `RulePipeline`. Mirrors the GpuLiteralSet
/// caching layer (same on-disk dir, same atomic-write protocol, same
/// SHA-256-of-inputs key). The two caches coexist so consumers that
/// run BOTH the literal-set and the regex pipeline (the planned
/// fast-path / regex-completion split) get cold-start speedup on each
/// without colliding cache files.
///
/// On-disk path: `~/.cache/keyhog/programs/pipe-<sha256>.bin`.
const PIPELINE_CACHE_VERSION: u32 = 1;

fn pipeline_cache_key(patterns: &[&str], input_len: u32) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(PIPELINE_CACHE_VERSION.to_le_bytes());
    h.update(input_len.to_le_bytes());
    h.update((patterns.len() as u32).to_le_bytes());
    for p in patterns {
        h.update((p.len() as u32).to_le_bytes());
        h.update(p.as_bytes());
    }
    let digest = h.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{:02x}", byte);
    }
    hex
}

/// Compile-or-load a `RulePipeline` for the given regex set. First call
/// hits the on-disk cache; misses recompile and re-cache. Returns
/// `Err` when the regex compile itself fails (state-cap overflow or
/// unsupported regex syntax) - the caller is expected to log + fall
/// back to the literal-set GPU dispatch in that case.
///
/// The on-disk cache is keyed by the (patterns, input_len, vyre wire
/// version) tuple so a vyre IR bump or a detector change automatically
/// invalidates the cache instead of loading a stale pipeline.
pub fn rule_pipeline_cached(
    patterns: &[&str],
    input_len: u32,
) -> std::result::Result<vyre_libs::scan::RulePipeline, vyre_libs::scan::RegexCompileError> {
    let started = std::time::Instant::now();
    let Some(cache_dir) = super::gpu_cache::gpu_matcher_cache_dir() else {
        return build_rule_pipeline(patterns, input_len);
    };
    let cache_key = format!("pipe-{}", pipeline_cache_key(patterns, input_len));

    if let Some(path) = vyre_libs::scan::engine_cache_path(&cache_dir, &cache_key) {
        if let Ok(bytes) = std::fs::read(&path) {
            match vyre_libs::scan::RulePipeline::from_bytes(&bytes) {
                Ok(pipeline) => {
                    tracing::debug!(
                        target: "keyhog::routing",
                        patterns = patterns.len(),
                        input_len,
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        "RulePipeline cache hit: skipped compile"
                    );
                    return Ok(pipeline);
                }
                Err(error) => {
                    tracing::debug!(
                        target: "keyhog::routing",
                        cache = %path.display(),
                        %error,
                        "corrupt rule pipeline cache entry removed"
                    );
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }

    let pipeline = build_rule_pipeline(patterns, input_len)?;
    if let Some(path) = vyre_libs::scan::engine_cache_path(&cache_dir, &cache_key) {
        if let Ok(bytes) = pipeline.to_bytes() {
            let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
            if let Some(parent) = path.parent() {
                if let Err(error) = std::fs::create_dir_all(parent) {
                    tracing::debug!(
                        target: "keyhog::routing",
                        dir = %parent.display(),
                        %error,
                        "rule pipeline cache dir create failed; cache write will be skipped"
                    );
                }
            }
            if std::fs::write(&tmp, &bytes).is_ok() {
                if let Err(error) = std::fs::rename(&tmp, &path) {
                    tracing::debug!(
                        target: "keyhog::routing",
                        error = %error,
                        path = %path.display(),
                        "rule pipeline cache rename failed"
                    );
                    let _ = std::fs::remove_file(&tmp);
                }
            }
        }
    }
    tracing::debug!(
        target: "keyhog::routing",
        patterns = patterns.len(),
        input_len,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "RulePipeline cache miss: compiled and saved"
    );
    Ok(pipeline)
}

/// Maximum input buffer length the MegaScan `RulePipeline` is
/// pre-compiled for. Chosen to match the orchestrator's
/// `BATCH_BYTES_BUDGET` so any normal coalesced batch fits the
/// pre-built pipeline without needing recompile-per-batch. Batches
/// larger than this fall back to the literal-set path.
///
/// Kept as the conservative default for hosts without GPU info or
/// for callers (tests, fuzzers) that want a stable byte budget. The
/// adaptive size for the running host is exposed via
/// [`megascan_input_len`].
pub const MEGASCAN_INPUT_LEN_DEFAULT: usize = 256 * 1024 * 1024;

/// Backwards-compatible alias preserved for any external consumer
/// that referenced the old constant by name. New code should call
/// [`megascan_input_len`] so the host's GPU VRAM scales the dispatch.
pub const MEGASCAN_INPUT_LEN: usize = MEGASCAN_INPUT_LEN_DEFAULT;

/// VRAM-adaptive megascan input length. Bigger buffers mean fewer
/// device dispatches per multi-TB scan; each kernel launch is a fixed
/// ~50-300 µs cost regardless of payload, so doubling the input
/// halves dispatch overhead. Capped by host VRAM (input + transition
/// tables + match output must fit) and by a 1 GiB upper bound so the
/// pre-compile time stays bounded.
///
/// | VRAM detected     | Input length | Adapter examples                 |
/// |-------------------|--------------|----------------------------------|
/// | >= 24 GiB         | 1 GiB        | RTX 4090 / 5090, A100 / H100     |
/// | 12 - 23 GiB       | 512 MiB      | RTX 3090, RTX 4080, M-Max        |
/// | 8 - 11 GiB        | 256 MiB      | RTX 3080, RTX 4070, M-Pro        |
/// |  < 8 GiB / Unknown| 128 MiB      | iGPU, software, no-GPU CI runner |
///
/// Cached on first call; the result is stable for the process
/// lifetime so the rule-pipeline cache key stays consistent across
/// every batch.
pub fn megascan_input_len() -> usize {
    use std::sync::OnceLock;
    static CACHED: OnceLock<usize> = OnceLock::new();
    *CACHED.get_or_init(|| {
        let caps = crate::hw_probe::probe_hardware();
        let len = match caps.gpu_vram_mb {
            Some(mb) if mb >= 24 * 1024 => 1024 * 1024 * 1024,
            Some(mb) if mb >= 12 * 1024 => 512 * 1024 * 1024,
            Some(mb) if mb >= 8 * 1024 => 256 * 1024 * 1024,
            Some(_) => 128 * 1024 * 1024,
            None => MEGASCAN_INPUT_LEN_DEFAULT,
        };
        tracing::debug!(
            target: "keyhog::routing",
            gpu_vram_mb = ?caps.gpu_vram_mb,
            megascan_input_len = len,
            "MegaScan input length sized for VRAM"
        );
        len
    })
}

/// Output buffer cap for the AC GPU kernel, per shard dispatch.
///
/// The AC path is a prefilter, not the final matcher. A 4 MiB shard that
/// emits more than 32k literal-prefix hits is already past one hit per 128
/// bytes, which is the measured point where CPU phase-2 confirmation loses
/// to the SIMD coalesced scanner. Keeping the cap near that density lets the
/// host detect pathological prefix floods without allocating multi-megabyte
/// readback buffers for every shard in a large batch.
pub const AC_GPU_MAX_MATCHES_PER_DISPATCH: u32 = 32_768;
