//! MegaScan `RulePipeline` compile + on-disk cache.

/// Compile a `RulePipeline` (vyre's regex multimatch path) for the
/// given detector regex sources, sized for `input_len` bytes. Uses
/// vyre's `regex_compile::build_rule_pipeline_from_regex` so each
/// pattern is parsed via `regex_syntax` (with `unicode(false)` /
/// `utf8(false)` — ASCII byte automaton) and lowered to the same
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
/// unsupported regex syntax) — the caller is expected to log + fall
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
                        "RulePipeline cache hit — skipped compile"
                    );
                    return Ok(pipeline);
                }
                Err(_) => {
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
                let _ = std::fs::create_dir_all(parent);
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
        "RulePipeline cache miss — compiled and saved"
    );
    Ok(pipeline)
}

/// Maximum input buffer length the MegaScan `RulePipeline` is
/// pre-compiled for. Chosen to match the orchestrator's
/// `BATCH_BYTES_BUDGET` (256 MiB) so any normal coalesced batch fits
/// the pre-built pipeline without needing recompile-per-batch.
/// Batches larger than this fall back to the literal-set path.
pub const MEGASCAN_INPUT_LEN: usize = 256 * 1024 * 1024;

/// Output buffer cap for the AC GPU kernel, per shard dispatch.
pub const AC_GPU_MAX_MATCHES_PER_DISPATCH: u32 = 1_000_000;
