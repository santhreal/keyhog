use crate::error::Result;
use crate::types::CompiledPattern;
use keyhog_core::DetectorSpec;

pub(super) fn validate_compiled_pattern_detector_indices(
    ac_map: &[CompiledPattern],
    phase2_patterns: &[(CompiledPattern, Vec<String>)],
    detectors_len: usize,
) -> Result<()> {
    for (pattern_index, pattern) in ac_map.iter().enumerate() {
        validate_compiled_pattern_detector_index("ac_map", pattern_index, pattern, detectors_len)?;
    }
    for (pattern_index, (pattern, _keywords)) in phase2_patterns.iter().enumerate() {
        validate_compiled_pattern_detector_index(
            "phase2_patterns",
            pattern_index,
            pattern,
            detectors_len,
        )?;
    }
    Ok(())
}

fn validate_compiled_pattern_detector_index(
    table: &str,
    pattern_index: usize,
    pattern: &CompiledPattern,
    detectors_len: usize,
) -> Result<()> {
    if pattern.detector_index >= detectors_len {
        return Err(crate::error::ScanError::Config(format!(
            "compiled scanner invariant violation: {table}[{pattern_index}] references \
             detector_index {} but only {detectors_len} detector(s) are loaded. \
             Fix: rebuild detector compilation so every compiled pattern keeps its source \
             detector index before scanner construction completes",
            pattern.detector_index
        )));
    }
    Ok(())
}

/// Resolve every hot-pattern slot into a single `Vec<HotPatternSlot>` — the one
/// runtime table the SIMD fast path indexes by `pattern_idx`.
///
/// Each slot's precise validator and its canonical `ac_map` delegate are built
/// by two focused helpers (`build_hot_pattern_validators` over the detector
/// regexes, `build_hot_ac_map_index_by_index` over the compiled AC prefixes),
/// then zipped into one row per slot. Both helpers project
/// `HOT_PATTERN_DETECTOR_IDS`, so both must equal `HOT_PATTERNS.len()`; we assert
/// that BEFORE the zip so a future divergence fails the scanner build loud
/// instead of `zip()` silently truncating to the shorter table (Law 10). After
/// the zip the two columns live in one row and can never drift again.
///
/// A slot is ACTIVE iff a compiled `ac_map` entry backs its hot literal. The
/// validator builder keys on detector-id-loaded and shares one combined
/// validator across every slot of a given detector, so a partial detector set
/// (e.g. an id reused from the embedded corpus but defining only a subset of its
/// hot prefixes) would otherwise leave a validator present on an unbacked slot.
/// We gate the validator on `ac_map_index` so both columns populate and empty
/// together: an unbacked slot resolves NEITHER and is simply skipped by the hot
/// path (recall-safe — the confirmed AC scan still covers it). This keeps the
/// unified-row invariant (`validator.is_some() == ac_map_index.is_some()`) true
/// for every detector set, not just the full corpus.
#[cfg(feature = "simdsieve")]
pub(super) fn build_hot_pattern_slots(
    detectors: &[DetectorSpec],
    ac_map: &[CompiledPattern],
) -> Result<Vec<crate::simdsieve_prefilter::HotPatternSlot>> {
    use crate::simdsieve_prefilter::{
        build_hot_pattern_validators, validate_hot_pattern_runtime_table_lengths, HotPatternSlot,
    };

    let validators = build_hot_pattern_validators(detectors)?;
    let ac_map_indices = build_hot_ac_map_index_by_index(detectors, ac_map);
    validate_hot_pattern_runtime_table_lengths(validators.len(), ac_map_indices.len())?;

    Ok(validators
        .into_iter()
        .zip(ac_map_indices)
        .map(|(validator, ac_map_index)| HotPatternSlot {
            // Lockstep: drop the validator on any slot no ac_map entry backs, so
            // an unbacked slot is (None, None) — never validator-without-delegate.
            validator: ac_map_index.and(validator),
            ac_map_index,
        })
        .collect())
}

/// Resolve, for each hot-pattern slot, the `ac_map` entry that backs it — or
/// `None` when no loaded detector exposes that slot's literal prefix.
///
/// A `None` slot is INACTIVE: the SIMD hot fast-path skips it
/// (`hot_patterns.rs` `continue`s when `ac_map_index` is `None`). That is
/// recall-safe because the hot path is a pure accelerator over the confirmed AC
/// scan, which is always active and independently triggers + extracts every
/// `ac_map` literal (`collect_triggered_patterns_*` -> `extract_confirmed_patterns`);
/// the stripe direct-prefix dedup only suppresses offsets the hot path ACTUALLY
/// emitted, so a deactivated slot just routes its credential through the confirmed
/// path instead. Compiling a custom or partial detector set that reuses a
/// production detector id but omits one of its hot prefixes therefore degrades
/// that slot gracefully rather than failing construction (the hot table is an
/// internal optimization and must not leak into a hard error for caller-supplied
/// detectors).
///
/// A DORMANT slot in the SHIPPED corpus (a `HOT_PATTERNS` entry that no embedded
/// detector backs) is still a bug — but it is caught loudly at the right scope by
/// `hot_pattern_table_fully_backed_by_embedded_corpus`, which compiles the real
/// embedded detector set and asserts every slot is backed. The table is authored
/// against the embedded corpus, not against arbitrary caller detectors, so that
/// is where the no-dormant-slot invariant belongs.
#[cfg(feature = "simdsieve")]
fn build_hot_ac_map_index_by_index(
    detectors: &[DetectorSpec],
    ac_map: &[CompiledPattern],
) -> Vec<Option<usize>> {
    use crate::simdsieve_prefilter::{HOT_PATTERNS, HOT_PATTERN_DETECTOR_IDS};

    HOT_PATTERN_DETECTOR_IDS
        .iter()
        .enumerate()
        .map(|(slot, detector_id)| {
            let hot_literal = std::str::from_utf8(HOT_PATTERNS[slot])
                .expect("static simdsieve hot-pattern literal must be valid UTF-8");
            ac_map.iter().position(|entry| {
                detectors
                    .get(entry.detector_index)
                    .is_some_and(|detector| detector.id == *detector_id)
                    && crate::compiler::compiler_prefix::extract_literal_prefixes(
                        entry.regex.as_str(),
                    )
                    .iter()
                    .any(|prefix| prefix.as_str() == hot_literal)
            })
        })
        .collect()
}

/// One-shot guard so the CUDA-acquisition-failed warning fires
/// exactly once per process, not on every recompile. The CUDA factory
/// is called inside `compile()` and a binary that re-compiles a
/// scanner per-job (daemon mode, watch mode) would otherwise spam.
#[cfg(all(target_os = "linux", feature = "gpu"))]
static CUDA_FALLBACK_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

/// Surface a CUDA-backend acquisition failure when the host looks
/// like it should have a working CUDA stack. We don't want to warn
/// on plain non-NVIDIA Linux (the wgpu fall-through is the right
/// path); we DO want to warn when the user is on an NVIDIA box with
/// libcuda.so or /proc/driver/nvidia present, because in that case
/// they paid for the CUDA stack and we just dropped them onto the
/// 5-10x slower wgpu path silently. `--require-gpu` turns the warning into a
/// hard exit, matching the contract used by the MoE init and the scan dispatch
/// paths.
#[cfg(all(target_os = "linux", feature = "gpu"))]
pub(super) fn surface_cuda_acquisition_failure(error: &dyn std::fmt::Display) {
    let on_nvidia_host = nvidia_userland_present();
    let require_gpu = crate::gpu::gpu_required_by_policy();
    let no_gpu = crate::gpu::gpu_disabled_by_policy();

    if require_gpu && on_nvidia_host {
        crate::process_exit::require_gpu_unmet(format!(
            "--require-gpu requested but CUDA backend acquisition failed on \
an NVIDIA host: {error}. Refusing to fall back to WGPU."
        ));
    }

    if no_gpu {
        return;
    }

    if on_nvidia_host && CUDA_FALLBACK_WARNED.set(()).is_ok() {
        eprintln!(
            "keyhog: CUDA backend unavailable on this NVIDIA host ({error}); \
falling back to WGPU (typically 5-10x slower than CUDA on the same hardware). \
This is usually a libcuda.so version mismatch or a driver upgrade pending a \
reboot. Use --no-gpu to silence this warning, or --require-gpu \
to hard-fail next time."
        );
    }
    tracing::warn!("CUDA backend unavailable, falling back to wgpu: {error}");
}

/// Check the common libcuda.so locations + /proc/driver/nvidia to
/// decide whether this host appears to have an NVIDIA CUDA userland
/// installed. Mirrors the probes install.sh uses so the runtime view
/// matches the install-time view.
#[cfg(all(target_os = "linux", feature = "gpu"))]
fn nvidia_userland_present() -> bool {
    if std::path::Path::new("/proc/driver/nvidia").exists() {
        return true;
    }
    for p in [
        "/usr/lib/x86_64-linux-gnu/libcuda.so",
        "/usr/lib/x86_64-linux-gnu/libcuda.so.1",
        "/usr/lib64/libcuda.so",
        "/usr/lib64/libcuda.so.1",
        "/usr/local/cuda/lib64/libcuda.so",
        "/opt/cuda/lib64/libcuda.so",
    ] {
        if std::path::Path::new(p).exists() {
            return true;
        }
    }
    false
}
