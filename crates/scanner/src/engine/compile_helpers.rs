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

/// Resolve every hot-pattern slot into a single `Vec<HotPatternSlot>`: the one
/// runtime table the SIMD fast path indexes by `pattern_idx`.
///
/// Prefix ownership comes directly from each loaded detector's
/// `simdsieve_prefixes`. Construction fails closed if the backend's 16-prefix
/// capacity is exceeded, ownership is duplicated, or a declaration is not
/// backed by one of that detector's compiled literal prefixes. Each surviving
/// row therefore carries its prefix, exact validator, and canonical `ac_map`
/// delegate together; no parallel table or missing-slot fallback exists.
#[cfg(feature = "simdsieve")]
pub(super) fn build_hot_pattern_slots(
    detectors: &[DetectorSpec],
    ac_map: &[CompiledPattern],
) -> Result<Vec<crate::simdsieve_prefilter::HotPatternSlot>> {
    use crate::simdsieve_prefilter::{build_hot_pattern_validator, HotPatternSlot};
    let total = detectors
        .iter()
        .map(|d| d.simdsieve_prefixes.len())
        .sum::<usize>();
    if total > 16 {
        return Err(crate::error::ScanError::Config(format!(
            "loaded detector corpus declares {total} simdsieve prefixes, but simdsieve supports at most 16; remove lower-value prefixes or extend the backend"
        )));
    }
    let mut seen = std::collections::HashSet::with_capacity(total);
    let mut slots = Vec::with_capacity(total);
    for detector in detectors {
        if detector.simdsieve_prefixes.is_empty() {
            continue;
        }
        let validator = build_hot_pattern_validator(detector)?;
        for prefix in &detector.simdsieve_prefixes {
            if !seen.insert(prefix.as_str()) {
                return Err(crate::error::ScanError::Config(format!(
                    "simdsieve prefix {prefix:?} is declared by more than one loaded detector"
                )));
            }
            let ac_map_index = ac_map.iter().position(|entry| {
                detectors
                    .get(entry.detector_index)
                    .is_some_and(|candidate| candidate.id == detector.id)
                    && crate::compiler::compiler_prefix::extract_literal_prefixes(
                        entry.regex.as_str(),
                    )
                    .iter()
                    .any(|literal| literal == prefix)
            }).ok_or_else(|| crate::error::ScanError::Config(format!(
                "detector {} declares simdsieve prefix {prefix:?}, but none of its compiled patterns exposes that literal prefix",
                detector.id
            )))?;
            slots.push(HotPatternSlot {
                prefix: prefix.as_bytes().into(),
                validator: validator.clone(),
                ac_map_index,
            });
        }
    }
    Ok(slots)
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
