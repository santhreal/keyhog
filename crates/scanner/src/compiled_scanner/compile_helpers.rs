#[cfg(feature = "simdsieve")]
use crate::error::Result;
#[cfg(any(feature = "simdsieve", test))]
use crate::types::CompiledPattern;
#[cfg(feature = "simdsieve")]
use keyhog_core::DetectorSpec;

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

/// One-shot guard so the CUDA acquisition warning fires once per process.
#[cfg(all(target_os = "linux", feature = "gpu"))]
static CUDA_FALLBACK_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

/// Surface a CUDA peer acquisition failure on a host that advertises NVIDIA
/// userland. The failure is also retained in scanner runtime status. WGPU is a
/// separate peer candidate, not a substitute selected by this function.
#[cfg(all(target_os = "linux", feature = "gpu"))]
pub(super) fn surface_cuda_acquisition_failure(error: &dyn std::fmt::Display) {
    let on_nvidia_host = nvidia_userland_present();
    let no_gpu = crate::gpu::gpu_disabled_by_policy();

    if no_gpu {
        return;
    }

    if on_nvidia_host && CUDA_FALLBACK_WARNED.set(()).is_ok() {
        eprintln!(
            "keyhog: CUDA backend unavailable on this NVIDIA host ({error}); \
the CUDA peer is ineligible until its driver/runtime is repaired. WGPU remains \
a separate candidate and will only run when explicitly selected or proven by \
autoroute calibration."
        );
    }
    tracing::warn!("CUDA peer backend acquisition failed: {error}");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::validate_compiled_pattern_detector_indices;
    use crate::types::LazyRegex;

    fn compiled_pattern(detector_index: usize) -> CompiledPattern {
        CompiledPattern {
            detector_index,
            regex: LazyRegex::plain("secret_[A-Za-z0-9]{16}"),
            group: None,
            client_safe: false,
            match_proves_keyword_nearby: false,
            homoglyph_variant: false,
        }
    }

    #[test]
    fn invalid_detector_indices_fail_before_scanner_construction() {
        let ac_error = validate_compiled_pattern_detector_indices(&[compiled_pattern(2)], &[], 1)
            .expect_err("an AC pattern cannot name an absent detector")
            .to_string();
        assert_eq!(
            ac_error,
            "compiled scanner invariant violation: ac_map[0] references detector_index 2 but only 1 detector(s) are loaded. Fix: rebuild detector compilation so every compiled pattern keeps its source detector index before scanner construction completes"
        );

        let phase2_error = validate_compiled_pattern_detector_indices(
            &[],
            &[(compiled_pattern(4), vec!["secret".to_string()])],
            3,
        )
        .expect_err("a phase-2 pattern cannot name an absent detector")
        .to_string();
        assert_eq!(
            phase2_error,
            "compiled scanner invariant violation: phase2_patterns[0] references detector_index 4 but only 3 detector(s) are loaded. Fix: rebuild detector compilation so every compiled pattern keeps its source detector index before scanner construction completes"
        );
    }
}
