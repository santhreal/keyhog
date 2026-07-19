use super::*;

#[test]
fn gpu_moe_score_validation_clamps_only_complete_finite_batches() {
    assert_eq!(
        checked_moe_scores(&[-0.25, 0.25, 1.25]),
        Ok(vec![0.0, 0.25, 1.0])
    );
}

#[test]
fn gpu_moe_score_validation_rejects_the_complete_batch_on_nonfinite_output() {
    assert_eq!(
        checked_moe_scores(&[0.9, f32::NAN, f32::INFINITY, f32::NEG_INFINITY]),
        Err(3)
    );
}

#[test]
fn gpu_moe_dispatch_matches_cpu_on_every_repeat() {
    // GPU/CPU parity guard: the GPU MoE compute shader must reproduce the CPU
    // MoE (`ml_scorer::score_features`, the reference every confidence floor is
    // tuned and benched against) on EVERY dispatch of a >=GPU_BATCH_THRESHOLD
    // batch, with no spurious 0.0 scores. This runs dispatches ONE AT A TIME,
    // so it isolates a genuinely broken shader/weights/driver from the
    // concurrent params-race regression below (which the autoroute-calibration
    // abort actually turned out to be) and proves the dispatch is stable across
    // many repeats.
    if super::super::gpu_disabled_by_policy() || get_gpu().is_none() {
        eprintln!("no usable GPU adapter; skipping GPU MoE dispatch regression");
        return;
    }
    let probe = gpu_moe_parity_probe_features();
    assert!(probe.len() >= GPU_BATCH_THRESHOLD);
    let cpu: Vec<f64> = probe.iter().map(crate::ml_scorer::score_features).collect();
    let timeout = Duration::from_millis(30_000);
    for rep in 0..128 {
        let gpu = dispatch_moe_batch(&probe, timeout)
            .unwrap_or_else(|| panic!("GPU MoE dispatch {rep} returned no result")); // LAW10: test-only proof panic, not a fallback; a missing dispatch result is the failure under test
        assert_eq!(
            gpu.len(),
            probe.len(),
            "dispatch {rep}: score count mismatch"
        );
        let zeroed = gpu
            .iter()
            .zip(cpu.iter())
            .filter(|(g, c)| **g == 0.0 && **c > 0.01)
            .count();
        let worst = gpu
            .iter()
            .zip(cpu.iter())
            .map(|(g, c)| (g - c).abs())
            .fold(0.0f64, f64::max);
        assert_eq!(
                zeroed, 0,
                "dispatch {rep}: {zeroed} candidate(s) read back 0.0 while the CPU MoE scores them >0.01 \
                 (the GPU MoE must never emit a spurious 0.0 for a real candidate)"
            );
        assert!(
                worst <= GPU_MOE_PARITY_TOLERANCE,
                "dispatch {rep}: GPU MoE diverged from CPU MoE by {worst:.6} (tolerance {GPU_MOE_PARITY_TOLERANCE})"
            );
    }
}

#[test]
fn gpu_moe_dispatch_is_race_free_under_concurrent_batches() {
    // Regression for the shared `GpuContext` params-buffer data race that aborted
    // `install.sh --calibrate` ("inconsistent calibration results"): per-chunk
    // ML scoring dispatches MoE batches concurrently (rayon par_iter in
    // scan_coalesced). A single shared uniform written by every dispatch let
    // one dispatch clobber another's batch_size, so the larger batch processed
    // too few candidates and its tail read back 0.0, dropping a
    // floor-straddling finding so the SIMD reference flipped between trials.
    // The diagnostic signature was unmistakable: on the demo a batch of 136
    // intermittently read back EXACTLY 64 zeros == 136 - 72, the other
    // concurrent batch size (NOT a coincidental workgroup multiple). Each
    // dispatch now owns its params buffer. Two distinct batch sizes are
    // dispatched from many threads in a tight loop; assert every concurrent
    // dispatch reproduces ITS OWN CPU reference with zero spurious zeros.
    if super::super::gpu_disabled_by_policy() || get_gpu().is_none() {
        eprintln!("no usable GPU adapter; skipping concurrent GPU MoE regression");
        return;
    }
    use std::sync::Arc;
    let small: Vec<[f32; INPUT_DIM]> = gpu_moe_parity_probe_features();
    let mut large = small.clone();
    large.extend(small.iter().copied()); // 2x threshold: a different batch size
    let cpu_small: Vec<f64> = small.iter().map(crate::ml_scorer::score_features).collect();
    let cpu_large: Vec<f64> = large.iter().map(crate::ml_scorer::score_features).collect();
    let small = Arc::new(small);
    let large = Arc::new(large);
    std::thread::scope(|scope| {
        for thread_idx in 0..16u32 {
            let small = Arc::clone(&small);
            let large = Arc::clone(&large);
            let cpu_small = &cpu_small;
            let cpu_large = &cpu_large;
            scope.spawn(move || {
                    let timeout = Duration::from_millis(30_000);
                    for _ in 0..8 {
                        let (feat, cpu): (&[[f32; INPUT_DIM]], &[f64]) = if thread_idx % 2 == 0 {
                            (&small, cpu_small)
                        } else {
                            (&large, cpu_large)
                        };
                        let gpu = dispatch_moe_batch(feat, timeout)
                            .expect("concurrent GPU MoE dispatch returned no result");
                        assert_eq!(gpu.len(), feat.len());
                        let zeroed = gpu
                            .iter()
                            .zip(cpu.iter())
                            .filter(|(g, c)| **g == 0.0 && **c > 0.01)
                            .count();
                        assert_eq!(
                            zeroed, 0,
                            "concurrent dispatch (batch={}) produced {zeroed} zeroed score(s): shared GPU params race",
                            feat.len()
                        );
                    }
                });
        }
    });
}

#[test]
fn gpu_moe_parity_probe_covers_dispatch_threshold_with_varied_features() {
    let features = gpu_moe_parity_probe_features();

    assert_eq!(
        features.len(),
        GPU_BATCH_THRESHOLD,
        "GPU MoE parity probe must exercise the production dispatch threshold"
    );
    assert!(
        features.iter().flatten().any(|value| *value > 0.0)
            && features.windows(2).any(|pair| pair[0] != pair[1]),
        "GPU MoE parity probe must include varied real feature vectors, not all-zero repeats"
    );
    let cpu_scores: Vec<f64> = features
        .iter()
        .map(crate::ml_scorer::score_features)
        .collect();
    assert!(
        cpu_scores.iter().copied().all(f64::is_finite),
        "CPU MoE scores for the GPU parity probe must be finite"
    );
    assert!(
        cpu_scores.windows(2).any(|pair| pair[0] != pair[1]),
        "GPU MoE parity probe must exercise distinct CPU MoE outputs"
    );
}

// ---- GPU-init-failure path (no real GPU required) --------------------------
//
// Regression for the reentrant-OnceLock deadlock: `get_gpu()`'s old `Err` arm
// called `probe_hardware().gpu_available`, which re-entered the `HW_PROBE`
// (and transitively `GPU`) OnceLock that was mid-init on that exact path,
// hanging the scan thread forever on any GPU-init failure. The failure
// decision is now a PURE function of the structured error + resolved policy,
// so it is driven here directly, off the GPU, and CANNOT hang.

#[test]
fn gpu_init_error_constructors_set_adapter_present() {
    // The `adapter_present` flag is the whole reason the reentrant probe is
    // gone: it carries "is a real GPU present?" in-band instead of asking the
    // initializing OnceLock. Pin both constructors' flag exactly.
    assert!(
        !GpuInitError::no_adapter("vyre WgpuBackend unavailable").adapter_present,
        "no_adapter must report NO adapter present (quiet CPU-only path)"
    );
    assert!(
        GpuInitError::adapter_unusable("max_storage_buffer_binding_size too small").adapter_present,
        "adapter_unusable must report a real adapter present (actionable notice)"
    );
}

#[test]
fn classify_gpu_init_failure_covers_full_policy_matrix() {
    use GpuInitFailureAction::{HardFail, Quiet, WarnCpuFallback};
    let present = GpuInitError::adapter_unusable("real adapter, MoE unusable");
    let absent = GpuInitError::no_adapter("no adapter");

    // --require-gpu ALWAYS hard-fails, regardless of adapter presence or the
    // (mutually exclusive) --no-gpu bit: the operator forbade a CPU degrade.
    assert_eq!(
        classify_gpu_init_failure(&present, false, true),
        HardFail,
        "required + adapter present => hard-fail"
    );
    assert_eq!(
        classify_gpu_init_failure(&absent, false, true),
        HardFail,
        "required + no adapter => hard-fail (the flag exists for exactly this)"
    );

    // Ordinary run: warn ONLY when a real GPU is present but unusable.
    assert_eq!(
        classify_gpu_init_failure(&present, false, false),
        WarnCpuFallback,
        "auto + adapter present => loud CPU-fallback notice"
    );
    assert_eq!(
        classify_gpu_init_failure(&absent, false, false),
        Quiet,
        "auto + no adapter => quiet (expected CPU-only majority: laptops/CI/containers)"
    );

    // --no-gpu stays quiet EVEN when a real adapter is present: CPU is the
    // explicitly requested route, so a "GPU unusable" notice would be noise.
    assert_eq!(
        classify_gpu_init_failure(&present, true, false),
        Quiet,
        "disabled + adapter present => quiet (CPU is the requested route)"
    );
    assert_eq!(
        classify_gpu_init_failure(&absent, true, false),
        Quiet,
        "disabled + no adapter => quiet"
    );
}

#[test]
fn on_gpu_init_failed_returns_none_without_reentering_onelocks() {
    // THE deadlock regression: force the `Err` branch and prove it RETURNS
    // (returns `None`, the loud degrade), rather than hanging on a reentrant
    // OnceLock. `on_gpu_init_failed` takes the resolved policy by value and,
    // by contract, calls neither `probe_hardware()` nor `get_gpu()`, so this
    // completes even when invoked from inside an initializing OnceLock. Pass
    // required=false so the hard-fail (process-exit) arm is never taken.
    //
    // adapter-present (real GPU unusable) => WarnCpuFallback notice, then None.
    let unusable = GpuInitError::adapter_unusable("forced adapter-present failure");
    assert!(
        on_gpu_init_failed(&unusable, /*disabled=*/ false, /*required=*/ false).is_none(),
        "adapter-present init failure must degrade to None (CPU MoE), not hang"
    );
    // no-adapter => quiet, then None.
    let no_adapter = GpuInitError::no_adapter("forced no-adapter failure");
    assert!(
        on_gpu_init_failed(
            &no_adapter,
            /*disabled=*/ false,
            /*required=*/ false
        )
        .is_none(),
        "no-adapter init failure must degrade to None quietly, not hang"
    );
    // --no-gpu with a real adapter present => still quiet, still None.
    assert!(
        on_gpu_init_failed(&unusable, /*disabled=*/ true, /*required=*/ false).is_none(),
        "disabled-policy init failure must degrade to None quietly, not hang"
    );
}

#[test]
fn on_gpu_init_failed_does_not_deadlock_when_called_mid_onelock_init() {
    // Structural proof of non-reentrancy: run the forced failure path from
    // INSIDE another OnceLock's initializer. The old code called
    // `probe_hardware()` here; if `on_gpu_init_failed` re-entered any
    // process-wide init OnceLock this get_or_init would deadlock and the test
    // would time out. It must complete and cache `true`.
    static GUARD: OnceLock<bool> = OnceLock::new();
    let completed = *GUARD.get_or_init(|| {
        let err = GpuInitError::adapter_unusable("failure raised during OnceLock init");
        on_gpu_init_failed(&err, /*disabled=*/ true, /*required=*/ false).is_none()
    });
    assert!(
        completed,
        "GPU-init-failure handling must complete from within an initializing OnceLock"
    );
}
