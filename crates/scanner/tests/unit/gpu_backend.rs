use super::*;
#[cfg(target_os = "linux")]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};

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
    let _gpu_test_guard = crate::testing::gpu_test_lock();
    // GPU/CPU parity guard: the GPU MoE compute shader must reproduce the CPU
    // MoE (`ml_scorer::score_features`, the reference every confidence floor is
    // tuned and benched against) on EVERY dispatch of a >=GPU_BATCH_THRESHOLD
    // batch, with no spurious 0.0 scores. This runs dispatches ONE AT A TIME,
    // so it isolates a genuinely broken shader/weights/driver from the
    // concurrent params-race regression below (which the autoroute-calibration
    // abort actually turned out to be) and proves the dispatch is stable across
    // many repeats.
    let gpu_available = match get_gpu() {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(error) => panic!("GPU acquisition policy failure: {error}"),
    };
    if super::super::gpu_disabled_by_policy() || !gpu_available {
        eprintln!("no usable GPU adapter; skipping GPU MoE dispatch regression");
        return;
    }
    let probe = gpu_moe_parity_probe_features();
    assert!(probe.len() >= GPU_BATCH_THRESHOLD);
    let cpu: Vec<f64> = probe.iter().map(crate::ml_scorer::score_features).collect();
    let timeout = Duration::from_millis(30_000);
    for rep in 0..128 {
        let gpu = dispatch_moe_batch(&probe, timeout)
            .expect("GPU MoE dispatch returned a typed failure")
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
    let _gpu_test_guard = crate::testing::gpu_test_lock();
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
    let gpu_available = match get_gpu() {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(error) => panic!("GPU acquisition policy failure: {error}"),
    };
    if super::super::gpu_disabled_by_policy() || !gpu_available {
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
                            .expect("concurrent GPU MoE dispatch returned a typed failure")
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
    use GpuInitFailureAction::{QuietAbsence, RecoverWithReceipt, RequiredFailure};
    let present = GpuInitError::adapter_unusable("real adapter, MoE unusable");
    let absent = GpuInitError::no_adapter("no adapter");

    // --require-gpu ALWAYS hard-fails, regardless of adapter presence or the
    // (mutually exclusive) --no-gpu bit: the operator forbade a CPU degrade.
    assert_eq!(
        classify_gpu_init_failure(&present, false, true),
        RequiredFailure,
        "required + adapter present => hard-fail"
    );
    assert_eq!(
        classify_gpu_init_failure(&absent, false, true),
        RequiredFailure,
        "required + no adapter => hard-fail (the flag exists for exactly this)"
    );

    // Ordinary run: warn ONLY when a real GPU is present but unusable.
    assert_eq!(
        classify_gpu_init_failure(&present, false, false),
        RecoverWithReceipt,
        "auto + adapter present => loud CPU-fallback notice"
    );
    assert_eq!(
        classify_gpu_init_failure(&absent, false, false),
        QuietAbsence,
        "auto + no adapter => quiet (expected CPU-only majority: laptops/CI/containers)"
    );

    // --no-gpu stays quiet EVEN when a real adapter is present: CPU is the
    // explicitly requested route, so a "GPU unusable" notice would be noise.
    assert_eq!(
        classify_gpu_init_failure(&present, true, false),
        QuietAbsence,
        "disabled + adapter present => quiet (CPU is the requested route)"
    );
    assert_eq!(
        classify_gpu_init_failure(&absent, true, false),
        QuietAbsence,
        "disabled + no adapter => quiet"
    );
}

#[test]
fn on_gpu_init_failed_returns_without_reentering_onelocks() {
    // THE deadlock regression: force the failure branch and prove it returns
    // a typed recovery outcome rather than hanging on a reentrant OnceLock.
    // `on_gpu_init_failed` takes the resolved policy by value and, by contract,
    // calls neither `probe_hardware()` nor `get_gpu()`, so this completes even
    // when invoked from inside an initializing OnceLock. `required=false`
    // selects the explicit recovery/absence outcomes rather than a typed error.
    //
    // Adapter-present (real GPU unusable) => receipt-backed recovery.
    let unusable = GpuInitError::adapter_unusable("forced adapter-present failure");
    assert!(
        on_gpu_init_failed(&unusable, /*disabled=*/ false, /*required=*/ false).is_ok(),
        "adapter-present init failure must emit a recovery receipt without hanging"
    );
    // No adapter => intentional quiet CPU-only route.
    let no_adapter = GpuInitError::no_adapter("forced no-adapter failure");
    assert!(
        on_gpu_init_failed(
            &no_adapter,
            /*disabled=*/ false,
            /*required=*/ false
        )
        .is_ok(),
        "no-adapter init failure must return quietly without hanging"
    );
    // --no-gpu with a real adapter present => intentional quiet CPU route.
    assert!(
        on_gpu_init_failed(&unusable, /*disabled=*/ true, /*required=*/ false).is_ok(),
        "disabled-policy init failure must return quietly without hanging"
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
        on_gpu_init_failed(&err, /*disabled=*/ true, /*required=*/ false).is_ok()
    });
    assert!(
        completed,
        "GPU-init-failure handling must complete from within an initializing OnceLock"
    );
}

/// Locks out scanner-library process exits by proving required GPU initialization
/// returns the complete typed failure while ordinary recovery records a receipt.
#[test]
fn gpu_init_diagnostics_return_required_error_and_receipt_recovery() {
    let required = GpuInitError::adapter_unusable("synthetic artifact load failure");
    let error = on_gpu_init_failed(&required, false, true)
        .expect_err("required GPU initialization must return a typed error");
    assert_eq!(
        error.to_string(),
        "--require-gpu requested but GPU MoE init failed: synthetic artifact load failure"
    );

    let absent = GpuInitError::no_adapter("synthetic CPU-only host");
    on_gpu_init_failed(&absent, false, false)
        .expect("ordinary CPU-only absence is not a GPU recovery");
    on_gpu_init_failed(&required, false, false)
        .expect("ordinary GPU initialization failure must emit a recovery receipt");
}

/// Locks out accidental CUDA/WGPU driver work on the production CPU-absence
/// state by proving both exact backend identities remain uninitialized.
#[test]
fn default_backend_peers_are_cpu_absent_and_lazy() {
    let peers = GpuBackendPeers::default();
    assert_eq!(peers.availability(), GpuBackendAvailability::default());
    for backend in [crate::ScanBackend::GpuCuda, crate::ScanBackend::GpuWgpu] {
        assert!(peers.get(backend).is_none());
        assert!(peers.initialized(backend).is_none());
        assert!(peers.initialization_error(backend).is_none());
    }
}

/// Locks out probing or acquiring either GPU backend when census reports a
/// CPU-only host; the lazy closure must remain completely untouched.
#[test]
fn unavailable_peer_never_runs_lazy_acquisition() {
    let slot = OnceLock::<Result<usize, String>>::new();
    let calls = AtomicUsize::new(0);
    let result = lazy_acquire(false, &slot, || {
        calls.fetch_add(1, Ordering::Relaxed);
        Ok(7)
    });
    assert!(result.is_none());
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert!(slot.get().is_none());
}

/// Locks out duplicate CUDA/WGPU lifecycle work by proving each backend's
/// independent slot acquires at most once and retains its own identity.
#[test]
fn backend_slots_are_lazy_once_and_identity_preserving() {
    let cuda = OnceLock::<Result<&'static str, String>>::new();
    let wgpu = OnceLock::<Result<&'static str, String>>::new();
    let calls = AtomicUsize::new(0);
    for _ in 0..2 {
        let cuda_result = lazy_acquire(true, &cuda, || {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok("cuda")
        })
        .expect("available CUDA slot must initialize");
        assert_eq!(
            cuda_result.as_ref().expect("synthetic CUDA acquisition"),
            &"cuda"
        );
        let wgpu_result = lazy_acquire(true, &wgpu, || {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok("wgpu")
        })
        .expect("available WGPU slot must initialize");
        assert_eq!(
            wgpu_result.as_ref().expect("synthetic WGPU acquisition"),
            &"wgpu"
        );
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

/// Locks out cudarc's release-build abort path by proving a failed dynamic
/// library preflight prevents the CUDA acquisition closure from running.
#[cfg(target_os = "linux")]
#[test]
fn failed_cuda_preflight_short_circuits_acquisition() {
    let acquired = AtomicBool::new(false);
    let error = run_cuda_after_preflight(
        || Err("synthetic missing libcuda".to_owned()),
        || {
            acquired.store(true, Ordering::Relaxed);
            Ok(())
        },
        "backend acquisition",
    )
    .expect_err("a failed driver preflight must fail CUDA acquisition");
    assert_eq!(error, "synthetic missing libcuda");
    assert!(!acquired.load(Ordering::Relaxed));
}

/// Locks out losing adapter identity or byte counts when artifact loading fails
/// before shader construction on a storage-constrained device.
#[test]
fn weights_limit_failure_retains_exact_adapter_context() {
    let info = wgpu::AdapterInfo {
        name: "test-wgpu-adapter".to_owned(),
        vendor: 0,
        device: 0,
        device_type: wgpu::DeviceType::DiscreteGpu,
        driver: "test-driver".to_owned(),
        driver_info: "test-driver-info".to_owned(),
        backend: wgpu::Backend::Vulkan,
    };
    let mut limits = wgpu::Limits::default();
    limits.max_storage_buffer_binding_size = 64;

    assert_eq!(
        validate_weights_size(65, &info, &limits),
        Err("GPU adapter test-wgpu-adapter exposes max_storage_buffer_binding_size=64 B, too small for the 65 B MoE weights buffer".to_owned())
    );
}

/// Locks out cross-request recovery attribution by proving the request scope
/// starts empty and owns exactly one explicit receipt.
#[test]
fn recovery_receipt_scope_has_exact_zero_and_positive_states() {
    let (_, untouched) = crate::gpu::with_recovery_receipt_scope(|| {});
    assert_eq!(untouched, 0);
    let (_, recorded) = crate::gpu::with_recovery_receipt_scope(|| {
        crate::gpu::record_recovery_receipt();
    });
    assert_eq!(recorded, 1);
}
