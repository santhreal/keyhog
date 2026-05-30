use super::*;

impl CompiledScanner {
    pub fn compile(detectors: Vec<DetectorSpec>) -> Result<Self> {
        let mut state = build_compile_state(&detectors)?;
        let ac = build_ac_pattern_set(&state.ac_literals)?;
        // GPU is unconditional in the build; runtime probe decides whether to
        // actually use it. `gpu_available` is set by hw_probe based on adapter
        // detection (excluding software renderers like llvmpipe/lavapipe).
        // Resolve the active GPU backend with the cascade
        //     CUDA (when `cuda` feature on + libcuda.so loadable)
        //     → wgpu (any-vendor cross-platform fallback)
        //     → None (auto-routes to SIMD/CPU).
        // CUDA bypasses the wgpu validation layers + naga IR + WGSL
        // text + driver shader compile; the path through CUDA driver
        // API + PTX is empirically 5-10× faster on NVIDIA hardware
        // and is the headline path. CUDA acquisition is opaque to
        // failures: if libcuda.so is missing or the driver refuses,
        // `acquire()` returns Err and we fall through to wgpu so
        // nothing regresses on non-CUDA hosts.
        // `crate::gpu::env_no_gpu()` is the single source of truth for
        // "skip every GPU init path". Explicit KEYHOG_NO_GPU wins both
        // directions; in its absence the helper auto-detects CI runners
        // (CI=true + a dozen platform-specific markers) and returns
        // true, since CI runners have no discrete GPU - the wgpu probe
        // would enumerate llvmpipe, get rejected as software, and the
        // operator would see a confusing "GPU MoE init failed" warning
        // after burning ~250ms on cold-start. Set KEYHOG_NO_GPU=0 in CI
        // to opt back in on self-hosted GPU runners.
        let gpu_disabled = crate::gpu::env_no_gpu();
        if gpu_disabled {
            let in_ci = crate::gpu::is_ci_environment() && std::env::var("KEYHOG_NO_GPU").is_err();
            if in_ci {
                tracing::info!(
                    target: "keyhog::routing",
                    "CI environment detected (CI= or platform-specific marker set); bypassing CUDA/wgpu init. \
                     Set KEYHOG_NO_GPU=0 to force GPU on self-hosted GPU runners."
                );
            } else {
                tracing::info!(
                    target: "keyhog::routing",
                    "KEYHOG_NO_GPU set: bypassing CUDA/wgpu init, routing every chunk through the CPU/SIMD path"
                );
            }
        }
        #[cfg(feature = "gpu")]
        let (gpu_literals, gpu_backend, wgpu_backend) =
            if !gpu_disabled && crate::hw_probe::probe_hardware().gpu_available {
                let literals = build_gpu_literals(&state.ac_literals);
                let cuda_backend: Option<Arc<dyn vyre::VyreBackend>> = {
                    #[cfg(target_os = "linux")]
                    {
                        match vyre_driver_cuda::cuda_factory() {
                            Ok(boxed) => {
                                tracing::info!(
                                    target: "keyhog::routing",
                                    "CUDA backend acquired, bypassing wgpu/naga/WGSL path"
                                );
                                Some(Arc::from(boxed))
                            }
                            Err(error) => {
                                surface_cuda_acquisition_failure(&error);
                                None
                            }
                        }
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        None
                    }
                };
                match cuda_backend {
                    Some(cuda) => (literals, Some(cuda), None),
                    None => match vyre_driver_wgpu::WgpuBackend::shared() {
                        Ok(wgpu) => {
                            let trait_obj: Arc<dyn vyre::VyreBackend> = wgpu.clone();
                            (literals, Some(trait_obj), Some(wgpu))
                        }
                        Err(error) => {
                            tracing::warn!(
                                target: "keyhog::routing",
                                %error,
                                "wgpu backend unavailable; scan will use CPU-only path"
                            );
                            (literals, None, None)
                        }
                    },
                }
            } else {
                (None, None, None)
            };

        // Lean (no-`gpu`) build: never link the wgpu / CUDA drivers, never
        // probe Vulkan at startup. The hw_probe still reports its findings so
        // downstream routing surfaces `KEYHOG_NO_GPU` semantics, but no
        // backend is acquired. `gpu_disabled` stays read so the cfg-aware
        // dead-code warning is suppressed without an `_ =` decoration.
        #[cfg(not(feature = "gpu"))]
        let (gpu_literals, gpu_backend): (
            Option<Arc<Vec<Vec<u8>>>>,
            Option<Arc<dyn vyre::VyreBackend>>,
        ) = {
            let _ = gpu_disabled;
            (None, None)
        };
        let prefix_propagation = build_prefix_propagation(&state.ac_literals);
        let same_prefix_patterns = build_same_prefix_patterns(&state.ac_literals);

        // Build the Hyperscan scanner BEFORE the keyword fallback so we
        // learn which ac_map patterns Hyperscan rejected (over-long, or an
        // unsupported construct like a large `{100,200}` bounded repeat).
        // A rejected pattern produces zero HS matches, and because it took
        // the literal-prefix (ac_map) branch in build_compile_state it is
        // NOT in the keyword fallback either - so it is silently dead under
        // the HS backend (the default on Linux/CI). Reroute each one into
        // the keyword fallback, gated by its detector's keywords, so it
        // fires via the backend-independent regex sweep. Closes the
        // contracts_runner recall hole on line/paloalto/tower/keystonejs/
        // snowflake/bandwidth and the matching adversarial-wrapper misses.
        #[cfg(feature = "simd")]
        let (simd_prefilter, hs_index_map) =
            match super::build_simd_scanner(&state.ac_map, &state.fallback) {
                Some((scanner, index_map, unsupported_ac)) => {
                    for ac_idx in unsupported_ac {
                        let pattern = state.ac_map[ac_idx].clone();
                        let keywords = detectors[pattern.detector_index].keywords.clone();
                        state.fallback.push((pattern, keywords));
                    }
                    (Some(scanner), index_map)
                }
                None => (None, Vec::new()),
            };

        let (fallback_keyword_ac, fallback_keyword_to_patterns) =
            build_fallback_keyword_ac(&state.fallback);
        // Precompute the per-pattern "always-active" bitmap so the per-chunk
        // hot path avoids walking every pattern's keyword list. See the
        // doc comment on the field for rationale.
        let fallback_always_active: Vec<bool> = state
            .fallback
            .iter()
            // Mirrors `compiler::build_fallback_keyword_ac`'s
            // 4-char floor - see the rationale comment there. The
            // experimental 3-char floor measured a net F1 regression
            // on SecretBench-medium, so both checks stay at 4.
            .map(|(_, keywords)| !keywords.iter().any(|k| k.len() >= 4))
            .collect();

        log_quality_warnings(&state.quality_warnings);

        let mut alphabet_targets = state.ac_literals.clone();
        for (_, keywords) in &state.fallback {
            alphabet_targets.extend(keywords.clone());
        }
        let alphabet_screen = if alphabet_targets.is_empty() {
            None
        } else {
            Some(crate::alphabet_filter::AlphabetScreen::new(
                &alphabet_targets,
            ))
        };

        let bigram_bloom =
            crate::bigram_bloom::BigramBloom::from_literal_prefixes(&alphabet_targets);
        tracing::debug!(
            popcount = bigram_bloom.popcount(),
            "bigram bloom built (4096 bits, lower popcount = stronger filter)"
        );

        // Pre-intern detector metadata strings into a CHD perfect
        // hash so per-scan `intern_metadata` calls hand out shared
        // `Arc<str>` without touching the global allocator. Built
        // once per scanner; lock-free on read.
        let static_intern_strings: Vec<&str> = detectors
            .iter()
            .flat_map(|d| [d.id.as_str(), d.name.as_str(), d.service.as_str()].into_iter())
            .collect();
        let static_intern = Arc::new(crate::static_intern::StaticInterner::from_detector_strings(
            static_intern_strings,
        ));

        // Precise-regex validators for the simdsieve hot fast-path. Built here
        // (before `detectors` is moved into the struct) so the fast path can
        // reject literal-prefix candidates the detector's own regex would not
        // match - see `build_hot_pattern_validators`.
        #[cfg(feature = "simdsieve")]
        let hot_pattern_validators =
            crate::simdsieve_prefilter::build_hot_pattern_validators(&detectors);

        Ok(Self {
            ac,
            gpu_backend,
            #[cfg(feature = "gpu")]
            wgpu_backend,
            gpu_literals,
            gpu_matcher: OnceLock::new(),
            gpu_const_packs: OnceLock::new(),
            gpu_ac_const_packs: OnceLock::new(),
            ac_gpu_program: OnceLock::new(),

            rule_pipeline: OnceLock::new(),
            fused_program: OnceLock::new(),
            fused_decode_programs: OnceLock::new(),
            static_intern,
            ac_map: state.ac_map,
            prefix_propagation,
            fallback: state.fallback,
            companions: state.companions,
            detectors,
            same_prefix_patterns,
            fallback_keyword_ac,
            fallback_keyword_to_patterns,
            fallback_always_active,
            #[cfg(feature = "simd")]
            simd_prefilter,
            #[cfg(feature = "simd")]
            hs_index_map,
            #[cfg(feature = "simdsieve")]
            hot_pattern_validators,
            config: ScannerConfig::default(),
            alphabet_screen,
            bigram_bloom,
            fragment_cache: crate::fragment_cache::FragmentCache::new(1000),
        })
    }

    /// Apply a custom configuration to the compiled scanner.
    pub fn with_config(mut self, config: ScannerConfig) -> Self {
        self.config = config;
        self
    }
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
/// 5-10x slower wgpu path silently. KEYHOG_REQUIRE_GPU=1 turns the
/// warning into a hard exit, matching the contract used by the MoE
/// init and the scan dispatch paths.
#[cfg(all(target_os = "linux", feature = "gpu"))]
fn surface_cuda_acquisition_failure(error: &dyn std::fmt::Display) {
    let on_nvidia_host = nvidia_userland_present();
    let require_gpu = std::env::var("KEYHOG_REQUIRE_GPU").as_deref() == Ok("1");
    let no_gpu = std::env::var("KEYHOG_NO_GPU").as_deref() == Ok("1");

    if require_gpu && on_nvidia_host {
        eprintln!(
            "keyhog: KEYHOG_REQUIRE_GPU=1 but CUDA backend acquisition failed on \
an NVIDIA host: {error}. Refusing to fall back to WGPU."
        );
        std::process::exit(2);
    }

    if no_gpu {
        return;
    }

    if on_nvidia_host && CUDA_FALLBACK_WARNED.set(()).is_ok() {
        eprintln!(
            "keyhog: CUDA backend unavailable on this NVIDIA host ({error}); \
falling back to WGPU (typically 5-10x slower than CUDA on the same hardware). \
This is usually a libcuda.so version mismatch or a driver upgrade pending a \
reboot. Set KEYHOG_NO_GPU=1 to silence this warning, or KEYHOG_REQUIRE_GPU=1 \
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
