use super::*;

impl CompiledScanner {
    pub fn compile(detectors: Vec<DetectorSpec>) -> Result<Self> {
        let state = build_compile_state(&detectors)?;
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
        let (gpu_literals, gpu_backend, wgpu_backend) =
            if crate::hw_probe::probe_hardware().gpu_available {
                let literals = build_gpu_literals(&state.ac_literals);
                let cuda_backend: Option<Arc<dyn vyre::VyreBackend>> = {
                    #[cfg(feature = "cuda")]
                    {
                        match vyre_driver_cuda::cuda_factory() {
                            Ok(boxed) => {
                                tracing::info!(
                                    target: "keyhog::routing",
                                    "CUDA backend acquired — bypassing wgpu/naga/WGSL path"
                                );
                                Some(Arc::from(boxed))
                            }
                            Err(error) => {
                                tracing::debug!(
                                    "CUDA backend unavailable, will try wgpu fallback: {error}"
                                );
                                None
                            }
                        }
                    }
                    #[cfg(not(feature = "cuda"))]
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
                        Err(_) => (literals, None, None),
                    },
                }
            } else {
                (None, None, None)
            };
        let prefix_propagation = build_prefix_propagation(&state.ac_literals);
        let same_prefix_patterns = build_same_prefix_patterns(&state.ac_literals);
        let (fallback_keyword_ac, fallback_keyword_to_patterns) =
            build_fallback_keyword_ac(&state.fallback);
        // Precompute the per-pattern "always-active" bitmap so the per-chunk
        // hot path avoids walking every pattern's keyword list. See the
        // doc comment on the field for rationale.
        let fallback_always_active: Vec<bool> = state
            .fallback
            .iter()
            // Mirrors `compiler::build_fallback_keyword_ac`'s
            // 4-char floor — see the rationale comment there. The
            // experimental 3-char floor measured a net F1 regression
            // on SecretBench-medium, so both checks stay at 4.
            .map(|(_, keywords)| !keywords.iter().any(|k| k.len() >= 4))
            .collect();

        log_quality_warnings(&state.quality_warnings);

        #[cfg(feature = "simdsieve")]
        let simdsieve_prefilter = crate::simdsieve_prefilter::SimdPrefilter::new();

        #[cfg(feature = "simd")]
        let (simd_prefilter, hs_index_map) =
            backend::build_simd_scanner(&state.ac_map, &state.fallback)
                .map(|(s, m)| (Some(s), m))
                .unwrap_or((None, Vec::new()));

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

        Ok(Self {
            ac,
            gpu_backend,
            wgpu_backend,
            gpu_literals,
            gpu_matcher: OnceLock::new(),
            gpu_const_packs: OnceLock::new(),
            gpu_ac_const_packs: OnceLock::new(),
            ac_gpu_program: OnceLock::new(),

            rule_pipeline: OnceLock::new(),
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
            simdsieve_prefilter,
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
