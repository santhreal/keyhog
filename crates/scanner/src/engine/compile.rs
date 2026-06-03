use super::*;

impl CompiledScanner {
    pub fn compile(detectors: Vec<DetectorSpec>) -> Result<Self> {
        Self::compile_with_gpu_policy(detectors, GpuInitPolicy::FromEnvironment)
    }

    pub fn compile_with_gpu_policy(
        detectors: Vec<DetectorSpec>,
        gpu_policy: GpuInitPolicy,
    ) -> Result<Self> {
        // `state` is only mutated under `feature = "simd"` (the
        // Hyperscan-reject reroute below). Lean builds would lint it
        // unused-mut otherwise.
        #[cfg_attr(not(feature = "simd"), allow(unused_mut))]
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
        let gpu_disabled = match gpu_policy {
            GpuInitPolicy::FromEnvironment => crate::gpu::env_no_gpu(),
            GpuInitPolicy::ForceEnabled => false,
            GpuInitPolicy::ForceDisabled => true,
        };
        if gpu_disabled {
            let disabled_by_policy = matches!(gpu_policy, GpuInitPolicy::ForceDisabled);
            let in_ci = !disabled_by_policy
                && crate::gpu::is_ci_environment()
                && std::env::var("KEYHOG_NO_GPU").is_err();
            if disabled_by_policy {
                tracing::info!(
                    target: "keyhog::routing",
                    "GPU init bypassed by caller policy; scanner will use CPU/SIMD paths"
                );
            } else if in_ci {
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
        let prefix_propagation = CsrU32::from(build_prefix_propagation(&state.ac_literals));
        let same_prefix_patterns = CsrU32::from(build_same_prefix_patterns(&state.ac_literals));

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
                    (Some(scanner), CsrU32::from(index_map))
                }
                None => (None, CsrU32::default()),
            };

        let (fallback_keyword_ac, fallback_keyword_to_patterns) =
            build_fallback_keyword_ac(&state.fallback);
        let fallback_keyword_to_patterns = CsrU32::from(fallback_keyword_to_patterns);
        // Precompute always-active fallback indices so the per-chunk hot path
        // seeds the sparse active set without scanning the full fallback table.
        let fallback_always_active_indices: Vec<usize> = state
            .fallback
            .iter()
            .enumerate()
            // Mirrors `compiler::build_fallback_keyword_ac`'s
            // 4-char floor - see the rationale comment there. The
            // experimental 3-char floor measured a net F1 regression
            // on SecretBench-medium, so both checks stay at 4.
            .filter_map(|(index, (_, keywords))| {
                (!keywords.iter().any(|k| k.len() >= 4)).then_some(index)
            })
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

        // Resolve each detector's interned (id, name, service) triple ONCE,
        // indexed by detector index, so the per-match emission sites clone by
        // index instead of re-hashing the same three strings through the CHD
        // perfect hash on every finding (PERF-locality_intern-1). The strings
        // are exactly the arena entries the per-match `lookup` would return;
        // every detector field was just fed into `from_detector_strings`
        // above, so each lookup is guaranteed `Some`. The `unwrap_or_else`
        // fallback (interning the source string directly) is unreachable in
        // practice but keeps the build total — a future detector field that
        // somehow missed the interner universe still emits its true string,
        // never an empty or wrong one.
        let metadata_by_index: Vec<(Arc<str>, Arc<str>, Arc<str>)> = detectors
            .iter()
            .map(|d| {
                (
                    static_intern
                        .lookup(&d.id)
                        .unwrap_or_else(|| Arc::from(d.id.as_str())),
                    static_intern
                        .lookup(&d.name)
                        .unwrap_or_else(|| Arc::from(d.name.as_str())),
                    static_intern
                        .lookup(&d.service)
                        .unwrap_or_else(|| Arc::from(d.service.as_str())),
                )
            })
            .collect();

        // Pre-intern the four synthetic entropy-fallback metadata triples once
        // (PERF-locality_intern-1). These are not detector specs, so they are
        // not in the StaticInterner universe; intern them directly into shared
        // Arc<str> here so the entropy emit path clones by index rather than
        // re-allocating/re-hashing the same four constants per finding. String
        // values are byte-identical to the prior `intern_metadata` results.
        #[cfg(feature = "entropy")]
        let entropy_metadata_by_index: [(Arc<str>, Arc<str>, Arc<str>); 4] = {
            use crate::engine::fallback_entropy_helpers::ENTROPY_DETECTOR_METADATA;
            std::array::from_fn(|i| {
                let (id, name, service) = ENTROPY_DETECTOR_METADATA[i];
                (
                    static_intern.lookup(id).unwrap_or_else(|| Arc::from(id)),
                    static_intern
                        .lookup(name)
                        .unwrap_or_else(|| Arc::from(name)),
                    static_intern
                        .lookup(service)
                        .unwrap_or_else(|| Arc::from(service)),
                )
            })
        };

        // Precise-regex validators for the simdsieve hot fast-path. Built here
        // (before `detectors` is moved into the struct) so the fast path can
        // reject literal-prefix candidates the detector's own regex would not
        // match - see `build_hot_pattern_validators`.
        #[cfg(feature = "simdsieve")]
        let hot_pattern_validators =
            crate::simdsieve_prefilter::build_hot_pattern_validators(&detectors);

        // Pre-intern the hot-pattern metadata constants ONCE, index-parallel
        // with HOT_PATTERNS, so the simdsieve fast path clones by slot index
        // instead of re-hashing the same three `&'static str`s through the CHD
        // interner on every hot hit (PERF-locality_intern-1). These constants
        // name real detectors whose id/name/service are already in the interner
        // universe; the `unwrap_or_else` only fires for the one synthetic slot
        // (square) with no canonical detector, where it interns the static
        // string directly — still byte-identical to what the per-match
        // `intern_metadata` call would have produced.
        #[cfg(feature = "simdsieve")]
        let hot_metadata_by_index: Vec<(Arc<str>, Arc<str>, Arc<str>)> = {
            use crate::simdsieve_prefilter::{
                HOT_PATTERN_DETECTOR_IDS, HOT_PATTERN_DISPLAY_NAMES, HOT_PATTERN_NAMES,
            };
            (0..HOT_PATTERN_NAMES.len())
                .map(|i| {
                    let id = HOT_PATTERN_DETECTOR_IDS[i];
                    let name = HOT_PATTERN_DISPLAY_NAMES[i];
                    let service = HOT_PATTERN_NAMES[i];
                    (
                        static_intern.lookup(id).unwrap_or_else(|| Arc::from(id)),
                        static_intern
                            .lookup(name)
                            .unwrap_or_else(|| Arc::from(name)),
                        static_intern
                            .lookup(service)
                            .unwrap_or_else(|| Arc::from(service)),
                    )
                })
                .collect()
        };

        let scanner = Self {
            ac,
            gpu_backend,
            #[cfg(feature = "gpu")]
            wgpu_backend,
            gpu_literals,
            gpu_matcher: OnceLock::new(),
            gpu_const_packs: OnceLock::new(),
            gpu_ac_const_packs: OnceLock::new(),
            ac_gpu_program: OnceLock::new(),
            gpu_last_degrade_reason: std::sync::Mutex::new(None),

            rule_pipeline: OnceLock::new(),
            fused_program: OnceLock::new(),
            fused_decode_programs: OnceLock::new(),
            static_intern,
            metadata_by_index,
            ac_map: state.ac_map,
            prefix_propagation,
            fallback: state.fallback,
            companions: state.companions,
            detectors,
            same_prefix_patterns,
            fallback_keyword_ac,
            fallback_keyword_to_patterns,
            fallback_always_active_indices,
            #[cfg(feature = "simd")]
            simd_prefilter,
            #[cfg(feature = "simd")]
            hs_index_map,
            #[cfg(feature = "simdsieve")]
            hot_pattern_validators,
            #[cfg(feature = "simdsieve")]
            hot_metadata_by_index,
            #[cfg(feature = "entropy")]
            entropy_metadata_by_index,
            config: ScannerConfig::default(),
            alphabet_screen,
            bigram_bloom,
            fragment_cache: crate::fragment_cache::FragmentCache::new(1000),
        };

        Ok(scanner)
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
