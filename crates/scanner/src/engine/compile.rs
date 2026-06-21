use super::*;

impl CompiledScanner {
    pub fn compile(detectors: Vec<DetectorSpec>) -> Result<Self> {
        Self::compile_with_gpu_policy(detectors, GpuInitPolicy::FromRuntimePolicy)
    }

    pub fn compile_with_gpu_policy(
        detectors: Vec<DetectorSpec>,
        gpu_policy: GpuInitPolicy,
    ) -> Result<Self> {
        Self::compile_with_gpu_policy_and_tuning(
            detectors,
            gpu_policy,
            &crate::scanner_config::ScannerTuningConfig::default(),
        )
    }

    pub fn compile_with_gpu_policy_and_tuning(
        detectors: Vec<DetectorSpec>,
        gpu_policy: GpuInitPolicy,
        tuning_config: &crate::scanner_config::ScannerTuningConfig,
    ) -> Result<Self> {
        // LAW10: cfg-only Hyperscan tuning marker; no runtime effect.
        #[cfg(not(feature = "simd"))]
        let _tuning_config = tuning_config;
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
        // `crate::gpu::gpu_disabled_by_policy()` is the single source of truth
        // for "skip every GPU init path". The value comes from the resolved
        // scanner runtime policy set by the CLI/TOML layer, not ambient process
        // environment.
        let gpu_disabled = match gpu_policy {
            GpuInitPolicy::FromRuntimePolicy => crate::gpu::gpu_disabled_by_policy(),
            GpuInitPolicy::ForceEnabled => false,
            GpuInitPolicy::ForceDisabled => true,
        };
        if gpu_disabled {
            let disabled_by_policy = matches!(gpu_policy, GpuInitPolicy::ForceDisabled);
            if disabled_by_policy {
                tracing::info!(
                    target: "keyhog::routing",
                    "GPU init bypassed by caller policy; scanner will use CPU/SIMD paths"
                );
            } else {
                tracing::info!(
                    target: "keyhog::routing",
                    "GPU init bypassed by resolved scanner policy; routing every chunk through the CPU/SIMD path"
                );
            }
        }
        #[cfg(feature = "gpu")]
        let gpu_backend = if !gpu_disabled && crate::hw_probe::probe_hardware().gpu_available {
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
                Some(cuda) => Some(cuda),
                None => match vyre_driver_wgpu::WgpuBackend::shared() {
                    Ok(wgpu) => {
                        let trait_obj: Arc<dyn vyre::VyreBackend> = wgpu;
                        Some(trait_obj)
                    }
                    Err(error) => {
                        tracing::warn!(
                            target: "keyhog::routing",
                            %error,
                            "wgpu backend unavailable; scan will use CPU-only path"
                        );
                        None
                    }
                },
            }
        } else {
            None
        };

        // Lean (no-`gpu`) build: never link the wgpu / CUDA drivers, never
        // probe Vulkan at startup. The hw_probe still reports its findings so
        // downstream routing surfaces resolved GPU-policy semantics, but no
        // backend is acquired. `gpu_disabled` stays read so the cfg-aware
        // dead-code warning is suppressed without an `_ =` decoration.
        #[cfg(not(feature = "gpu"))]
        let gpu_backend: Option<Arc<dyn vyre::VyreBackend>> = {
            let _ = gpu_disabled; // LAW10: unused-binding marker (signature/borrowck/cfg/compile-time assert); no runtime effect, not a fallback
            None
        };
        let prefix_propagation = CsrU32::from(build_prefix_propagation(&state.ac_literals));
        let same_prefix_patterns = CsrU32::from(build_same_prefix_patterns(&state.ac_literals));

        // Build the Hyperscan scanner BEFORE the phase-2 keyword lane so we
        // learn which ac_map patterns Hyperscan rejected (over-long, or an
        // unsupported construct like a large `{100,200}` bounded repeat).
        // A rejected pattern produces zero HS matches, and because it took
        // the literal-prefix (ac_map) branch in build_compile_state it is
        // NOT in the phase-2 keyword lane either - so it is silently dead under
        // the HS backend (the default on Linux/CI). Reroute each one into
        // the phase-2 keyword lane, gated by its detector's keywords, so it
        // fires via the backend-independent regex sweep. Closes the
        // contracts_runner recall hole on line/paloalto/tower/keystonejs/
        // snowflake/bandwidth and the matching adversarial-wrapper misses.
        #[cfg(feature = "simd")]
        let mut state = state;
        #[cfg(feature = "simd")]
        let (simd_prefilter, hs_index_map) =
            match super::build_simd_scanner(&state.ac_map, tuning_config) {
                Some((scanner, index_map, unsupported_ac)) => {
                    for ac_idx in unsupported_ac {
                        let pattern = state.ac_map[ac_idx].clone();
                        let keywords = detectors[pattern.detector_index].keywords.clone();
                        state.phase2_patterns.push((pattern, keywords));
                    }
                    (Some(scanner), CsrU32::from(index_map))
                }
                None => (None, CsrU32::default()),
            };

        let (phase2_keyword_ac, phase2_keyword_to_patterns, phase2_keywords) =
            build_phase2_keyword_ac(&state.phase2_patterns);
        let phase2_keyword_count = phase2_keywords.len();
        let phase2_keyword_to_patterns = CsrU32::from(phase2_keyword_to_patterns);
        // Precompute always-active phase-2 indices so the per-chunk hot path
        // seeds the sparse active set without scanning the full phase-2 table.
        let phase2_always_active_indices: Vec<usize> = state
            .phase2_patterns
            .iter()
            .enumerate()
            // Mirrors `compiler::build_phase2_keyword_ac`'s
            // 4-char floor - see the rationale comment there. The
            // experimental 3-char floor measured a net F1 regression
            // on SecretBench-medium, so both checks stay at 4.
            .filter_map(|(index, (_, keywords))| {
                (!keywords.iter().any(|k| k.len() >= 4)).then_some(index)
            })
            .collect();

        // Shared-anchor localization index: one Aho-Corasick over every
        // phase-2 pattern's regex-REQUIRED prefix literals, so a single chunk
        // pass yields candidate positions for all eligible patterns instead of
        // each pattern scanning the chunk for its own literal. `None` when no
        // pattern is anchor-eligible. Recall-identical (see `phase2_anchor`).
        // Built BEFORE the prefilter so eligible always-active patterns can be
        // removed from it (the prefilter, not extraction, is ~90% of phase-2 cost).
        let phase2_anchor_index = phase2_anchor::Phase2AnchorIndex::build(
            &state.phase2_patterns,
            &phase2_always_active_indices,
        );
        let phase2_always_anchor_literal_count = phase2_anchor_index
            .as_ref()
            .map_or(0, |index| index.always_anchor_literals().len());

        // Confirmed-pass suffix gate (one AC over required suffix literals) so a
        // triggered detector whose rare trailing literal (`.*<sitename>`) is
        // absent skips its O(chunk) whole-chunk regex run.
        let (suffix_gate_ac, ac_suffix_gate) =
            super::scan_postprocess::build_confirmed_suffix_gate(&state.ac_map);
        let gated = ac_suffix_gate.iter().filter(|g| !g.is_empty()).count();
        let confirmed_anchor_index =
            scan_postprocess::confirmed_anchor::ConfirmedAnchorIndex::build(&state.ac_map);
        #[cfg(feature = "gpu")]
        let confirmed_anchor_literal_count = confirmed_anchor_index
            .as_ref()
            .map_or(0, |index| index.anchor_literals().len());
        #[cfg(feature = "gpu")]
        let generic_keyword_literals =
            super::phase2_generic::keywords::generic_keyword_prefilter_stems()
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
        #[cfg(feature = "gpu")]
        let generic_keyword_literal_count = generic_keyword_literals.len();

        #[cfg(feature = "gpu")]
        let gpu_literals = if gpu_backend.is_some() {
            let phase2_always_anchor_literals = phase2_anchor_index
                .as_ref()
                .map_or(&[] as &[String], |index| index.always_anchor_literals());
            build_gpu_literals(
                &state.ac_literals,
                &phase2_keywords,
                phase2_always_anchor_literals,
            )
        } else {
            None
        };
        #[cfg(feature = "gpu")]
        let gpu_position_literals = if gpu_backend.is_some() {
            let confirmed_anchor_literals = confirmed_anchor_index
                .as_ref()
                .map_or(&[] as &[String], |index| index.anchor_literals());
            build_gpu_position_literals(confirmed_anchor_literals, &generic_keyword_literals)
        } else {
            None
        };
        #[cfg(not(feature = "gpu"))]
        let gpu_literals: Option<Arc<Vec<Vec<u8>>>> = None;

        // Combined-RegexSet prefilter over EVERY always-active phase-2 pattern. The
        // plain (homoglyph-variant) batches carry a fast ASCII-folded alternate
        // RegexSet (the homoglyph regex with non-ASCII stripped); on a pure-ASCII
        // chunk it is match-equivalent to the slow unicode-class form, so the
        // prefilter marks the IDENTICAL set in the IDENTICAL order — recall and
        // active-set order unchanged — but far faster (the homoglyph unicode
        // RegexSet was measured at ~90% of phase-2 time). `None` on build
        // failure runs them all (recall-safe).
        let phase2_always_active_prefilter = phase2::Phase2AlwaysActivePrefilter::build(
            &state.phase2_patterns,
            &phase2_always_active_indices,
        );
        tracing::debug!(
            eligible = phase2_anchor_index
                .as_ref()
                .map_or(0, |i| i.eligible_count()),
            total = state.phase2_patterns.len(),
            always_active = phase2_always_active_indices.len(),
            "phase-2 prefilter built with homoglyph ASCII-folded fast path"
        );

        tracing::debug!(
            gated,
            anchored = confirmed_anchor_index
                .as_ref()
                .map_or(0, |index| index.eligible_count()),
            total = state.ac_map.len(),
            "confirmed suffix/anchor gates built"
        );

        log_quality_warnings(&state.quality_warnings);

        let mut alphabet_targets = state.ac_literals.clone();
        for (_, keywords) in &state.phase2_patterns {
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
                        .unwrap_or_else(|| Arc::from(d.id.as_str())), // LAW10: string-intern miss => owned Arc of identical bytes, recall-safe
                    static_intern
                        .lookup(&d.name)
                        .unwrap_or_else(|| Arc::from(d.name.as_str())), // LAW10: string-intern miss => owned Arc of identical bytes, recall-safe
                    static_intern
                        .lookup(&d.service)
                        .unwrap_or_else(|| Arc::from(d.service.as_str())), // LAW10: string-intern miss => owned Arc of identical bytes, recall-safe
                )
            })
            .collect();

        // Pre-resolve the per-detector weak-anchor classification once, indexed
        // by detector_index. `detector_weak_anchor` runs a regex-string scan
        // (`has_broad_identifier_capture`) over the detector's patterns; the
        // result depends ONLY on the spec, so the per-match path in
        // `process_match` would otherwise recompute it for every surviving
        // candidate. Built here (before `detectors` is moved into the struct).
        let detector_weak_anchor_by_index: Vec<bool> = detectors
            .iter()
            .map(crate::suppression::detector_weak_anchor)
            .collect();
        let generic_named_assignment_keywords =
            crate::generic_keyword_owner::build_generic_named_assignment_keywords(&detectors);

        let pattern_boundary_context = boundary::derive_pattern_boundary_context(
            state
                .ac_map
                .iter()
                .chain(state.phase2_patterns.iter().map(|(pattern, _)| pattern)),
        );
        #[cfg(feature = "gpu")]
        let ac_match_upper_bounds: Vec<Option<usize>> = state
            .ac_map
            .iter()
            .map(|pattern| boundary::regex_match_byte_upper_bound(pattern.regex.as_str()))
            .collect();

        // Pre-intern the four synthetic entropy-fallback metadata triples once
        // (PERF-locality_intern-1). These are not detector specs, so they are
        // not in the StaticInterner universe; intern them directly into shared
        // Arc<str> here so the entropy emit path clones by index rather than
        // re-allocating/re-hashing the same four constants per finding. String
        // values are byte-identical to the prior `intern_metadata` results.
        #[cfg(feature = "entropy")]
        let entropy_metadata_by_index: [(Arc<str>, Arc<str>, Arc<str>); 4] = {
            use crate::engine::phase2_entropy::helpers::ENTROPY_DETECTOR_METADATA;
            std::array::from_fn(|i| {
                let (id, name, service) = ENTROPY_DETECTOR_METADATA[i];
                (
                    static_intern.lookup(id).unwrap_or_else(|| Arc::from(id)), // LAW10: string-intern miss => owned Arc of identical bytes, recall-safe
                    static_intern
                        .lookup(name)
                        .unwrap_or_else(|| Arc::from(name)), // LAW10: string-intern miss => owned Arc of identical bytes, recall-safe
                    static_intern
                        .lookup(service)
                        .unwrap_or_else(|| Arc::from(service)), // LAW10: string-intern miss => owned Arc of identical bytes, recall-safe
                )
            })
        };

        // Precise-regex validators for the simdsieve hot fast-path. Built here
        // (before `detectors` is moved into the struct) so the fast path can
        // reject literal-prefix candidates the detector's own regex would not
        // match - see `build_hot_pattern_validators`.
        #[cfg(feature = "simdsieve")]
        let hot_pattern_validators =
            crate::simdsieve_prefilter::build_hot_pattern_validators(&detectors)?;

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
                        static_intern.lookup(id).unwrap_or_else(|| Arc::from(id)), // LAW10: string-intern miss => owned Arc of identical bytes, recall-safe
                        static_intern
                            .lookup(name)
                            .unwrap_or_else(|| Arc::from(name)), // LAW10: string-intern miss => owned Arc of identical bytes, recall-safe
                        static_intern
                            .lookup(service)
                            .unwrap_or_else(|| Arc::from(service)), // LAW10: string-intern miss => owned Arc of identical bytes, recall-safe
                    )
                })
                .collect()
        };

        let scanner = Self {
            ac,
            gpu_backend,
            gpu_literals,
            gpu_matcher: OnceLock::new(),
            #[cfg(feature = "gpu")]
            gpu_position_literals,
            #[cfg(feature = "gpu")]
            gpu_position_matcher: OnceLock::new(),
            gpu_last_degrade_reason: std::sync::Mutex::new(None),
            gpu_degrade_count: std::sync::atomic::AtomicU64::new(0),
            static_intern,
            metadata_by_index,
            detector_weak_anchor_by_index,
            generic_named_assignment_keywords,
            #[cfg(feature = "gpu")]
            ac_match_upper_bounds,
            suffix_gate_ac,
            ac_suffix_gate,
            confirmed_anchor_index,
            ac_map: state.ac_map,
            pattern_boundary_context,
            prefix_propagation,
            phase2_patterns: state.phase2_patterns,
            companions: state.companions,
            detectors,
            same_prefix_patterns,
            phase2_keyword_ac,
            phase2_keyword_to_patterns,
            phase2_keyword_count,
            phase2_always_anchor_literal_count,
            #[cfg(feature = "gpu")]
            confirmed_anchor_literal_count,
            #[cfg(feature = "gpu")]
            generic_keyword_literal_count,
            phase2_always_active_indices,
            phase2_always_active_prefilter,
            phase2_anchor_index,
            #[cfg(feature = "gpu")]
            phase2_gpu_dfa: phase2_gpu_dfa::Phase2GpuDfaCatalogCache::default(),
            tuning: phase2::ScannerTuning::from_defaults(),
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
        profile::set_profile_enabled(config.profile);
        profile::set_perf_trace_enabled(config.perf_trace);
        self.config = config;
        self
    }

    /// Apply explicit performance-route tuning to this compiled scanner.
    pub fn with_tuning_config(self, config: crate::scanner_config::ScannerTuningConfig) -> Self {
        self.tuning.apply_config(&config);
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
/// 5-10x slower wgpu path silently. `--require-gpu` turns the warning into a
/// hard exit, matching the contract used by the MoE init and the scan dispatch
/// paths.
#[cfg(all(target_os = "linux", feature = "gpu"))]
fn surface_cuda_acquisition_failure(error: &dyn std::fmt::Display) {
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
