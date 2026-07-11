#[cfg(feature = "simdsieve")]
use super::compile_helpers::build_hot_pattern_slots;
#[cfg(all(target_os = "linux", feature = "gpu"))]
use super::compile_helpers::surface_cuda_acquisition_failure;
use super::compile_helpers::validate_compiled_pattern_detector_indices;
use super::*;

impl CompiledScanner {
    /// Compile detector specs into a [`CompiledScanner`] using the process-wide
    /// runtime GPU policy and default tuning. The common entry point.
    pub fn compile(detectors: Vec<DetectorSpec>) -> Result<Self> {
        Self::compile_with_gpu_policy(detectors, GpuInitPolicy::FromRuntimePolicy)
    }

    /// Compile with an explicit [`GpuInitPolicy`] (overriding the runtime
    /// policy) and default scanner tuning.
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

    /// Full-control compile entry point: explicit [`GpuInitPolicy`] and scanner
    /// [`ScannerTuningConfig`]. The other `compile*` methods delegate here.
    pub fn compile_with_gpu_policy_and_tuning(
        detectors: Vec<DetectorSpec>,
        gpu_policy: GpuInitPolicy,
        tuning_config: &crate::scanner_config::ScannerTuningConfig,
    ) -> Result<Self> {
        crate::detector_classification::validate().map_err(crate::error::ScanError::Config)?;
        // LAW10: cfg-only Hyperscan tuning marker; no runtime effect.
        #[cfg(not(feature = "simd"))]
        let _tuning_config = tuning_config;
        let state = build_compile_state(&detectors)?;
        let ac = build_ac_pattern_set(&state.ac_literals)?;
        let credential_shape_by_detector_index =
            crate::credential_shapes::build_detector_shape_rules(&detectors)
                .map_err(crate::error::ScanError::Config)?;
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
                    super::gpu_artifacts::append_hyperscan_unsupported_patterns(
                        &mut state,
                        &detectors,
                        unsupported_ac,
                    );
                    (Some(scanner), CsrU32::from(index_map))
                }
                None => (None, CsrU32::default()),
            };

        validate_compiled_pattern_detector_indices(
            &state.ac_map,
            &state.phase2_patterns,
            detectors.len(),
        )?;

        let (phase2_keyword_ac, phase2_keyword_to_patterns, phase2_keywords) =
            build_phase2_keyword_ac(&state.phase2_patterns);
        let phase2_keyword_count = phase2_keywords.len();
        let phase2_keyword_to_patterns = CsrU32::from(phase2_keyword_to_patterns);
        // Precompute always-active phase-2 indices so the per-chunk hot path
        // seeds the sparse active set without scanning the full phase-2 table.
        let phase2_always_active_indices =
            super::gpu_artifacts::phase2_always_active_indices(&state.phase2_patterns);

        // Three independent Aho-Corasick indices over the (post-HS-append)
        // compile state. They share no mutable state and each is a pure function
        // of `state`, so they build concurrently on the rayon pool instead of
        // back-to-back (~82ms -> ~46ms serial->parallel on the full corpus):
        //   - phase2_anchor_index: shared-anchor localization over every phase-2
        //     pattern's regex-REQUIRED prefix literals, so one chunk pass yields
        //     candidate positions for all eligible patterns. Built BEFORE the
        //     prefilter so eligible always-active patterns can be removed from it
        //     (the prefilter, not extraction, is ~90% of phase-2 cost). `None`
        //     when no pattern is anchor-eligible. Recall-identical.
        //   - suffix gate: one AC over required suffix literals so a triggered
        //     detector whose rare trailing literal (`.*<sitename>`) is absent
        //     skips its O(chunk) whole-chunk regex run.
        //   - confirmed_anchor_index: AC over the confirmed ac_map anchors.
        let (phase2_anchor_index, ((suffix_gate_ac, ac_suffix_gate), confirmed_anchor_index)) =
            rayon::join(
                || {
                    phase2_anchor::Phase2AnchorIndex::build(
                        &state.phase2_patterns,
                        &phase2_always_active_indices,
                    )
                },
                || {
                    rayon::join(
                        || super::scan_postprocess::build_confirmed_suffix_gate(&state.ac_map),
                        || {
                            scan_postprocess::confirmed_anchor::ConfirmedAnchorIndex::build(
                                &state.ac_map,
                            )
                        },
                    )
                },
            );
        let phase2_always_anchor_literal_count = phase2_anchor_index
            .as_ref()
            .map_or(0, |index| index.always_anchor_literals().len());
        let gated = ac_suffix_gate.iter().filter(|g| !g.is_empty()).count();
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
        // Reserve the exact keyword total up front and clone each keyword
        // straight in (`iter().cloned()`), instead of materializing a throwaway
        // `Vec<String>` per phase-2 pattern via `keywords.clone()` and growing
        // `alphabet_targets` by repeated reallocation (Law 7). Byte-identical:
        // the same keyword strings land in the same order.
        let extra_keyword_count: usize = state
            .phase2_patterns
            .iter()
            .map(|(_, keywords)| keywords.len())
            .sum();
        alphabet_targets.reserve(extra_keyword_count);
        for (_, keywords) in &state.phase2_patterns {
            alphabet_targets.extend(keywords.iter().cloned());
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
            "bigram bloom built (65536 slots / 8 KB direct table, lower popcount = stronger filter)"
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

        // Pre-resolve the per-detector weak-anchor BASE classification once,
        // indexed by detector_index. The detector-wide half (residual pure-hex
        // list, generic/private-key carve-out, explicit min_confidence) depends
        // ONLY on the spec and is resolved here; the per-PATTERN broad-identifier
        // half is resolved in `process_match` against the matched `entry.regex`
        // (memoized on the `LazyRegex`), so a strong pattern in a multi-pattern
        // detector keeps its anchor. Built before `detectors` is moved.
        let detector_weak_anchor_base_by_index: Vec<crate::suppression::WeakAnchorBase> = detectors
            .iter()
            .map(crate::suppression::detector_weak_anchor_base)
            .collect::<std::result::Result<_, _>>()
            .map_err(crate::error::ScanError::Config)?;
        let generic_named_assignment_keywords =
            crate::generic_keyword_owner::build_generic_named_assignment_keywords(&detectors);
        let generic_owning_detector =
            crate::generic_keyword_owner::GenericOwningDetectorIndex::build(&detectors);

        let stripe_hot_confirmed_prefixes =
            crate::detector_classification::stripe_hot_confirmed_prefixes()
                .map_err(crate::error::ScanError::Config)?;
        let stripe_hot_confirmed_by_pattern: Vec<bool> = state
            .ac_map
            .iter()
            .map(|entry| {
                detectors.get(entry.detector_index).is_some_and(|detector| {
                    detector.id.as_str() == crate::detector_ids::STRIPE_SECRET_KEY
                        && stripe_hot_confirmed_prefixes
                            .iter()
                            .any(|prefix| entry.regex.as_str().starts_with(prefix.as_str()))
                })
            })
            .collect();

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

        // Resolved hot-pattern slots for the simdsieve fast path: one row per
        // slot carrying BOTH the precise-regex validator AND the canonical
        // `ac_map` delegate, so the two can never be indexed apart at scan time.
        // Built here (before `detectors` is moved into the struct) so the fast
        // path can reject literal-prefix candidates the detector's own regex
        // would not match - see `build_hot_pattern_slots`. The builder asserts
        // both component tables equal `HOT_PATTERNS.len()` before zipping, so a
        // drift fails the scanner build loud rather than silently truncating.
        #[cfg(feature = "simdsieve")]
        let hot_pattern_slots = build_hot_pattern_slots(&detectors, &state.ac_map)?;

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
            detector_weak_anchor_base_by_index,
            generic_named_assignment_keywords,
            generic_owning_detector,
            #[cfg(feature = "gpu")]
            ac_match_upper_bounds,
            suffix_gate_ac,
            ac_suffix_gate,
            stripe_hot_confirmed_by_pattern,
            confirmed_anchor_index,
            ac_map: state.ac_map,
            pattern_boundary_context,
            prefix_propagation,
            phase2_patterns: state.phase2_patterns,
            companions: state.companions,
            detectors,
            credential_shape_by_detector_index,
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
            hot_pattern_slots,
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
