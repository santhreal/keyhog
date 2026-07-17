#[cfg(feature = "simdsieve")]
use super::compile_helpers::build_hot_pattern_slots;
#[cfg(all(target_os = "linux", feature = "gpu"))]
use super::compile_helpers::surface_cuda_acquisition_failure;
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
            &ScannerTuningConfig::default(),
        )
    }

    /// Full-control compile entry point: explicit [`GpuInitPolicy`] and scanner
    /// [`ScannerTuningConfig`]. The other `compile*` methods delegate here.
    pub fn compile_with_gpu_policy_and_tuning(
        detectors: Vec<DetectorSpec>,
        gpu_policy: GpuInitPolicy,
        tuning_config: &ScannerTuningConfig,
    ) -> Result<Self> {
        // LAW10: cfg-only Hyperscan tuning marker; no runtime effect.
        #[cfg(not(feature = "simd"))]
        let _tuning_config = tuning_config;
        let state = build_compile_state(&detectors)?;
        validate_compiled_pattern_detector_indices(
            &state.ac_map,
            &state.phase2_patterns,
            detectors.len(),
        )?;
        let ac = build_ac_pattern_set(&state.ac_literals)?;
        // GPU is unconditional in the build; runtime probe decides whether to
        // actually use it. `gpu_available` is set by hw_probe based on adapter
        // detection (excluding software renderers like llvmpipe/lavapipe).
        // Acquire every compiled GPU driver independently. CUDA and WGPU are
        // peer execution candidates. Persisted autoroute evidence chooses the
        // exact driver for each workload, so acquisition order has no routing
        // meaning and one driver's failure never silently selects another.
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
        let (gpu_backends, gpu_acquisition_failures) = if !gpu_disabled {
            let mut peers = GpuBackendPeers::default();
            let mut failures = Vec::new();
            {
                #[cfg(target_os = "linux")]
                {
                    match vyre_driver_cuda::backend::CudaBackend::acquire() {
                        Ok(cuda) => {
                            let caps = &cuda.caps;
                            peers.cuda_device_identity = Some(format!(
                                "{}:ordinal={}:cc={}.{}:vram={}",
                                caps.name,
                                caps.ordinal,
                                caps.compute_capability.0,
                                caps.compute_capability.1,
                                caps.total_memory
                            ));
                            match linux_cuda_runtime_identity() {
                                Ok(identity) => peers.cuda_runtime_identity = Some(identity),
                                Err(diagnostic) => {
                                    tracing::warn!(
                                        target: "keyhog::routing",
                                        %diagnostic,
                                        "CUDA peer acquired without reproducible runtime identity"
                                    );
                                }
                            }
                            let boxed: Box<dyn vyre::VyreBackend> =
                                Box::new(vyre_driver_cuda::CudaBackendRegistration::new(cuda));
                            tracing::info!(
                                target: "keyhog::routing",
                                "CUDA peer backend acquired"
                            );
                            peers.cuda = Some(Arc::from(boxed));
                        }
                        Err(error) => {
                            surface_cuda_acquisition_failure(&error);
                            failures.push(GpuBackendAcquisitionFailure {
                                backend: "cuda",
                                diagnostic: error.to_string(),
                            });
                        }
                    }
                }
            }
            match vyre_driver_wgpu::WgpuBackend::shared() {
                Ok(wgpu) => {
                    let info = wgpu.adapter_info();
                    peers.wgpu_device_identity = Some(format!(
                        "{}:vendor={:04x}:device={:04x}",
                        info.name, info.vendor, info.device
                    ));
                    peers.wgpu_runtime_identity = Some(format!(
                        "{:?}:{}:{}",
                        info.backend, info.driver, info.driver_info
                    ));
                    peers.wgpu_is_software = info.device_type == wgpu::DeviceType::Cpu;
                    let trait_obj: Arc<dyn vyre::VyreBackend> = wgpu;
                    peers.wgpu = Some(trait_obj);
                    tracing::info!(target: "keyhog::routing", "WGPU peer backend acquired");
                }
                Err(error) => {
                    tracing::warn!(
                        target: "keyhog::routing",
                        %error,
                        "WGPU peer backend acquisition failed"
                    );
                    failures.push(GpuBackendAcquisitionFailure {
                        backend: "wgpu",
                        diagnostic: error.to_string(),
                    });
                }
            }
            (peers, failures)
        } else {
            (GpuBackendPeers::default(), Vec::new())
        };

        // Lean (no-`gpu`) build: never link the wgpu / CUDA drivers, never
        // probe Vulkan at startup. The hw_probe still reports its findings so
        // downstream routing surfaces resolved GPU-policy semantics, but no
        // backend is acquired. `gpu_disabled` stays read so the cfg-aware
        // dead-code warning is suppressed without an `_ =` decoration.
        #[cfg(not(feature = "gpu"))]
        let (gpu_backends, gpu_acquisition_failures) = {
            let _ = gpu_disabled; // LAW10: unused-binding marker (signature/borrowck/cfg/compile-time assert); no runtime effect, not a fallback
            (GpuBackendPeers::default(), Vec::new())
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
        let (simd_prefilter, hs_index_map) = match build_simd_scanner(&state.ac_map, tuning_config)
        {
            Some((scanner, index_map, unsupported_ac)) => {
                append_hyperscan_unsupported_patterns(&mut state, &detectors, unsupported_ac);
                (Some(scanner), CsrU32::from(index_map))
            }
            None => (None, CsrU32::default()),
        };

        // Hyperscan may reroute unsupported confirmed patterns into phase 2.
        // Validate the augmented state as well as the pre-append state above.
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
        let phase2_always_active_indices = phase2_always_active_indices(&state.phase2_patterns);

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
                || Phase2AnchorIndex::build(&state.phase2_patterns, &phase2_always_active_indices),
                || {
                    rayon::join(
                        || build_confirmed_suffix_gate(&state.ac_map),
                        || ConfirmedAnchorIndex::build(&state.ac_map),
                    )
                },
            );
        let phase2_always_anchor_literal_count = phase2_anchor_index
            .as_ref()
            .map_or(0, |index| index.always_anchor_literals().len());
        #[cfg(feature = "gpu")]
        let confirmed_anchor_literals = confirmed_anchor_index
            .as_ref()
            .map_or(&[] as &[String], |index| index.anchor_literals());
        #[cfg(feature = "gpu")]
        let confirmed_anchor_literal_count = confirmed_anchor_literals.len();
        #[cfg(feature = "gpu")]
        let generic_keyword_literals =
            crate::engine::phase2_generic::keywords::generic_keyword_prefilter_stems()
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
        #[cfg(feature = "gpu")]
        let generic_keyword_literal_count = generic_keyword_literals.len();
        let gated = ac_suffix_gate.iter().filter(|g| !g.is_empty()).count();
        #[cfg(feature = "gpu")]
        let gpu_literals = if gpu_backends.availability().any() {
            let phase2_always_anchor_literals = phase2_anchor_index
                .as_ref()
                .map_or(&[] as &[String], |index| index.always_anchor_literals());
            build_gpu_literals(
                &state.ac_literals,
                &phase2_keywords,
                phase2_always_anchor_literals,
                confirmed_anchor_literals,
                &generic_keyword_literals,
            )
        } else {
            None
        };
        #[cfg(not(feature = "gpu"))]
        let gpu_literals: Option<Arc<Vec<Vec<u8>>>> = None;
        #[cfg(feature = "gpu")]
        let gpu_max_literal_len = gpu_literals.as_ref().map_or(0, |literals| {
            literals
                .iter()
                .fold(0, |longest, literal| longest.max(literal.len()))
        });

        // Combined-RegexSet prefilter over EVERY always-active phase-2 pattern. The
        // plain (homoglyph-variant) batches carry a fast ASCII-folded alternate
        // RegexSet (the homoglyph regex with non-ASCII stripped); on a pure-ASCII
        // chunk it is match-equivalent to the slow unicode-class form, so the
        // prefilter marks the IDENTICAL set in the IDENTICAL order, recall and
        // active-set order unchanged, but far faster (the homoglyph unicode
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

        // Pre-intern detector metadata strings into the shared
        // hash so per-scan `intern_metadata` calls hand out shared
        // `Arc<str>` without touching the global allocator. Built
        // once per scanner; lock-free on read.
        let static_intern_strings: Vec<&str> = detectors
            .iter()
            .flat_map(|detector| {
                [
                    detector.id.as_str(),
                    detector.name.as_str(),
                    detector.service.as_str(),
                ]
                .into_iter()
                .chain(
                    detector
                        .entropy_fallback
                        .as_ref()
                        .into_iter()
                        .flat_map(|metadata| {
                            [
                                metadata.id.as_str(),
                                metadata.name.as_str(),
                                metadata.service.as_str(),
                            ]
                        }),
                )
            })
            .collect();
        let static_intern = Arc::new(crate::static_intern::StaticInterner::from_detector_strings(
            static_intern_strings,
        ));

        let detector_plans = crate::detector_plan::CompiledDetectorPlans::compile(
            &detectors,
            static_intern.as_ref(),
            state.companions,
        )
        .map_err(crate::error::ScanError::Config)?;

        // Pre-resolve the detector-wide weak-anchor base once. The per-pattern
        // bit is compiled beside its regex, so mixed detectors protect only the
        // patterns that declare the policy. Built before `detectors` is moved.
        let missing_weak_anchor_floors = detectors
            .iter()
            .enumerate()
            .filter_map(|(index, detector)| {
                let has_weak_pattern = match detector_plans.get(index).weak_anchor_base {
                    crate::suppression::WeakAnchorBase::Always => true,
                    crate::suppression::WeakAnchorBase::PerPattern => {
                        detector.patterns.iter().any(|pattern| pattern.weak_anchor)
                    }
                    crate::suppression::WeakAnchorBase::Never => false,
                };
                (has_weak_pattern && detector_plans.get(index).entropy_floor.is_none())
                    .then_some(detector.id.as_str())
            })
            .collect::<Vec<_>>();
        if !missing_weak_anchor_floors.is_empty() {
            return Err(crate::error::ScanError::Config(format!(
                "weak-anchor detectors omit detector-local entropy_high/entropy_floor policy: {}",
                missing_weak_anchor_floors.join(", ")
            )));
        }
        let generic_named_assignment_keywords =
            crate::generic_keyword_owner::build_generic_named_assignment_keywords(&detectors);
        let mut generic_assignment_max_len = None;
        for detector in detectors
            .iter()
            .filter(|detector| detector.owns_entropy_policy())
        {
            let max_len = detector.max_len.ok_or_else(|| {
                crate::error::ScanError::Config(format!(
                    "generic entropy owner {:?} omits max_len; declare it in the detector TOML",
                    detector.id
                ))
            })?;
            generic_assignment_max_len = Some(
                generic_assignment_max_len.map_or(max_len, |current: usize| current.max(max_len)),
            );
        }
        let mut generic_keyword_stems = None;
        let mut generic_gpu_positions_compatible = false;
        let generic_assignment_re = if let Some(max_len) = generic_assignment_max_len {
            let keywords = crate::assignment_keywords::derive_assignment_keywords(&detectors)
                .map_err(crate::error::ScanError::Config)?;
            let vendor_fallback_owners = detectors
                .iter()
                .filter(|detector| detector.generic_vendor_suffix_fallback)
                .count();
            if vendor_fallback_owners > 1 {
                return Err(crate::error::ScanError::Config(
                    "multiple detectors declare generic_vendor_suffix_fallback; exactly one detector may own the structural vendor-suffix arm"
                        .to_string(),
                ));
            }
            let include_vendor_fallback = vendor_fallback_owners == 1;
            generic_gpu_positions_compatible =
                keywords.as_slice() == crate::assignment_keywords::assignment_keywords();
            generic_keyword_stems = Some(
                crate::engine::phase2_generic::keywords::GenericKeywordStemSet::compile(
                    keywords
                        .iter()
                        .map(String::as_str)
                        .chain(include_vendor_fallback.then_some("key")),
                ),
            );
            let alternation = crate::engine::phase2_generic::generic_keyword_alternation_from_with_vendor_fallback(
                &keywords,
                include_vendor_fallback,
            );
            Some(
                crate::engine::phase2_generic::compile_generic_re_with_max(
                    &alternation,
                    max_len,
                )
                .map_err(|error| {
                    crate::error::ScanError::Config(format!(
                        "cannot compile the detector-owned generic assignment bridge: {error}. Fix the phase-2 generic detector keywords and max_len values"
                    ))
                })?,
            )
        } else {
            None
        };
        let generic_owning_detector =
            crate::generic_keyword_owner::GenericOwningDetectorIndex::build(&detectors)
                .map_err(crate::error::ScanError::Config)?;
        // Resolve the detector-owned hot-prefix table once, then mark its exact
        // confirmed delegates. Limiting suppression to the delegate is
        // recall-safe when one detector has overlapping regexes at one offset.
        #[cfg(feature = "simdsieve")]
        let hot_pattern_slots = build_hot_pattern_slots(&detectors, &state.ac_map)?;
        #[cfg(feature = "simdsieve")]
        let hot_confirmed_by_pattern = {
            let mut hot = vec![false; state.ac_map.len()];
            for slot in &hot_pattern_slots {
                hot[slot.ac_map_index] = true;
            }
            hot
        };
        #[cfg(not(feature = "simdsieve"))]
        let hot_confirmed_by_pattern = vec![false; state.ac_map.len()];

        let pattern_boundary_context = derive_pattern_boundary_context(
            state
                .ac_map
                .iter()
                .chain(state.phase2_patterns.iter().map(|(pattern, _)| pattern)),
        );
        #[cfg(feature = "gpu")]
        let ac_match_upper_bounds: Vec<Option<usize>> = state
            .ac_map
            .iter()
            .map(|pattern| regex_match_byte_upper_bound(pattern.regex.as_str()))
            .collect();

        let scanner = Self {
            ac,
            gpu_backends,
            gpu_acquisition_failures,
            gpu_literals,
            #[cfg(feature = "gpu")]
            gpu_max_literal_len,
            gpu_matcher: OnceLock::new(),
            #[cfg(feature = "gpu")]
            gpu_resident_literal_cuda: std::sync::Mutex::new(GpuResidentLiteralSlot::Empty),
            #[cfg(feature = "gpu")]
            gpu_resident_literal_wgpu: std::sync::Mutex::new(GpuResidentLiteralSlot::Empty),
            gpu_last_degrade_reason: std::sync::Mutex::new(None),
            gpu_degrade_count: std::sync::atomic::AtomicU64::new(0),
            autoroute_gpu_shared_cold_ns: std::sync::atomic::AtomicU64::new(0),
            static_intern,
            detector_plans,
            generic_named_assignment_keywords,
            generic_assignment_re,
            generic_keyword_stems,
            generic_gpu_positions_compatible,
            generic_owning_detector,
            #[cfg(feature = "gpu")]
            ac_match_upper_bounds,
            suffix_gate_ac,
            ac_suffix_gate,
            hot_confirmed_by_pattern,
            confirmed_anchor_index,
            ac_map: state.ac_map,
            pattern_boundary_context,
            prefix_propagation,
            phase2_patterns: state.phase2_patterns,
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
            phase2_gpu_dfa: Phase2GpuDfaCatalogCache::default(),
            tuning: phase2::ScannerTuning::from_defaults(),
            #[cfg(feature = "simd")]
            simd_prefilter,
            #[cfg(feature = "simd")]
            hs_index_map,
            #[cfg(feature = "simdsieve")]
            hot_pattern_slots,
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
    pub fn with_tuning_config(self, config: ScannerTuningConfig) -> Self {
        self.tuning.apply_config(&config);
        self
    }
}

#[cfg(all(target_os = "linux", feature = "gpu"))]
fn linux_cuda_runtime_identity() -> std::result::Result<String, String> {
    let version = std::fs::read_to_string("/proc/driver/nvidia/version")
        .map_err(|error| format!("cannot read /proc/driver/nvidia/version: {error}"))?;
    let version = version.split_whitespace().collect::<Vec<_>>().join(" ");
    if version.is_empty() {
        Err("/proc/driver/nvidia/version contains no runtime identity".to_owned())
    } else {
        Ok(format!("nvidia-kernel:{version}"))
    }
}
