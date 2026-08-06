#[cfg(feature = "simdsieve")]
use super::compile_helpers::build_hot_pattern_slots;
#[cfg(all(target_os = "linux", feature = "gpu"))]
use super::compile_helpers::surface_cuda_acquisition_failure;
use super::*;
use crate::compiler::compiler_build::CompileState;
#[cfg(feature = "simd")]
type PackedSimdProgram = crate::execution_pack::HyperscanSimdExecutionProgram;
#[cfg(not(feature = "simd"))]
type PackedSimdProgram = ();
struct PackedVyreProgramSource<'a> {
    bytes: &'a [u8],
    pack_identity: crate::execution_pack::ExecutionPackIdentity,
}

fn selected_gpu_peer(backend: crate::hw_probe::ScanBackend) -> SelectedGpuPeer {
    let mut peer = SelectedGpuPeer::new(backend);
    #[cfg(not(feature = "gpu"))]
    {
        peer.mark_unavailable(format!(
            "{} is unavailable because this scanner was built without GPU support",
            backend.label()
        ));
        return peer;
    }
    #[cfg(feature = "gpu")]
    match backend {
        crate::hw_probe::ScanBackend::GpuCuda => {
            #[cfg(target_os = "linux")]
            match super::types::probe_cuda_peer() {
                Ok(caps) => {
                    let device_identity = format!(
                        "{}:ordinal={}:cc={}.{}:vram={}",
                        caps.name,
                        caps.ordinal,
                        caps.compute_capability.0,
                        caps.compute_capability.1,
                        caps.total_memory
                    );
                    let runtime_identity = linux_cuda_runtime_identity()
                        .map_err(|diagnostic| {
                            tracing::warn!(
                                target: "keyhog::routing",
                                %diagnostic,
                                "CUDA peer acquired without reproducible runtime identity"
                            );
                        })
                        .ok();
                    peer.mark_available(device_identity, runtime_identity, false);
                }
                Err(error) => {
                    surface_cuda_acquisition_failure(&error);
                    peer.mark_unavailable(error.to_string());
                }
            }
            #[cfg(not(target_os = "linux"))]
            peer.mark_unavailable(format!(
                "native CUDA peer acquisition is unavailable on {}; use WGPU or a supported Linux CUDA host",
                std::env::consts::OS
            ));
        }
        crate::hw_probe::ScanBackend::GpuMetal => {
            #[cfg(target_os = "macos")]
            match crate::gpu::gpu_adapter_probe() {
                Some(probe) => peer.mark_available(
                    probe.device_identity,
                    Some(format!(
                        "vyre-metal={};{}",
                        env!("KEYHOG_VYRE_METAL_VERSION"),
                        probe.runtime_identity
                    )),
                    false,
                ),
                None => peer
                    .mark_unavailable("native Metal adapter census found no adapters".to_string()),
            }
            #[cfg(not(target_os = "macos"))]
            peer.mark_unavailable(format!(
                "native Metal peer acquisition is unavailable on {}; use WGPU or a macOS host",
                std::env::consts::OS
            ));
        }
        crate::hw_probe::ScanBackend::GpuWgpu => match crate::gpu::gpu_adapter_probe() {
            Some(probe) => peer.mark_available(
                probe.device_identity.clone(),
                Some(probe.runtime_identity.clone()),
                probe.is_software,
            ),
            None => peer.mark_unavailable("WGPU adapter census found no adapters".to_string()),
        },
        _ => unreachable!("selected GPU peer requires a GPU backend"),
    }
    peer
}

impl CompiledScanner {
    /// Compile the deterministic scalar library route. Hardware autoroute is an
    /// installer/runtime concern and must select a route before construction.
    pub fn compile(detectors: Vec<DetectorSpec>) -> Result<Self> {
        Self::compile_for_backend(detectors, crate::hw_probe::ScanBackend::CpuFallback)
    }

    /// Compile only the backend selected before scanner construction.
    pub fn compile_for_backend(
        detectors: Vec<DetectorSpec>,
        backend: crate::hw_probe::ScanBackend,
    ) -> Result<Self> {
        Self::compile_with_gpu_policy(detectors, GpuInitPolicy::SelectedBackend(backend))
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
        Self::compile_shared_with_gpu_policy_and_tuning(detectors.into(), gpu_policy, tuning_config)
    }

    /// Compile from shared detector ownership without cloning the corpus.
    pub fn compile_shared_with_gpu_policy_and_tuning(
        detectors: Arc<[DetectorSpec]>,
        gpu_policy: GpuInitPolicy,
        tuning_config: &ScannerTuningConfig,
    ) -> Result<Self> {
        Self::compile_shared_with_state_source(
            detectors,
            gpu_policy,
            tuning_config,
            None,
            None,
            None,
        )
    }

    /// Construct a scanner from the canonical matcher graph compiled into an execution pack.
    pub fn compile_from_packed_matchers(
        detectors: Vec<DetectorSpec>,
        matchers: &crate::execution_pack::CompiledRouteMatcherSections,
    ) -> Result<Self> {
        Self::compile_shared_from_packed_matchers_with_tuning(
            detectors.into(),
            matchers,
            &ScannerTuningConfig::default(),
        )
    }

    /// Construct a tuned scanner without rebuilding detector routing or homoglyph state.
    pub fn compile_shared_from_packed_matchers_with_tuning(
        detectors: Arc<[DetectorSpec]>,
        matchers: &crate::execution_pack::CompiledRouteMatcherSections,
        tuning_config: &ScannerTuningConfig,
    ) -> Result<Self> {
        let state = matchers
            .decode_compile_state(&detectors)
            .map_err(|error| crate::error::ScanError::Config(error.to_string()))?;
        let backend = execution_backend(matchers.backend);
        Self::compile_shared_with_state_source(
            detectors,
            GpuInitPolicy::SelectedBackend(backend),
            tuning_config,
            Some(state),
            None,
            None,
        )
    }

    /// Construct a scanner directly from borrowed sections of a mapped execution pack.
    pub fn compile_from_execution_pack(
        pack: &crate::execution_pack::ExecutionPack,
    ) -> Result<Self> {
        Self::compile_from_execution_pack_with_tuning(pack, &ScannerTuningConfig::default())
    }

    /// Construct a tuned scanner directly from borrowed sections of a mapped execution pack.
    pub fn compile_from_execution_pack_with_tuning(
        pack: &crate::execution_pack::ExecutionPack,
        tuning_config: &ScannerTuningConfig,
    ) -> Result<Self> {
        Self::compile_from_execution_pack_with_tuning_and_detectors(pack, tuning_config)
            .map(|(scanner, _detectors)| scanner)
    }

    /// Construct a tuned scanner and return the exact shared detector corpus decoded from it.
    pub fn compile_from_execution_pack_with_tuning_and_detectors(
        pack: &crate::execution_pack::ExecutionPack,
        tuning_config: &ScannerTuningConfig,
    ) -> Result<(Self, Arc<[DetectorSpec]>)> {
        use crate::execution_pack::ExecutionPackSectionKind as Section;

        let detector_ir_bytes = pack.section(Section::DetectorIr).ok_or_else(|| {
            crate::error::ScanError::Config(
                "execution pack is missing required detector-ir section".to_owned(),
            )
        })?;
        let detector_ir =
            crate::execution_pack::CanonicalDetectorExecutionIr::decode(detector_ir_bytes)
                .map_err(|error| crate::error::ScanError::Config(error.to_string()))?;
        if detector_ir.digest() != pack.identity().detector_digest {
            return Err(crate::error::ScanError::Config(
                "execution pack DetectorIr identity does not match its header".to_owned(),
            ));
        }
        let detectors: Arc<[DetectorSpec]> = detector_ir.into_detectors().into();
        let scanner = Self::compile_shared_from_execution_pack_with_tuning(
            Arc::clone(&detectors),
            pack,
            tuning_config,
        )?;
        Ok((scanner, detectors))
    }

    /// Construct from a mapped pack while retaining an already decoded shared detector corpus.
    pub fn compile_shared_from_execution_pack_with_tuning(
        detectors: Arc<[DetectorSpec]>,
        pack: &crate::execution_pack::ExecutionPack,
        tuning_config: &ScannerTuningConfig,
    ) -> Result<Self> {
        Self::compile_shared_matchers_from_execution_pack_with_gpu_policy_and_tuning(
            detectors,
            pack,
            GpuInitPolicy::SelectedBackend(execution_backend(pack.identity().backend)),
            tuning_config,
        )
    }

    /// Hydrate route-neutral matchers from a mapped pack before autoroute selects a backend.
    pub fn compile_shared_matchers_from_execution_pack_with_gpu_policy_and_tuning(
        detectors: Arc<[DetectorSpec]>,
        pack: &crate::execution_pack::ExecutionPack,
        gpu_policy: GpuInitPolicy,
        tuning_config: &ScannerTuningConfig,
    ) -> Result<Self> {
        use crate::execution_pack::ExecutionPackSectionKind as Section;

        let identity = pack.identity();
        let section = |kind| {
            pack.section(kind).ok_or_else(|| {
                crate::error::ScanError::Config(format!(
                    "execution pack is missing required {kind} section"
                ))
            })
        };
        if pack
            .digest_mapped_bytes_and_release(section(Section::DetectorIr)?)
            .map_err(|error| crate::error::ScanError::Config(error.to_string()))?
            != identity.detector_digest
        {
            return Err(crate::error::ScanError::Config(
                "execution pack DetectorIr identity does not match its header".to_owned(),
            ));
        }
        let backend_program = section(Section::BackendProgram)?;
        let backend_identity_bytes = if identity.backend.is_gpu() {
            #[cfg(feature = "gpu")]
            {
                crate::execution_pack::VyreOrchestrationProgram::backend_section_receipt(
                    backend_program,
                    identity.backend,
                )
                .map_err(|error| crate::error::ScanError::Config(error.to_string()))?
            }
            #[cfg(not(feature = "gpu"))]
            {
                return Err(crate::error::ScanError::Config(
                    "execution pack selects GPU but this scanner was built without GPU support"
                        .to_owned(),
                ));
            }
        } else {
            backend_program
        };
        if pack
            .digest_mapped_bytes_and_release(backend_identity_bytes)
            .map_err(|error| crate::error::ScanError::Config(error.to_string()))?
            != identity.backend_digest
        {
            return Err(crate::error::ScanError::Config(
                "execution pack BackendProgram identity does not match its header".to_owned(),
            ));
        }
        let packed_simd_program: Option<PackedSimdProgram> = match identity.backend {
            crate::execution_pack::ExecutionPackBackend::Cpu => {
                crate::execution_pack::ScalarCpuExecutionProgram::decode(
                    backend_program,
                    identity.detector_digest,
                )
                .map_err(|error| crate::error::ScanError::Config(error.to_string()))?;
                None
            }
            crate::execution_pack::ExecutionPackBackend::Simd => {
                #[cfg(feature = "simd")]
                {
                    Some(
                        crate::execution_pack::HyperscanSimdExecutionProgram::
                            decode_mapped_with_release(
                                backend_program,
                                identity.detector_digest,
                                |bytes| pack.mapped_bytes(bytes),
                                |bytes| pack.release_mapped_bytes(bytes),
                            )
                        .map_err(|error| crate::error::ScanError::Config(error.to_string()))?,
                    )
                }
                #[cfg(not(feature = "simd"))]
                {
                    return Err(crate::error::ScanError::Config(
                        "execution pack selects SIMD but this scanner was built without SIMD support"
                            .to_owned(),
                    ));
                }
            }
            crate::execution_pack::ExecutionPackBackend::GpuCuda
            | crate::execution_pack::ExecutionPackBackend::GpuWgpu
            | crate::execution_pack::ExecutionPackBackend::GpuMetal => None,
        };
        let packed_vyre_program = identity.backend.is_gpu().then(|| PackedVyreProgramSource {
            bytes: backend_program,
            pack_identity: identity,
        });
        let state = crate::execution_pack::matcher_sections::decode_compile_state_sections(
            identity.backend,
            section(Section::LiteralIndex)?,
            section(Section::RegexPrograms)?,
            section(Section::SuppressionPolicy)?,
            identity.detector_digest,
            &detectors,
        )
        .map_err(|error| crate::error::ScanError::Config(error.to_string()))?;
        // Section decoders above now own every byte they retain. Drop the
        // immutable mapping's faulted pages before allocating runtime indexes,
        // otherwise large native programs overlap their decoded ownership at
        // the process high-water mark.
        pack.release_resident_pages()
            .map_err(|error| crate::error::ScanError::Config(error.to_string()))?;
        Self::compile_shared_with_state_source(
            detectors,
            gpu_policy,
            tuning_config,
            Some(state),
            packed_simd_program,
            packed_vyre_program,
        )
    }

    fn compile_shared_with_state_source(
        mut detectors: Arc<[DetectorSpec]>,
        gpu_policy: GpuInitPolicy,
        tuning_config: &ScannerTuningConfig,
        packed_state: Option<CompileState>,
        mut packed_simd_program: Option<PackedSimdProgram>,
        packed_vyre_program: Option<PackedVyreProgramSource<'_>>,
    ) -> Result<Self> {
        if packed_state.is_none() {
            super::validation::validate_detector_corpus(&detectors)
                .map_err(crate::error::ScanError::Config)?;
        }
        crate::entropy::policy::validate_feature_compatibility(&detectors)
            .map_err(crate::error::ScanError::Config)?;
        let decoder_plan = Arc::new(crate::decode::CompiledDecoderPlan::snapshot().map_err(
            |error| crate::error::ScanError::Config(format!("invalid decoder registry: {error}")),
        )?);
        // LAW10: cfg-only Hyperscan tuning marker; no runtime effect.
        #[cfg(not(feature = "simd"))]
        let (_tuning_config, _packed_simd_program) = (tuning_config, packed_simd_program);
        let mut state = match packed_state {
            Some(state) => state,
            None => build_compile_state(&detectors)?,
        };
        // Build the canonical detector execution plan before any backend
        // projection. Backends consume only derived matcher inputs from this
        // owner and never reinterpret detector TOML independently.
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
                .chain(
                    detector
                        .companions
                        .iter()
                        .map(|companion| companion.name.as_str()),
                )
            })
            .collect();
        let static_intern = Arc::new(crate::static_intern::StaticInterner::from_detector_strings(
            static_intern_strings,
        ));
        for companions in &mut state.companions {
            for companion in companions {
                companion.name =
                    static_intern
                        .lookup(companion.name.as_ref())
                        .ok_or_else(|| {
                            crate::error::ScanError::Config(format!(
                                "compiled companion name missing from static interner: {}",
                                companion.name
                            ))
                        })?;
            }
        }
        let compiled_plan_digest = super::detector_digest::from_execution_plan(
            keyhog_core::compute_spec_hash(&detectors),
            decoder_plan.identity(),
        );
        let detector_digest = super::detector_digest::projection(compiled_plan_digest);
        let detector_count = detectors.len();
        validate_compiled_pattern_detector_indices(
            &state.ac_map,
            &state.phase2_patterns,
            detector_count,
        )?;
        // Resolve the final schema-dependent validations before compact plan
        // compilation so a sole installed corpus can be drained row by row.
        let missing_weak_anchor_floors = detectors
            .iter()
            .filter_map(|detector| {
                let has_weak_pattern = match crate::suppression::detector_weak_anchor_base(detector)
                {
                    crate::suppression::WeakAnchorBase::Always => true,
                    crate::suppression::WeakAnchorBase::PerPattern => {
                        detector.patterns.iter().any(|pattern| pattern.weak_anchor)
                    }
                    crate::suppression::WeakAnchorBase::Never => false,
                };
                (has_weak_pattern && detector.entropy_floor.is_empty())
                    .then_some(detector.id.as_str())
            })
            .collect::<Vec<_>>();
        if !missing_weak_anchor_floors.is_empty() {
            return Err(crate::error::ScanError::Config(format!(
                "weak-anchor detectors omit detector-local entropy_high/entropy_floor policy: {}",
                missing_weak_anchor_floors.join(", ")
            )));
        }
        drop(missing_weak_anchor_floors);
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

        let detector_plans = if let Some(detectors) = Arc::get_mut(&mut detectors) {
            crate::detector_plan::CompiledDetectorPlans::compile_draining_with_decoder_plan(
                detectors,
                static_intern.as_ref(),
                state.companions,
                decoder_plan,
            )
        } else {
            crate::detector_plan::CompiledDetectorPlans::compile_with_decoder_plan(
                &detectors,
                static_intern.as_ref(),
                state.companions,
                decoder_plan,
            )
        }
        .map_err(crate::error::ScanError::Config)?;
        drop(detectors);
        let ac = if matches!(
            gpu_policy,
            GpuInitPolicy::SelectedBackend(crate::hw_probe::ScanBackend::SimdCpu)
        ) {
            None
        } else {
            build_ac_pattern_set(&state.ac_literals)?
        };
        // GPU is unconditional in the build; runtime probe decides whether to
        // actually use it. `gpu_available` is set by hw_probe based on adapter
        // detection (excluding software renderers like llvmpipe/lavapipe).
        // Census every compiled GPU driver independently without retaining an
        // execution device. Persisted autoroute evidence chooses the exact
        // peer for each workload; the selected peer is materialized lazily at
        // the dispatch boundary, while calibration materializes every peer it
        // measures.
        // `crate::gpu::gpu_disabled_by_policy()` is the single source of truth
        // for "skip every GPU init path". The value comes from the resolved
        // scanner runtime policy set by the CLI/TOML layer, not ambient process
        // environment.
        let gpu_disabled = match gpu_policy {
            GpuInitPolicy::FromRuntimePolicy => crate::gpu::gpu_disabled_by_policy(),
            GpuInitPolicy::ForceEnabled => false,
            GpuInitPolicy::SelectedBackend(backend) => !backend.is_gpu(),
            GpuInitPolicy::ForceDisabled => true,
        };
        let selected_backend = match gpu_policy {
            GpuInitPolicy::SelectedBackend(backend) => Some(backend),
            _ => None,
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
        let backend_state = match gpu_policy {
            GpuInitPolicy::SelectedBackend(backend) if backend.is_gpu() => {
                ScannerBackendState::SelectedGpu {
                    peer: selected_gpu_peer(backend),
                    #[cfg(feature = "gpu")]
                    resident_literal: std::sync::Mutex::new(GpuResidentLiteralSlot::Empty),
                }
            }
            GpuInitPolicy::SelectedBackend(backend) => ScannerBackendState::SelectedHost(backend),
            GpuInitPolicy::ForceDisabled => ScannerBackendState::Disabled,
            GpuInitPolicy::FromRuntimePolicy | GpuInitPolicy::ForceEnabled => {
                #[cfg(feature = "gpu")]
                let (peers, failures) = {
                    let mut peers = GpuBackendPeers::default();
                    let mut failures = Vec::new();
                    if !gpu_disabled {
                        #[cfg(not(target_os = "linux"))]
                        failures.push(GpuBackendAcquisitionFailure {
                            backend: "cuda",
                            diagnostic: format!(
                                "native CUDA peer acquisition is unavailable on {}; use WGPU or a supported Linux CUDA host",
                                std::env::consts::OS
                            ),
                        });
                        #[cfg(not(target_os = "macos"))]
                        failures.push(GpuBackendAcquisitionFailure {
                            backend: "metal",
                            diagnostic: format!(
                                "native Metal peer acquisition is unavailable on {}; use WGPU or a macOS host",
                                std::env::consts::OS
                            ),
                        });
                        #[cfg(target_os = "linux")]
                        match super::types::probe_cuda_peer() {
                            Ok(caps) => {
                                peers.cuda_available = true;
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
                                tracing::debug!(
                                    target: "keyhog::routing",
                                    "CUDA peer identity probed"
                                );
                            }
                            Err(error) => {
                                surface_cuda_acquisition_failure(&error);
                                failures.push(GpuBackendAcquisitionFailure {
                                    backend: "cuda",
                                    diagnostic: error.to_string(),
                                });
                            }
                        }
                        if let Some(probe) = crate::gpu::gpu_adapter_probe() {
                            peers.wgpu_available = true;
                            peers.wgpu_device_identity = Some(probe.device_identity.clone());
                            peers.wgpu_runtime_identity = Some(probe.runtime_identity.clone());
                            peers.wgpu_is_software = probe.is_software;
                            #[cfg(target_os = "macos")]
                            {
                                peers.metal_available = true;
                                peers.metal_device_identity = Some(probe.device_identity.clone());
                                peers.metal_runtime_identity = Some(format!(
                                    "vyre-metal={};{}",
                                    env!("KEYHOG_VYRE_METAL_VERSION"),
                                    probe.runtime_identity
                                ));
                                tracing::debug!(
                                    target: "keyhog::routing",
                                    "native Metal peer identity probed"
                                );
                            }
                            tracing::debug!(
                                target: "keyhog::routing",
                                "WGPU peer identity probed"
                            );
                        } else {
                            failures.push(GpuBackendAcquisitionFailure {
                                backend: "wgpu",
                                diagnostic: "WGPU adapter census found no adapters".to_string(),
                            });
                            #[cfg(target_os = "macos")]
                            failures.push(GpuBackendAcquisitionFailure {
                                backend: "metal",
                                diagnostic: "native Metal adapter census found no adapters"
                                    .to_string(),
                            });
                        }
                    }
                    (peers, failures)
                };
                #[cfg(not(feature = "gpu"))]
                let (peers, failures) = {
                    let _ = gpu_disabled;
                    (GpuBackendPeers::default(), Vec::new())
                };
                ScannerBackendState::Census {
                    peers,
                    failures,
                    #[cfg(feature = "gpu")]
                    resident_literal_cuda: std::sync::Mutex::new(GpuResidentLiteralSlot::Empty),
                    #[cfg(feature = "gpu")]
                    resident_literal_metal: std::sync::Mutex::new(GpuResidentLiteralSlot::Empty),
                    #[cfg(feature = "gpu")]
                    resident_literal_wgpu: std::sync::Mutex::new(GpuResidentLiteralSlot::Empty),
                }
            }
        };
        #[cfg(feature = "gpu")]
        let packed_gpu_artifact = if let Some(source) = packed_vyre_program {
            let selected = selected_backend
                .filter(|backend| backend.is_gpu())
                .ok_or_else(|| {
                    crate::error::ScanError::Config(
                        "a packed VYRE program requires its exact GPU backend to be selected"
                            .into(),
                    )
                })?;
            let expected_backend = execution_backend(source.pack_identity.backend);
            if selected != expected_backend {
                return Err(crate::error::ScanError::Config(format!(
                    "packed VYRE backend {:?} does not match selected backend {:?}",
                    source.pack_identity.backend, selected
                )));
            }
            backend_state.gpu_backend(selected).ok_or_else(|| {
                crate::error::ScanError::Config(format!(
                    "selected packed VYRE peer {selected:?} could not be acquired: {}",
                    backend_state
                        .gpu_backend_initialization_error(selected)
                        .unwrap_or("backend unavailable")
                ))
            })?;
            if !backend_state.gpu_backend_acquired(selected) {
                return Err(crate::error::ScanError::Config(format!(
                    "selected packed VYRE peer {selected:?} was not retained after acquisition"
                )));
            }
            if backend_state.gpu_backend_is_software(selected) {
                return Err(crate::error::ScanError::Config(format!(
                    "selected packed VYRE peer {selected:?} is a software adapter"
                )));
            }
            let runtime_identity = backend_state
                .gpu_backend_runtime_identity(selected)
                .ok_or_else(|| {
                    crate::error::ScanError::Config(format!(
                        "selected packed VYRE peer {selected:?} has no runtime identity"
                    ))
                })?;
            let device_identity = backend_state
                .gpu_backend_device_identity(selected)
                .ok_or_else(|| {
                    crate::error::ScanError::Config(format!(
                        "selected packed VYRE peer {selected:?} has no device identity"
                    ))
                })?;
            let hardware_identity = format!("{:?}", crate::hw_probe::probe_hardware());
            let expected_identity =
                crate::execution_pack::VyreExecutionIdentity::for_selected_peer(
                    source.pack_identity.backend,
                    source.pack_identity.target_digest,
                    &runtime_identity,
                    &device_identity,
                    &hardware_identity,
                )
                .map_err(|error| crate::error::ScanError::Config(error.to_string()))?;
            let program = crate::execution_pack::VyreOrchestrationProgram::decode_backend_section(
                &source.bytes,
                source.pack_identity.backend,
                source.pack_identity.detector_digest,
                &expected_identity,
            )
            .map_err(|error| crate::error::ScanError::Config(error.to_string()))?;
            Some(
                crate::gpu_literal_artifacts::install_compiled_gpu_literal_artifact(
                    program.matcher_cache_key,
                    program.matcher_pattern_count,
                    &program.matcher_bytes,
                )?,
            )
        } else {
            None
        };
        #[cfg(not(feature = "gpu"))]
        if packed_vyre_program.is_some() {
            return Err(crate::error::ScanError::Config(
                "execution pack selects VYRE GPU but this scanner was built without GPU support"
                    .into(),
            ));
        }

        let prefix_propagation = build_prefix_propagation(&state.ac_literals);
        let same_prefix_patterns = build_same_prefix_patterns(&state.ac_literals);

        #[cfg(feature = "simd")]
        let packed_phase2_scopes = packed_simd_program
            .as_mut()
            .map(|program| std::mem::take(&mut program.phase2_scopes));

        let (phase2_keyword_ac, phase2_keyword_to_patterns, phase2_keywords) =
            build_phase2_keyword_ac(&state.phase2_patterns);
        let phase2_keyword_count = phase2_keywords.len();
        // Precompute always-active phase-2 indices so the per-chunk hot path
        // seeds the sparse active set without scanning the full phase-2 table.
        let phase2_always_active_indices = phase2_always_active_indices(&state.phase2_patterns);

        // Three independent Aho-Corasick indices over the canonical compile
        // state. They share no mutable state and each is a pure function
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
        let generic_keyword_plan = detector_plans.generic_assignment();
        #[cfg(feature = "gpu")]
        let generic_keyword_literal_count =
            generic_keyword_plan.map_or(0, |plan| plan.stem_literals().count());
        let gated = ac_suffix_gate.iter().filter(|g| !g.is_empty()).count();
        #[cfg(feature = "gpu")]
        let (gpu_literals, packed_gpu_matcher, gpu_max_literal_len) =
            if let Some(artifact) = packed_gpu_artifact {
                tracing::debug!(
                    target: "keyhog::routing",
                    cache_key = %artifact.cache_key,
                    pattern_count = artifact.pattern_count,
                    "installed authenticated packed VYRE matcher"
                );
                (None, Some(artifact.matcher), artifact.max_literal_len)
            } else {
                let literals = if backend_state.gpu_availability().any() {
                    let phase2_always_anchor_literals = phase2_anchor_index
                        .as_ref()
                        .map_or(&[] as &[String], |index| index.always_anchor_literals());
                    build_gpu_literals(
                        state.ac_literals.iter().map(String::as_bytes),
                        phase2_keywords.iter().map(|keyword| keyword.as_bytes()),
                        phase2_always_anchor_literals.iter().map(String::as_bytes),
                        confirmed_anchor_literals.iter().map(String::as_bytes),
                        generic_keyword_plan
                            .into_iter()
                            .flat_map(|plan| plan.stem_literals())
                            .map(str::as_bytes),
                    )
                } else {
                    None
                };
                let max_literal_len = literals.as_ref().map_or(0, |literals| {
                    literals
                        .iter()
                        .fold(0, |longest, literal| longest.max(literal.len()))
                });
                (literals, None, max_literal_len)
            };
        #[cfg(not(feature = "gpu"))]
        let gpu_literals: Option<Arc<Vec<Vec<u8>>>> = None;

        // GPU literal planning is the final consumer. Release synthesized
        // keyword strings before compiling the remaining retained indexes.
        drop(phase2_keywords);

        // Compile one ownership plan for the always-active phase-2 set. The full
        // scope serves legacy extraction and admission; anchored extraction uses
        // residual scopes that omit patterns already owned by its localizers.
        // Hyperscan and portable RegexSet engines consume the same scopes lazily.
        let phase2_always_active_prefilter = phase2::Phase2AlwaysActivePrefilter::build(
            &state.phase2_patterns,
            &phase2_always_active_indices,
            phase2_anchor_index.as_ref(),
        );
        #[cfg(feature = "simd")]
        if let Some(programs) = packed_phase2_scopes {
            match &phase2_always_active_prefilter {
                Some(prefilter) => prefilter
                    .install_hyperscan_programs(&state.phase2_patterns, programs)
                    .map_err(crate::error::ScanError::Config)?,
                None => {
                    if programs.iter().any(|scope| {
                        !scope.pattern_indices.is_empty()
                            || scope.full.is_some()
                            || scope.ascii_lean.is_some()
                    }) {
                        return Err(crate::error::ScanError::Config(
                            "packed SIMD phase-two scopes are nonempty for a scanner with no always-active phase-two patterns".into(),
                        ));
                    }
                }
            }
        }
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
        drop(std::mem::take(&mut state.quality_warnings));

        let extra_keyword_count: usize = state
            .phase2_patterns
            .iter()
            .map(|(_, keywords)| keywords.len())
            .sum();
        let alphabet_target_count = state.ac_literals.len() + extra_keyword_count;
        let alphabet_screen = (alphabet_target_count > 0).then(|| {
            crate::alphabet_filter::AlphabetScreen::from_byte_slices(
                state.ac_literals.iter().map(String::as_bytes).chain(
                    state
                        .phase2_patterns
                        .iter()
                        .flat_map(|(_, keywords)| keywords.iter().map(String::as_bytes)),
                ),
            )
        });

        // Only direct AC alternatives belong to the selective literal gate.
        // Prefixless/dynamic phase-2 patterns stay in the explicit always-admit
        // no-hit lane and are evaluated even when this gate rejects.
        let bigram_bloom =
            crate::bigram_bloom::BigramBloom::from_literal_prefixes(&state.ac_literals);
        tracing::debug!(
            popcount = bigram_bloom.popcount(),
            "selective literal-anchor bloom built (65536 slots / 8 KB)"
        );
        // Development/custom corpora retain lazy compilation. An authenticated
        // SIMD pack instead owns exact native shards and canonical mappings.
        // Move the canonical literal allocation only after every route-neutral
        // index has consumed it; the lazy SIMD plan then shares one Arc owner
        // instead of cloning the complete table until first backend use.
        #[cfg(feature = "simd")]
        let simd_compile_plan = if selected_backend
            .is_none_or(|backend| backend == crate::hw_probe::ScanBackend::SimdCpu)
        {
            let ac_literals: std::sync::Arc<[String]> =
                std::mem::take(&mut state.ac_literals).into();
            match packed_simd_program {
                Some(program) => Some(
                    crate::engine::build_packed_simd_compile_plan(
                        program,
                        &state.ac_map,
                        std::sync::Arc::clone(&ac_literals),
                    )
                    .map_err(crate::error::ScanError::Config)?,
                ),
                None => build_simd_compile_plan(
                    &state.ac_map,
                    std::sync::Arc::clone(&ac_literals),
                    tuning_config,
                ),
            }
        } else {
            None
        };
        #[cfg(feature = "simd")]
        let simd_candidate_available = simd_compile_plan.is_some();

        // Exact CPU/GPU routes do not retain the canonical literal strings;
        // SIMD moved them into its lazy plan above. Release either residual
        // allocation before the retained scanner graph is finalized.
        drop(std::mem::take(&mut state.ac_literals));

        let pattern_boundary_context = derive_pattern_boundary_context(
            state
                .ac_map
                .iter()
                .chain(state.phase2_patterns.iter().map(|(pattern, _)| pattern)),
        );
        #[cfg(feature = "gpu")]
        let ac_match_upper_bounds = backend_state.gpu_availability().any().then(|| {
            state
                .ac_map
                .iter()
                .map(|pattern| regex_match_byte_upper_bound(pattern.regex.as_str()))
                .collect()
        });

        let structural_confirmed_patterns = CsrU32::from_pairs(
            detector_count,
            state
                .ac_map
                .iter()
                .enumerate()
                .filter_map(|(pattern_index, pattern)| {
                    pattern
                        .structural_password_slot
                        .then_some((pattern.detector_index, pattern_index))
                }),
        );
        let structural_phase2_patterns =
            CsrU32::from_pairs(
                detector_count,
                state.phase2_patterns.iter().enumerate().filter_map(
                    |(pattern_index, (pattern, _))| {
                        pattern
                            .structural_password_slot
                            .then_some((pattern.detector_index, pattern_index))
                    },
                ),
            );

        let gpu_matcher = OnceLock::new();
        #[cfg(feature = "gpu")]
        if let Some(matcher) = packed_gpu_matcher {
            if gpu_matcher.set(Some(matcher)).is_err() {
                unreachable!("new packed GPU matcher cell was already initialized");
            }
        }
        let scanner = Self {
            backend_state,
            detector_digest,
            compiled_plan_digest,
            ac,
            gpu_literals,
            #[cfg(feature = "gpu")]
            gpu_max_literal_len,
            gpu_matcher,
            gpu_last_degrade_reason: std::sync::Mutex::new(None),
            gpu_degrade_count: std::sync::atomic::AtomicU64::new(0),
            autoroute_gpu_shared_cold_ns: std::sync::atomic::AtomicU64::new(0),
            static_intern,
            detector_plans,
            assignment_keyword_matcher: std::sync::Mutex::new(
                crate::assignment_keyword_matcher::AssignmentKeywordMatcherCache::default(),
            ),
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
            structural_confirmed_patterns,
            structural_phase2_patterns,
            same_prefix_patterns,
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
            simd_candidate_available,
            #[cfg(feature = "simd")]
            simd_compile_plan: std::sync::Mutex::new(simd_compile_plan),
            #[cfg(feature = "simd")]
            simd_prefilter: std::sync::OnceLock::new(),
            #[cfg(feature = "simd")]
            simd_initialization_ns: std::sync::atomic::AtomicU64::new(0),
            #[cfg(feature = "simdsieve")]
            hot_pattern_slots,
            config: ScannerConfig::default(),
            route_classification: Arc::new(
                crate::engine::phase1_admission::RouteClassificationPlan {
                    alphabet_screen,
                    bigram_bloom,
                    phase2_keyword_ac,
                },
            ),
            fragment_cache: crate::fragment_cache::FragmentCache::new(1000),
        };

        Ok(scanner)
    }

    /// Apply a custom configuration to the compiled scanner.
    pub fn with_config(mut self, config: ScannerConfig) -> Self {
        keyhog_profile::set_detail(config.profile_detail());
        self.config = config;
        self
    }

    /// Apply explicit performance-route tuning to this compiled scanner.
    pub fn with_tuning_config(self, config: ScannerTuningConfig) -> Self {
        self.tuning.apply_config(&config);
        self
    }
}

#[cfg(all(test, feature = "simd"))]
mod tests {
    use super::*;
    use keyhog_core::{DetectorSpec, PatternSpec, Severity};

    fn detector() -> DetectorSpec {
        DetectorSpec {
            id: "selected-simd-index-owner".into(),
            name: "Selected SIMD Index Owner".into(),
            service: "test".into(),
            severity: Severity::Medium,
            patterns: vec![PatternSpec {
                regex: r"STATIC_SECRET_[0-9]+".into(),
                ..Default::default()
            }],
            ..crate::testing::named_detector_fixture_defaults()
        }
    }

    /// WHY: retaining the complete scalar automaton beside exact SIMD shards doubles phase-one matcher ownership and makes every single-chunk SIMD scan repeat the same trigger pass.
    #[test]
    fn exact_simd_scanner_omits_overlapping_scalar_literal_index() {
        let scanner = CompiledScanner::compile_for_backend(
            vec![detector()],
            crate::hw_probe::ScanBackend::SimdCpu,
        )
        .expect("compile exact SIMD scanner");

        assert!(
            scanner.ac.is_none(),
            "exact SIMD ownership is native shards plus unsupported-pattern recovery"
        );
    }

    /// WHY: GPU-only matcher rows and lazy matcher cells used to be populated by
    /// universal scanner construction even when autoroute had already selected
    /// a host backend, multiplying inactive buffers across concurrent scans.
    #[cfg(feature = "gpu")]
    #[test]
    fn exact_host_scanners_omit_gpu_matcher_buffers() {
        for backend in [
            crate::hw_probe::ScanBackend::CpuFallback,
            crate::hw_probe::ScanBackend::SimdCpu,
        ] {
            let scanner = CompiledScanner::compile_for_backend(vec![detector()], backend)
                .expect("compile exact host scanner");

            assert!(scanner.gpu_literals.is_none());
            assert!(scanner.gpu_matcher.get().is_none());
            assert!(scanner.ac_match_upper_bounds.is_none());
            assert_eq!(scanner.gpu_max_literal_len, 0);
            assert!(!scanner.backend_state.gpu_availability().any());
        }
    }

    /// WHY: detector and pattern partitions used to retain one inner vector per row even when almost every row was empty.
    #[test]
    fn scanner_relations_retain_only_flat_offset_tables() {
        let mut spec = detector();
        spec.keywords = vec!["credential".into()];
        spec.patterns[0].structural_password_slot = true;
        spec.patterns.push(PatternSpec {
            regex: r"[A-Za-z_]+[:=]([A-Z0-9]{16})".into(),
            group: Some(1),
            structural_password_slot: true,
            ..Default::default()
        });
        let scanner = CompiledScanner::compile_for_backend(
            vec![spec],
            crate::hw_probe::ScanBackend::CpuFallback,
        )
        .expect("compile compact relation fixture");

        let expected_confirmed = scanner
            .ac_map
            .iter()
            .enumerate()
            .filter_map(|(index, pattern)| pattern.structural_password_slot.then_some(index as u32))
            .collect::<Vec<_>>();
        let expected_phase2 = scanner
            .phase2_patterns
            .iter()
            .enumerate()
            .filter_map(|(index, (pattern, _))| {
                pattern.structural_password_slot.then_some(index as u32)
            })
            .collect::<Vec<_>>();

        assert_eq!(
            scanner.structural_confirmed_patterns.get(0),
            Some(expected_confirmed.as_slice())
        );
        assert_eq!(
            scanner.structural_phase2_patterns.get(0),
            Some(expected_phase2.as_slice())
        );
        assert_eq!(
            scanner.structural_confirmed_patterns.storage_lengths(),
            (expected_confirmed.len(), 2)
        );
        assert_eq!(
            scanner.structural_phase2_patterns.storage_lengths(),
            (expected_phase2.len(), 2)
        );
        assert_eq!(scanner.ac_suffix_gate.len(), scanner.ac_map.len());
        assert_eq!(
            scanner.ac_suffix_gate.storage_lengths().1,
            scanner.ac_map.len() + 1
        );
    }
}

fn execution_backend(
    backend: crate::execution_pack::ExecutionPackBackend,
) -> crate::hw_probe::ScanBackend {
    match backend {
        crate::execution_pack::ExecutionPackBackend::Cpu => {
            crate::hw_probe::ScanBackend::CpuFallback
        }
        crate::execution_pack::ExecutionPackBackend::Simd => crate::hw_probe::ScanBackend::SimdCpu,
        crate::execution_pack::ExecutionPackBackend::GpuCuda => {
            crate::hw_probe::ScanBackend::GpuCuda
        }
        crate::execution_pack::ExecutionPackBackend::GpuWgpu => {
            crate::hw_probe::ScanBackend::GpuWgpu
        }
        crate::execution_pack::ExecutionPackBackend::GpuMetal => {
            crate::hw_probe::ScanBackend::GpuMetal
        }
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
