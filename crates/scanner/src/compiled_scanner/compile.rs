#[cfg(all(target_os = "linux", feature = "gpu"))]
use super::compile_helpers::surface_cuda_acquisition_failure;
#[cfg(feature = "simdsieve")]
use super::compile_helpers::{build_hot_pattern_slots, StreamingHotPatternSlots};
use super::*;
use crate::compiler::compiler_build::CompileState;
#[cfg(feature = "simd")]
type PackedSimdProgram = crate::execution_pack::HyperscanSimdExecutionProgram;
#[cfg(not(feature = "simd"))]
type PackedSimdProgram = ();
#[allow(dead_code)]
struct PackedVyreProgramSource<'a> {
    bytes: &'a [u8],
    pack_identity: crate::execution_pack::ExecutionPackIdentity,
    signature_authenticated: bool,
}

struct PackedDetectorPlanPrelude<'a> {
    detector_ids: Vec<Arc<str>>,
    static_intern: Arc<crate::static_intern::StaticInterner>,
    decoder_plan: Arc<crate::decode::CompiledDecoderPlan>,
    detector_ir_digest: [u8; 32],
    compiled_plan_digest: [u8; 32],
    detector_count: usize,
    section_bytes: &'a [u8],
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
                        // LAW10: missing CUDA runtime identity is already warned and retained as unavailable provenance.
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
                    probe.device_identity.clone(),
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
    #[cfg(feature = "gpu")]
    {
        peer
    }
}

impl CompiledScanner {
    /// Compile the deterministic scalar library route. Hardware autoroute is an
    /// installer/runtime concern and must select a route before construction.
    pub fn compile(detectors: Vec<DetectorSpec>) -> Result<Self> {
        Self::compile_for_backend(detectors, crate::hw_probe::ScanBackend::CpuFallback)
    }

    /// Compile using the resolved scanner runtime GPU policy.
    pub fn compile_with_runtime_policy(detectors: Vec<DetectorSpec>) -> Result<Self> {
        Self::compile_with_gpu_policy(detectors, GpuInitPolicy::FromRuntimePolicy)
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
            None,
            None,
            true,
        )
    }

    /// Hydrate a scanner from an already-decoded [`CompileState`].
    ///
    /// Used by the MatcherArtifact cache hit path and by miss-path hydration
    /// after a freshly compiled artifact is persisted, so eager construction
    /// runs at most once per miss.
    pub(crate) fn compile_shared_from_compile_state(
        detectors: Arc<[DetectorSpec]>,
        gpu_policy: GpuInitPolicy,
        tuning_config: &ScannerTuningConfig,
        state: crate::compiler::compiler_build::CompileState,
    ) -> Result<Self> {
        Self::compile_shared_with_state_source(
            detectors,
            gpu_policy,
            tuning_config,
            Some(state),
            None,
            None,
            None,
            None,
            true,
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
            None,
            None,
            false,
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
        Self::compile_from_execution_pack_with_gpu_policy_and_tuning(
            pack,
            GpuInitPolicy::SelectedBackend(execution_backend(pack.identity().backend)),
            tuning_config,
        )
    }

    /// Construct a tuned scanner directly from a mapped execution pack while
    /// preserving the caller's already-resolved GPU initialization policy.
    pub fn compile_from_execution_pack_with_gpu_policy_and_tuning(
        pack: &crate::execution_pack::ExecutionPack,
        gpu_policy: GpuInitPolicy,
        tuning_config: &ScannerTuningConfig,
    ) -> Result<Self> {
        use crate::execution_pack::ExecutionPackSectionKind as Section;
        let bytes = pack.section(Section::DetectorPlan).ok_or_else(|| {
            crate::error::ScanError::Config(
                "execution pack is missing required detector-plan section".to_owned(),
            )
        })?;
        let mut detector_ids = Vec::new();
        let mut static_intern =
            crate::static_intern::StaticInternerBuilder::with_capacity(bytes.len() / 1024);
        let header = crate::execution_pack::CompiledDetectorPlanSection::stream_prelude_records(
            bytes,
            pack.identity().detector_digest,
            |_, record| {
                let id = static_intern.intern(record.id);
                detector_ids.push(Arc::clone(&id));
                static_intern.intern(record.name);
                static_intern.intern(record.service);
                if let Some(metadata) = record.entropy_fallback {
                    static_intern.intern(metadata.id);
                    static_intern.intern(metadata.name);
                    static_intern.intern(metadata.service);
                }
                for name in record.companion_names {
                    static_intern.intern(name);
                }
                Ok(id)
            },
        )
        .map_err(|error| crate::error::ScanError::Config(error.to_string()))?;
        let prelude = PackedDetectorPlanPrelude {
            detector_ids,
            static_intern: Arc::new(static_intern.finish()),
            decoder_plan: header.decoder_plan,
            detector_ir_digest: header.detector_ir_digest,
            compiled_plan_digest: header.compiled_plan_digest,
            detector_count: header.detector_count,
            section_bytes: bytes,
        };
        Self::compile_shared_matchers_from_execution_pack_with_gpu_policy_and_tuning_inner(
            Vec::<DetectorSpec>::new().into(),
            pack,
            gpu_policy,
            tuning_config,
            None,
            Some(prelude),
        )
    }

    /// Construct a tuned scanner and return the exact shared detector corpus decoded from it.
    pub fn compile_from_execution_pack_with_tuning_and_detectors(
        pack: &crate::execution_pack::ExecutionPack,
        tuning_config: &ScannerTuningConfig,
    ) -> Result<(Self, Arc<[DetectorSpec]>)> {
        use crate::execution_pack::ExecutionPackSectionKind as Section;

        let section_bytes = pack.section(Section::DetectorPlan).ok_or_else(|| {
            crate::error::ScanError::Config(
                "execution pack is missing required detector-plan section".to_owned(),
            )
        })?;
        let (detectors, header) =
            crate::execution_pack::CompiledDetectorPlanSection::decode_schema(
                section_bytes,
                pack.identity().detector_digest,
            )
            .map_err(|error| crate::error::ScanError::Config(error.to_string()))?;
        if header.detector_ir_digest != pack.identity().detector_digest {
            return Err(crate::error::ScanError::Config(
                "execution pack detector plan identity does not match its header".to_owned(),
            ));
        }
        let scanner =
            Self::compile_shared_matchers_from_execution_pack_with_gpu_policy_and_tuning_inner(
                Arc::clone(&detectors),
                pack,
                GpuInitPolicy::SelectedBackend(execution_backend(pack.identity().backend)),
                tuning_config,
                Some((header.decoder_plan, header.compiled_plan_digest)),
                None,
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
        Self::compile_shared_matchers_from_execution_pack_with_gpu_policy_and_tuning_inner(
            detectors,
            pack,
            gpu_policy,
            tuning_config,
            None,
            None,
        )
    }

    fn compile_shared_matchers_from_execution_pack_with_gpu_policy_and_tuning_inner(
        detectors: Arc<[DetectorSpec]>,
        pack: &crate::execution_pack::ExecutionPack,
        gpu_policy: GpuInitPolicy,
        tuning_config: &ScannerTuningConfig,
        decoder_plan: Option<(Arc<crate::decode::CompiledDecoderPlan>, [u8; 32])>,
        packed_detector_plan: Option<PackedDetectorPlanPrelude>,
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
        if !pack.signature_authenticated() {
            if pack
                .digest_mapped_bytes_and_release(section(Section::DetectorIr)?)
                .map_err(|error| crate::error::ScanError::Config(error.to_string()))?
                != identity.detector_digest
            {
                return Err(crate::error::ScanError::Config(
                    "execution pack DetectorIr identity does not match its header".to_owned(),
                ));
            }
        }
        let backend_program = section(Section::BackendProgram)?;
        if !pack.signature_authenticated() {
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
        }
        let packed_simd_program: Option<PackedSimdProgram> = match identity.backend {
            crate::execution_pack::ExecutionPackBackend::Cpu => {
                let decoded = if pack.signature_authenticated() {
                    crate::execution_pack::ScalarCpuExecutionProgram::decode_authenticated(
                        backend_program,
                        identity.detector_digest,
                    )
                } else {
                    crate::execution_pack::ScalarCpuExecutionProgram::decode(
                        backend_program,
                        identity.detector_digest,
                    )
                };
                decoded.map_err(|error| crate::error::ScanError::Config(error.to_string()))?;
                None
            }
            crate::execution_pack::ExecutionPackBackend::Simd => {
                #[cfg(feature = "simd")]
                {
                    let decoded = if pack.signature_authenticated() {
                        crate::execution_pack::HyperscanSimdExecutionProgram::
                            decode_authenticated_mapped_with_release(
                                backend_program,
                                identity.detector_digest,
                                |bytes| pack.mapped_bytes(bytes),
                                |bytes| pack.release_mapped_bytes(bytes),
                            )
                    } else {
                        crate::execution_pack::HyperscanSimdExecutionProgram::
                            decode_mapped_with_release(
                                backend_program,
                                identity.detector_digest,
                                |bytes| pack.mapped_bytes(bytes),
                                |bytes| pack.release_mapped_bytes(bytes),
                            )
                    };
                    Some(
                        decoded
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
            signature_authenticated: pack.signature_authenticated(),
        });
        let state =
            if let Some(prelude) = packed_detector_plan.as_ref() {
                let detector_ids = prelude
                    .detector_ids
                    .iter()
                    .map(Arc::as_ref)
                    .collect::<Vec<_>>();
                if pack.signature_authenticated() {
                    crate::execution_pack::matcher_sections::
                    decode_authenticated_compile_state_sections_from_ids(
                        identity.backend,
                        section(Section::LiteralIndex)?,
                        section(Section::RegexPrograms)?,
                        section(Section::SuppressionPolicy)?,
                        identity.detector_digest,
                        &detector_ids,
                    )
                } else {
                    crate::execution_pack::matcher_sections::decode_compile_state_sections_from_ids(
                        identity.backend,
                        section(Section::LiteralIndex)?,
                        section(Section::RegexPrograms)?,
                        section(Section::SuppressionPolicy)?,
                        identity.detector_digest,
                        &detector_ids,
                    )
                }
            } else {
                if pack.signature_authenticated() {
                    crate::execution_pack::matcher_sections::
                    decode_authenticated_compile_state_sections(
                        identity.backend,
                        section(Section::LiteralIndex)?,
                        section(Section::RegexPrograms)?,
                        section(Section::SuppressionPolicy)?,
                        identity.detector_digest,
                        &detectors,
                    )
                } else {
                    crate::execution_pack::matcher_sections::decode_compile_state_sections(
                        identity.backend,
                        section(Section::LiteralIndex)?,
                        section(Section::RegexPrograms)?,
                        section(Section::SuppressionPolicy)?,
                        identity.detector_digest,
                        &detectors,
                    )
                }
            }
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
            decoder_plan,
            packed_detector_plan,
            false,
        )
    }

    fn compile_shared_with_state_source(
        detectors: Arc<[DetectorSpec]>,
        gpu_policy: GpuInitPolicy,
        tuning_config: &ScannerTuningConfig,
        packed_state: Option<CompileState>,
        mut packed_simd_program: Option<PackedSimdProgram>,
        packed_vyre_program: Option<PackedVyreProgramSource<'_>>,
        packed_decoder_plan: Option<(Arc<crate::decode::CompiledDecoderPlan>, [u8; 32])>,
        mut packed_detector_plan: Option<PackedDetectorPlanPrelude<'_>>,
        validate_live_detector_corpus: bool,
    ) -> Result<Self> {
        tuning_config
            .validate()
            .map_err(crate::error::ScanError::Config)?;
        // Fresh compiles and MatcherArtifact hydration supply full live
        // DetectorSpecs (including companion regexes). Authenticated
        // execution-pack schema reconstruction only fills companion names, so
        // the corpus quality gate must stay skipped there. Feature
        // compatibility (e.g. entropy-less builds refusing entropy-owning
        // detectors) still runs for every non-prelude path.
        if packed_detector_plan.is_none() {
            if validate_live_detector_corpus {
                super::validation::validate_detector_corpus(&detectors)
                    .map_err(crate::error::ScanError::Config)?;
            }
            crate::entropy::policy::validate_feature_compatibility(&detectors)
                .map_err(crate::error::ScanError::Config)?;
        }
        let packed_schema_digest = packed_decoder_plan.as_ref().map(|(_, digest)| *digest);
        let decoder_plan = match (
            packed_decoder_plan.map(|(plan, _)| plan),
            packed_detector_plan.as_ref(),
        ) {
            (Some(plan), _) => plan,
            (None, Some(prelude)) => Arc::clone(&prelude.decoder_plan),
            (None, None) => Arc::new(crate::decode::CompiledDecoderPlan::snapshot().map_err(
                |error| {
                    crate::error::ScanError::Config(format!("invalid decoder registry: {error}"))
                },
            )?),
        };
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
        let static_intern =
            if let Some(prelude) = packed_detector_plan.as_ref() {
                Arc::clone(&prelude.static_intern)
            } else {
                Arc::new(crate::static_intern::StaticInterner::from_detector_strings(
                    detectors.iter().flat_map(|detector| {
                        [
                            detector.id.as_str(),
                            detector.name.as_str(),
                            detector.service.as_str(),
                        ]
                        .into_iter()
                        .chain(detector.entropy_fallback.as_ref().into_iter().flat_map(
                            |metadata| {
                                [
                                    metadata.id.as_str(),
                                    metadata.name.as_str(),
                                    metadata.service.as_str(),
                                ]
                            },
                        ))
                        .chain(
                            detector
                                .companions
                                .iter()
                                .map(|companion| companion.name.as_str()),
                        )
                    }),
                ))
            };
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
        #[cfg(feature = "simdsieve")]
        let mut streamed_hot_pattern_slots = None;
        let (compiled_plan_digest, detector_plans, detector_count) =
            if let Some(prelude) = packed_detector_plan.take() {
                let mut companions = std::mem::take(&mut state.companions).into_iter();
                let mut builder =
                    crate::detector_plan::StreamingCompiledDetectorPlansBuilder::with_capacity(
                        prelude.detector_count,
                    );
                #[cfg(feature = "simdsieve")]
                let mut hot_slots = StreamingHotPatternSlots::new();
                let header = crate::execution_pack::CompiledDetectorPlanSection::stream_records(
                    prelude.section_bytes,
                    prelude.detector_ir_digest,
                    |index, record| {
                        #[cfg(feature = "simdsieve")]
                        hot_slots
                            .push(index, &record, &state.ac_map)
                            .map_err(|error| {
                                crate::execution_pack::ExecutionPackError::InvalidPack(
                                    error.to_string(),
                                )
                            })?;
                        let companion_row = companions.next().ok_or_else(|| {
                            crate::execution_pack::ExecutionPackError::InvalidPack(format!(
                                "detector-plan record {index} has no compiled companion row"
                            ))
                        })?;
                        builder
                            .push(record, companion_row, static_intern.as_ref())
                            .map_err(|error| {
                                crate::execution_pack::ExecutionPackError::InvalidPack(format!(
                                    "cannot hydrate detector-plan record {index}: {error}"
                                ))
                            })
                    },
                )
                .map_err(|error| crate::error::ScanError::Config(error.to_string()))?;
                if companions.next().is_some()
                    || header.detector_count != prelude.detector_count
                    || header.compiled_plan_digest != prelude.compiled_plan_digest
                    || header.decoder_plan.identity() != prelude.decoder_plan.identity()
                {
                    return Err(crate::error::ScanError::Config(
                        "detector-plan framing changed between ordered validation and hydration"
                            .to_owned(),
                    ));
                }
                let plans = builder
                    .finish(static_intern.as_ref(), header.decoder_plan)
                    .map_err(crate::error::ScanError::Config)?;
                #[cfg(feature = "simdsieve")]
                {
                    streamed_hot_pattern_slots = Some(hot_slots.finish());
                }
                (prelude.compiled_plan_digest, plans, prelude.detector_count)
            } else {
                // LAW10: unpacked development compilation computes the same canonical digest from exact detector and decoder inputs.
                let digest = packed_schema_digest.unwrap_or_else(|| {
                    super::detector_digest::from_execution_plan(
                        keyhog_core::compute_spec_hash(&detectors),
                        decoder_plan.identity(),
                    )
                });
                let plans = crate::detector_plan::CompiledDetectorPlans::compile_with_decoder_plan(
                    &detectors,
                    static_intern.as_ref(),
                    state.companions,
                    decoder_plan,
                )
                .map_err(crate::error::ScanError::Config)?;
                (digest, plans, detectors.len())
            };
        let detector_digest = super::detector_digest::projection(compiled_plan_digest);
        validate_compiled_pattern_detector_indices(
            &state.ac_map,
            &state.phase2_patterns,
            detector_count,
        )?;
        if packed_detector_plan.is_none() && !detectors.is_empty() {
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
                    (has_weak_pattern && detector_plans.entropy_floor(index).is_none())
                        .then_some(detector.id.as_str())
                })
                .collect::<Vec<_>>();
            if !missing_weak_anchor_floors.is_empty() {
                return Err(crate::error::ScanError::Config(format!(
                    "weak-anchor detectors omit detector-local entropy_high/entropy_floor policy: {}",
                    missing_weak_anchor_floors.join(", ")
                )));
            }
        }
        #[cfg(feature = "simdsieve")]
        let hot_pattern_slots = match streamed_hot_pattern_slots {
            Some(slots) => slots,
            None => build_hot_pattern_slots(&detectors, &state.ac_map)?,
        };
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
                    // LAW10: non-GPU builds consume the resolved policy only to keep cfg branches warning-free; no backend fallback occurs.
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
        let packed_confidence_authentication = packed_vyre_program
            .as_ref()
            .map(|source| source.signature_authenticated);
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
                        // LAW10: absent optional backend diagnostics use a loud operator-facing acquisition message.
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
            let backend_id = match source.pack_identity.backend {
                crate::execution_pack::ExecutionPackBackend::GpuCuda => Some("cuda"),
                crate::execution_pack::ExecutionPackBackend::GpuWgpu => Some("wgpu"),
                crate::execution_pack::ExecutionPackBackend::GpuMetal => Some("metal"),
                _ => None,
            };
            let installed = crate::gpu_literal_artifacts::install_compiled_gpu_literal_artifact(
                program.matcher_cache_key,
                program.matcher_pattern_count,
                &program.matcher_bytes,
            )?;
            Some((installed, program.phase2_catalog_bytes, backend_id))
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

        let (phase2_keyword_index, phase2_keyword_to_patterns, phase2_keywords) =
            build_phase2_keyword_index(&state.phase2_patterns);
        let phase2_keyword_count = phase2_keywords.len();
        // Precompute always-active phase-2 indices so the per-chunk hot path
        // seeds the sparse active set without scanning the full phase-2 table.
        let phase2_always_active_indices = phase2_always_active_indices(&state.phase2_patterns);
        let localization_hints = state.localization_hints.take();
        let (confirmed_prefixes, confirmed_suffixes, phase2_localization) = match localization_hints
        {
            Some(hints) => (
                Some(hints.confirmed_prefixes),
                Some(hints.confirmed_suffixes),
                Some(hints.phase2),
            ),
            None => (None, None, None),
        };
        let phase2_patterns = &state.phase2_patterns;
        let ac_map = &state.ac_map;

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
        let phase2_always_active_indices_ref = &phase2_always_active_indices;
        let (phase2_anchor_index, ((suffix_gate_ac, ac_suffix_gate), confirmed_anchor_index)) =
            rayon::join(
                move || {
                    Phase2AnchorIndex::build_with_hints(
                        phase2_patterns,
                        phase2_always_active_indices_ref,
                        phase2_localization,
                    )
                },
                move || {
                    rayon::join(
                        move || build_confirmed_suffix_gate_with_hints(ac_map, confirmed_suffixes),
                        move || ConfirmedAnchorIndex::build_with_hints(ac_map, confirmed_prefixes),
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
        let quantized_confidence_authenticated = selected_backend.map_or(true, |backend| {
            if !backend.is_gpu() {
                true
            } else if let Some(signature_authenticated) = packed_confidence_authentication {
                signature_authenticated && packed_gpu_artifact.is_some()
            } else {
                validate_live_detector_corpus
            }
        });
        #[cfg(not(feature = "gpu"))]
        let quantized_confidence_authenticated = true;
        #[cfg(feature = "gpu")]
        let (gpu_literals, packed_gpu_matcher, gpu_max_literal_len, phase2_gpu_dfa) =
            if let Some((artifact, phase2_catalog_bytes, backend_id)) = packed_gpu_artifact {
                tracing::debug!(
                    target: "keyhog::routing",
                    cache_key = %artifact.cache_key,
                    pattern_count = artifact.pattern_count,
                    "installed authenticated packed VYRE matcher"
                );
                let phase2_gpu_dfa = Phase2GpuDfaCatalogCache::from_artifact(
                    &state.phase2_patterns,
                    &phase2_always_active_indices,
                    backend_id,
                    &phase2_catalog_bytes,
                )
                .map_err(crate::error::ScanError::Config)?;
                (
                    None,
                    Some(artifact.matcher),
                    artifact.max_literal_len,
                    phase2_gpu_dfa,
                )
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
                (
                    literals,
                    None,
                    max_literal_len,
                    Phase2GpuDfaCatalogCache::default(),
                )
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
            #[cfg(feature = "gpu")]
            direct_gpu_resident_dispatch: std::sync::Mutex::new(()),
            quantized_confidence_authenticated,
            detector_digest,
            vocab_stage_absence_cache: dashmap::DashMap::with_hasher(ahash::RandomState::new()),
            entropy_config_digest_cache: parking_lot::Mutex::new(None),
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
            phase2_gpu_dfa,
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
                    phase2_keyword_index,
                },
            ),
            #[cfg(debug_assertions)]
            phase2_keyword_scanned_bytes: std::sync::atomic::AtomicU64::new(0),
            #[cfg(debug_assertions)]
            generic_keyword_scanned_bytes: std::sync::atomic::AtomicU64::new(0),
            #[cfg(debug_assertions)]
            phase2_prefilter_scanned_bytes: std::sync::atomic::AtomicU64::new(0),
            #[cfg(debug_assertions)]
            phase1_trigger_scanned_bytes: std::sync::atomic::AtomicU64::new(0),
            #[cfg(debug_assertions)]
            normalization_scanned_bytes: std::sync::atomic::AtomicU64::new(0),
            #[cfg(debug_assertions)]
            confirmed_pattern_scanned_bytes: std::sync::atomic::AtomicU64::new(0),
            #[cfg(debug_assertions)]
            entropy_scanned_bytes: std::sync::atomic::AtomicU64::new(0),
            #[cfg(debug_assertions)]
            multiline_admission_scanned_bytes: std::sync::atomic::AtomicU64::new(0),
            #[cfg(debug_assertions)]
            line_index_scanned_bytes: std::sync::atomic::AtomicU64::new(0),
            #[cfg(debug_assertions)]
            decoder_admission_scanned_bytes: std::sync::atomic::AtomicU64::new(0),
            #[cfg(debug_assertions)]
            direct_scan_absence_skipped_bytes: std::sync::atomic::AtomicU64::new(0),
            #[cfg(debug_assertions)]
            direct_scan_absence_batches: std::sync::atomic::AtomicU64::new(0),
            #[cfg(debug_assertions)]
            simd_phase2_tail_absence_skipped_bytes: std::sync::atomic::AtomicU64::new(0),
            #[cfg(feature = "simd")]
            reusable_simd_triggers: parking_lot::Mutex::new(
                crate::engine::ReusableSimdTriggerCache::default(),
            ),
            fragment_cache: crate::fragment_cache::FragmentCache::new(1000),
            reusable_phase1_evidence: parking_lot::Mutex::new(
                crate::engine::phase1_admission::ReusablePhase1EvidenceCache::default(),
            ),
        };

        scanner
            .tuning
            .apply_config(tuning_config)
            .map_err(crate::error::ScanError::Config)?;
        Ok(scanner)
    }

    /// Apply a custom configuration to the compiled scanner.
    pub fn with_config(mut self, config: ScannerConfig) -> Self {
        keyhog_profile::set_detail(config.profile_detail());
        self.config = config;
        *self.entropy_config_digest_cache.lock() = None;
        self
    }

    /// Apply explicit performance-route tuning to this compiled scanner.
    ///
    /// This compatibility method preserves the original infallible builder
    /// signature. Use [`Self::try_with_tuning_config`] when tuning comes from an
    /// untrusted or dynamically constructed source.
    ///
    /// # Panics
    ///
    /// Panics when `config` contains a value the runtime cannot represent.
    #[deprecated(note = "use try_with_tuning_config to handle invalid tuning")]
    pub fn with_tuning_config(self, config: ScannerTuningConfig) -> Self {
        self.try_with_tuning_config(config)
            .unwrap_or_else(|error| panic!("invalid scanner tuning configuration: {error}"))
    }

    /// Validate and apply explicit performance-route tuning.
    pub fn try_with_tuning_config(self, config: ScannerTuningConfig) -> Result<Self> {
        self.tuning
            .apply_config(&config)
            .map_err(crate::error::ScanError::Config)?;
        Ok(self)
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
