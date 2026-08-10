use super::{
    compose_policy_execution_pack, BackendPlan, CanonicalDetectorExecutionIr,
    CompiledExecutionPack, ExecutionPackBackend, ExecutionPackError, ExecutionPackIdentity,
    ExecutionPackPolicy, ExecutionPackSignature, ExecutionPackSigningKey,
    PackFindingParityEvidence, PolicyPlanSections, ScalarCpuExecutionProgram,
};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledNativeBackendPrograms {
    cpu: Vec<u8>,
    #[cfg(feature = "simd")]
    simd: Vec<u8>,
}

impl CompiledNativeBackendPrograms {
    /// Compiles install-time native backend programs from the canonical detector IR.
    pub fn compile(detector_ir: &CanonicalDetectorExecutionIr) -> Result<Self, ExecutionPackError> {
        let cpu = ScalarCpuExecutionProgram::compile(detector_ir)?.canonical_bytes()?;
        #[cfg(feature = "simd")]
        let simd = super::simd_program::HyperscanSimdExecutionProgram::compile(detector_ir)?
            .canonical_bytes()?;
        Ok(Self {
            cpu,
            #[cfg(feature = "simd")]
            simd,
        })
    }

    pub fn artifacts(&self) -> Vec<BackendProgramArtifact<'_>> {
        #[allow(unused_mut)]
        let mut artifacts = vec![BackendProgramArtifact::Cpu(&self.cpu)];
        #[cfg(feature = "simd")]
        artifacts.push(BackendProgramArtifact::Simd(&self.simd));
        artifacts
    }

    pub fn cpu_bytes(&self) -> &[u8] {
        &self.cpu
    }

    #[cfg(feature = "simd")]
    pub fn simd_bytes(&self) -> &[u8] {
        &self.simd
    }
}

#[cfg(feature = "gpu")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledVyreBackendProgram {
    backend: ExecutionPackBackend,
    bytes: Vec<u8>,
}

#[cfg(feature = "gpu")]
impl CompiledVyreBackendProgram {
    pub fn compile(
        detector_ir: &CanonicalDetectorExecutionIr,
        backend: ExecutionPackBackend,
        execution_identity: super::VyreExecutionIdentity,
    ) -> Result<Self, ExecutionPackError> {
        let bytes =
            super::VyreOrchestrationProgram::compile(detector_ir, backend, execution_identity)?
                .canonical_bytes()?;
        Ok(Self { backend, bytes })
    }

    pub fn artifact(&self) -> BackendProgramArtifact<'_> {
        BackendProgramArtifact::VyreGpu {
            backend: self.backend,
            orchestration_receipt: &self.bytes,
        }
    }

    pub fn backend(&self) -> ExecutionPackBackend {
        self.backend
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PackGenerationIdentity {
    pub config_digest: [u8; 32],
    pub target_digest: [u8; 32],
    pub binary_digest: [u8; 32],
    pub feature_digest: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct BackendExecutionArtifact<'a> {
    pub program: BackendProgramArtifact<'a>,
    pub literal_index: &'a [u8],
    pub regex_programs: &'a [u8],
    pub suppression_policy: &'a [u8],
    pub finding_parity: PackFindingParityEvidence,
}

impl<'a> BackendExecutionArtifact<'a> {
    pub const fn new(
        program: BackendProgramArtifact<'a>,
        literal_index: &'a [u8],
        regex_programs: &'a [u8],
        suppression_policy: &'a [u8],
        finding_parity: PackFindingParityEvidence,
    ) -> Self {
        Self {
            program,
            literal_index,
            regex_programs,
            suppression_policy,
            finding_parity,
        }
    }

    pub const fn backend(&self) -> ExecutionPackBackend {
        self.program.backend()
    }
}

#[derive(Clone, Copy, Debug)]
pub enum BackendProgramArtifact<'a> {
    Cpu(&'a [u8]),
    Simd(&'a [u8]),
    VyreGpu {
        backend: ExecutionPackBackend,
        orchestration_receipt: &'a [u8],
    },
}

impl<'a> BackendProgramArtifact<'a> {
    pub const fn backend(self) -> ExecutionPackBackend {
        match self {
            Self::Cpu(_) => ExecutionPackBackend::Cpu,
            Self::Simd(_) => ExecutionPackBackend::Simd,
            Self::VyreGpu { backend, .. } => backend,
        }
    }

    fn bytes(self) -> &'a [u8] {
        match self {
            Self::Cpu(bytes) | Self::Simd(bytes) => bytes,
            Self::VyreGpu {
                orchestration_receipt,
                ..
            } => orchestration_receipt,
        }
    }

    fn plan(self) -> BackendPlan<'a> {
        match self {
            Self::Cpu(bytes) => BackendPlan::Cpu(bytes),
            Self::Simd(bytes) => BackendPlan::Simd(bytes),
            Self::VyreGpu {
                backend,
                orchestration_receipt,
            } => BackendPlan::VyreGpu {
                backend,
                orchestration_receipt,
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledBackendExecutionPack {
    pub backend: ExecutionPackBackend,
    pub pack: CompiledExecutionPack,
    pub signature: ExecutionPackSignature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledPolicyExecutionPacks {
    pub policy: ExecutionPackPolicy,
    pub packs: Vec<CompiledBackendExecutionPack>,
}

impl CompiledPolicyExecutionPacks {
    pub fn get(&self, backend: ExecutionPackBackend) -> Option<&CompiledExecutionPack> {
        self.packs
            .iter()
            .find(|candidate| candidate.backend == backend)
            .map(|candidate| &candidate.pack)
    }
}

pub fn compile_fast_policy_execution_packs(
    generation: PackGenerationIdentity,
    signing_key: &ExecutionPackSigningKey,
    detector_ir: &CanonicalDetectorExecutionIr,
    routes: &[BackendExecutionArtifact<'_>],
) -> Result<CompiledPolicyExecutionPacks, ExecutionPackError> {
    compile_policy_execution_packs(
        generation,
        signing_key,
        ExecutionPackPolicy::Fast,
        detector_ir,
        routes,
    )
}

pub fn compile_deep_policy_execution_packs(
    generation: PackGenerationIdentity,
    signing_key: &ExecutionPackSigningKey,
    detector_ir: &CanonicalDetectorExecutionIr,
    routes: &[BackendExecutionArtifact<'_>],
) -> Result<CompiledPolicyExecutionPacks, ExecutionPackError> {
    compile_policy_execution_packs(
        generation,
        signing_key,
        ExecutionPackPolicy::Deep,
        detector_ir,
        routes,
    )
}

pub fn compile_precision_policy_execution_packs(
    generation: PackGenerationIdentity,
    signing_key: &ExecutionPackSigningKey,
    detector_ir: &CanonicalDetectorExecutionIr,
    routes: &[BackendExecutionArtifact<'_>],
) -> Result<CompiledPolicyExecutionPacks, ExecutionPackError> {
    compile_policy_execution_packs(
        generation,
        signing_key,
        ExecutionPackPolicy::Precision,
        detector_ir,
        routes,
    )
}

pub fn compile_default_policy_execution_packs(
    generation: PackGenerationIdentity,
    signing_key: &ExecutionPackSigningKey,
    detector_ir: &CanonicalDetectorExecutionIr,
    routes: &[BackendExecutionArtifact<'_>],
) -> Result<CompiledPolicyExecutionPacks, ExecutionPackError> {
    compile_policy_execution_packs(
        generation,
        signing_key,
        ExecutionPackPolicy::Default,
        detector_ir,
        routes,
    )
}

pub fn compile_policy_execution_packs(
    generation: PackGenerationIdentity,
    signing_key: &ExecutionPackSigningKey,
    policy: ExecutionPackPolicy,
    detector_ir: &CanonicalDetectorExecutionIr,
    routes: &[BackendExecutionArtifact<'_>],
) -> Result<CompiledPolicyExecutionPacks, ExecutionPackError> {
    if routes.is_empty() {
        return Err(ExecutionPackError::InvalidCompilerInput(format!(
            "{policy:?} policy has no eligible backend programs"
        )));
    }
    let mut seen = BTreeSet::new();
    for route in routes {
        let artifact = route.program;
        let backend = route.backend();
        if !seen.insert(backend) {
            return Err(ExecutionPackError::InvalidCompilerInput(format!(
                "{policy:?} policy repeats backend {backend:?}"
            )));
        }
        if artifact.bytes().is_empty() {
            return Err(ExecutionPackError::InvalidCompilerInput(format!(
                "{policy:?} policy backend {backend:?} has an empty program artifact"
            )));
        }
        for (section, bytes) in [
            ("literal index", route.literal_index),
            ("regex programs", route.regex_programs),
            ("suppression policy", route.suppression_policy),
        ] {
            if bytes.is_empty() {
                return Err(ExecutionPackError::InvalidCompilerInput(format!(
                    "{policy:?} policy backend {backend:?} has an empty route-required {section}"
                )));
            }
        }
        let route_digest = super::parity::route_content_digest(
            artifact.bytes(),
            route.literal_index,
            route.regex_programs,
            route.suppression_policy,
        );
        route
            .finding_parity
            .validate(backend, detector_ir.digest(), generation, route_digest)?;
        if backend.is_gpu() && !matches!(artifact, BackendProgramArtifact::VyreGpu { .. }) {
            return Err(ExecutionPackError::InvalidCompilerInput(format!(
                "{policy:?} policy GPU backend {backend:?} is not a VYRE orchestration artifact"
            )));
        }
    }
    if !seen.contains(&ExecutionPackBackend::Cpu) {
        return Err(ExecutionPackError::InvalidCompilerInput(format!(
            "{policy:?} policy omits the mandatory scalar correctness pack"
        )));
    }

    let mut packs = Vec::with_capacity(routes.len());
    for route in routes {
        let artifact = route.program;
        let backend = route.backend();
        let backend_digest = *blake3::hash(artifact.bytes()).as_bytes();
        let identity = ExecutionPackIdentity::new(
            detector_ir.digest(),
            generation.config_digest,
            generation.target_digest,
            generation.binary_digest,
            generation.feature_digest,
            backend_digest,
            policy,
            backend,
        );
        let pack = compose_policy_execution_pack(
            identity,
            PolicyPlanSections {
                detector_ir: detector_ir.as_bytes(),
                literal_index: route.literal_index,
                regex_programs: route.regex_programs,
                suppression_policy: route.suppression_policy,
                backend_plan: artifact.plan(),
            },
        )?;
        let signature = signing_key.sign(&pack);
        packs.push(CompiledBackendExecutionPack {
            backend,
            pack,
            signature,
        });
    }
    packs.sort_unstable_by_key(|candidate| candidate.backend);
    Ok(CompiledPolicyExecutionPacks { policy, packs })
}
