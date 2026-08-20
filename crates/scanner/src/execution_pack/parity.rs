use super::{ExecutionPackBackend, ExecutionPackError, PackGenerationIdentity};

pub const PACK_FINDING_PARITY_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackFindingParityEvidence {
    pub version: u16,
    pub backend: ExecutionPackBackend,
    pub detector_digest: [u8; 32],
    pub config_digest: [u8; 32],
    pub binary_digest: [u8; 32],
    pub route_digest: [u8; 32],
    pub fixture_digest: [u8; 32],
    pub scalar_findings_digest: [u8; 32],
    pub candidate_findings_digest: [u8; 32],
    pub finding_count: u64,
}

impl PackFindingParityEvidence {
    /// Creates route-bound evidence from the exact serialized matcher structures that will be published.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_route(
        backend: ExecutionPackBackend,
        detector_digest: [u8; 32],
        generation: PackGenerationIdentity,
        fixture_digest: [u8; 32],
        finding_count: u64,
        scalar_findings: &[u8],
        candidate_findings: &[u8],
        program: &[u8],
        literal_index: &[u8],
        regex_programs: &[u8],
        suppression_policy: &[u8],
    ) -> Result<Self, ExecutionPackError> {
        Self::prove(
            backend,
            detector_digest,
            generation,
            route_content_digest(program, literal_index, regex_programs, suppression_policy),
            fixture_digest,
            finding_count,
            scalar_findings,
            candidate_findings,
        )
    }

    /// Creates evidence from canonical, sorted finding bytes produced by real scalar and candidate executions.
    pub fn prove(
        backend: ExecutionPackBackend,
        detector_digest: [u8; 32],
        generation: PackGenerationIdentity,
        route_digest: [u8; 32],
        fixture_digest: [u8; 32],
        finding_count: u64,
        scalar_findings: &[u8],
        candidate_findings: &[u8],
    ) -> Result<Self, ExecutionPackError> {
        if fixture_digest == [0; 32] {
            return Err(ExecutionPackError::InvalidCompilerInput(
                "pack parity fixture identity is empty".into(),
            ));
        }
        if scalar_findings != candidate_findings {
            return Err(ExecutionPackError::InvalidCompilerInput(format!(
                "pack finding parity failed for {backend:?}; candidate findings differ from scalar oracle"
            )));
        }
        Ok(Self {
            version: PACK_FINDING_PARITY_VERSION,
            backend,
            detector_digest,
            config_digest: generation.config_digest,
            binary_digest: generation.binary_digest,
            route_digest,
            fixture_digest,
            scalar_findings_digest: *blake3::hash(scalar_findings).as_bytes(),
            candidate_findings_digest: *blake3::hash(candidate_findings).as_bytes(),
            finding_count,
        })
    }

    /// Validates that this parity evidence matches the expected execution pack backend,
    /// detector digest, generation identity, and route digest.
    pub fn validate(
        &self,
        backend: ExecutionPackBackend,
        detector_digest: [u8; 32],
        generation: PackGenerationIdentity,
        route_digest: [u8; 32],
    ) -> Result<(), ExecutionPackError> {
        if self.version != PACK_FINDING_PARITY_VERSION {
            return Err(ExecutionPackError::Incompatible(format!(
                "pack finding parity version {} is unsupported; recalibrate with version {}",
                self.version, PACK_FINDING_PARITY_VERSION
            )));
        }
        if self.backend != backend
            || self.detector_digest != detector_digest
            || self.config_digest != generation.config_digest
            || self.binary_digest != generation.binary_digest
            || self.route_digest != route_digest
        {
            return Err(ExecutionPackError::Incompatible(format!(
                "pack finding parity evidence for {backend:?} is stale or belongs to another route; reinstall and recalibrate"
            )));
        }
        if self.fixture_digest == [0; 32]
            || self.scalar_findings_digest != self.candidate_findings_digest
        {
            return Err(ExecutionPackError::InvalidCompilerInput(format!(
                "pack finding parity evidence for {backend:?} does not prove exact scalar parity"
            )));
        }
        Ok(())
    }
}

pub(crate) fn route_content_digest(
    program: &[u8],
    literal_index: &[u8],
    regex_programs: &[u8],
    suppression_policy: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for bytes in [program, literal_index, regex_programs, suppression_policy] {
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    *hasher.finalize().as_bytes()
}
