use super::{CanonicalDetectorExecutionIr, ExecutionPackError};
use serde::{Deserialize, Serialize};
use std::cell::Cell;

thread_local! {
    static RUNTIME_CANONICAL_REENCODES: Cell<usize> = const { Cell::new(0) };
}

pub const SCALAR_CPU_PROGRAM_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScalarCpuExecutionProgram {
    pub version: u16,
    pub detector_ir_digest: [u8; 32],
    pub patterns: Vec<ScalarCpuPatternProgram>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScalarCpuPatternProgram {
    pub detector_index: u32,
    pub pattern_index: u32,
    pub phase2: bool,
    pub regex: String,
    pub capture_group: Option<u32>,
    pub required_literals: Vec<String>,
    pub client_safe: bool,
    pub weak_anchor: bool,
    pub structural_password_slot: bool,
}

impl ScalarCpuExecutionProgram {
    pub fn compile(ir: &CanonicalDetectorExecutionIr) -> Result<Self, ExecutionPackError> {
        let mut patterns = Vec::new();
        for (detector_index, detector) in ir.detectors().iter().enumerate() {
            let detector_index = u32::try_from(detector_index).map_err(|_| {
                ExecutionPackError::InvalidCompilerInput(
                    "scalar CPU program exceeds u32 detector indices".to_owned(),
                )
            })?;
            for (pattern_index, pattern) in detector.patterns.iter().enumerate() {
                let pattern_index = u32::try_from(pattern_index).map_err(|_| {
                    ExecutionPackError::InvalidCompilerInput(format!(
                        "scalar CPU detector {:?} exceeds u32 pattern indices",
                        detector.id
                    ))
                })?;
                let capture_group = pattern
                    .group
                    .map(u32::try_from)
                    .transpose()
                    .map_err(|_| {
                        ExecutionPackError::InvalidCompilerInput(format!(
                            "scalar CPU detector {:?} pattern {pattern_index} capture group exceeds u32",
                            detector.id
                        ))
                    })?;
                let mut required_literals = pattern.required_literals.clone();
                required_literals.sort_unstable();
                required_literals.dedup();
                patterns.push(ScalarCpuPatternProgram {
                    detector_index,
                    pattern_index,
                    phase2: detector.kind == keyhog_core::DetectorKind::Phase2Generic,
                    regex: pattern.regex.clone(),
                    capture_group,
                    required_literals,
                    client_safe: pattern.client_safe,
                    weak_anchor: pattern.weak_anchor,
                    structural_password_slot: pattern.structural_password_slot,
                });
            }
        }
        Ok(Self {
            version: SCALAR_CPU_PROGRAM_VERSION,
            detector_ir_digest: ir.digest(),
            patterns,
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExecutionPackError> {
        serde_json::to_vec(self).map_err(|error| {
            ExecutionPackError::InvalidCompilerInput(format!(
                "cannot serialize scalar CPU execution program: {error}"
            ))
        })
    }

    pub fn decode(bytes: &[u8], expected_ir_digest: [u8; 32]) -> Result<Self, ExecutionPackError> {
        Self::decode_inner(bytes, expected_ir_digest, false)
    }

    /// Decode structurally typed bytes after the exact immutable pack mapping
    /// and its signature have already been authenticated.
    pub(crate) fn decode_authenticated(
        bytes: &[u8],
        expected_ir_digest: [u8; 32],
    ) -> Result<Self, ExecutionPackError> {
        Self::decode_inner(bytes, expected_ir_digest, true)
    }

    fn decode_inner(
        bytes: &[u8],
        expected_ir_digest: [u8; 32],
        authenticated: bool,
    ) -> Result<Self, ExecutionPackError> {
        let program: Self = serde_json::from_slice(bytes).map_err(|error| {
            ExecutionPackError::InvalidPack(format!(
                "scalar CPU execution program is invalid: {error}"
            ))
        })?;
        if program.version != SCALAR_CPU_PROGRAM_VERSION {
            return Err(ExecutionPackError::Incompatible(format!(
                "scalar CPU program version {} is unsupported; this binary requires {}",
                program.version, SCALAR_CPU_PROGRAM_VERSION
            )));
        }
        if program.detector_ir_digest != expected_ir_digest {
            return Err(ExecutionPackError::Incompatible(
                "scalar CPU program detector IR identity does not match its pack".to_owned(),
            ));
        }
        if !authenticated {
            RUNTIME_CANONICAL_REENCODES.set(RUNTIME_CANONICAL_REENCODES.get().saturating_add(1));
            let canonical = program.canonical_bytes()?;
            if canonical != bytes {
                return Err(ExecutionPackError::InvalidPack(
                    "scalar CPU execution program is not canonically encoded".to_owned(),
                ));
            }
        }
        Ok(program)
    }

    #[doc(hidden)]
    pub fn runtime_canonical_reencodes() -> usize {
        RUNTIME_CANONICAL_REENCODES.get()
    }
}
