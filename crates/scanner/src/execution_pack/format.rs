use crate::hw_probe::ScanBackend;

use std::fmt;

pub const EXECUTION_PACK_MAGIC: [u8; 8] = *b"KHPACK\0\x02";
pub const EXECUTION_PACK_FORMAT_VERSION: u16 = 2;
pub const EXECUTION_PACK_HEADER_LEN: usize = 320;
pub const EXECUTION_PACK_SECTION_ENTRY_LEN: usize = 24;
pub const EXECUTION_PACK_COMPILER_ABI: [u8; 32] = *b"keyhog-pack-compiler-abi-v2\0\0\0\0\0";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum ExecutionPackSectionKind {
    DetectorIr = 1,
    LiteralIndex = 2,
    RegexPrograms = 3,
    SuppressionPolicy = 4,
    BackendProgram = 5,
    DetectorPlan = 6,
}

impl ExecutionPackSectionKind {
    pub const ALL: [Self; 6] = [
        Self::DetectorIr,
        Self::LiteralIndex,
        Self::RegexPrograms,
        Self::SuppressionPolicy,
        Self::BackendProgram,
        Self::DetectorPlan,
    ];

    pub const fn schema_version(self) -> u16 {
        match self {
            Self::DetectorIr => super::ir::DETECTOR_EXECUTION_IR_VERSION,
            Self::LiteralIndex | Self::RegexPrograms | Self::SuppressionPolicy => {
                super::matcher_sections::ROUTE_MATCHER_SECTION_VERSION
            }
            Self::BackendProgram => 2,
            Self::DetectorPlan => super::detector_plan::DETECTOR_PLAN_SECTION_VERSION,
        }
    }

    pub(crate) fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::DetectorIr),
            2 => Some(Self::LiteralIndex),
            3 => Some(Self::RegexPrograms),
            4 => Some(Self::SuppressionPolicy),
            5 => Some(Self::BackendProgram),
            6 => Some(Self::DetectorPlan),
            _ => None,
        }
    }
}

impl fmt::Display for ExecutionPackSectionKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DetectorIr => "detector-ir",
            Self::LiteralIndex => "literal-index",
            Self::RegexPrograms => "regex-programs",
            Self::SuppressionPolicy => "suppression-policy",
            Self::BackendProgram => "backend-program",
            Self::DetectorPlan => "detector-plan",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ExecutionPackBackend {
    Cpu = 1,
    Simd = 2,
    GpuCuda = 3,
    GpuWgpu = 4,
    GpuMetal = 5,
}

impl ExecutionPackBackend {
    pub const ALL: [Self; 5] = [
        Self::Cpu,
        Self::Simd,
        Self::GpuCuda,
        Self::GpuWgpu,
        Self::GpuMetal,
    ];

    pub const fn lowercase_name(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Simd => "simd",
            Self::GpuCuda => "gpu-cuda",
            Self::GpuWgpu => "gpu-wgpu",
            Self::GpuMetal => "gpu-metal",
        }
    }

    pub const fn pascal_name(self) -> &'static str {
        match self {
            Self::Cpu => "Cpu",
            Self::Simd => "Simd",
            Self::GpuCuda => "GpuCuda",
            Self::GpuWgpu => "GpuWgpu",
            Self::GpuMetal => "GpuMetal",
        }
    }

    pub fn from_pascal_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|backend| backend.pascal_name() == name)
    }
    pub fn from_lowercase_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|backend| backend.lowercase_name() == name)
    }

    pub const fn scan_backend(self) -> ScanBackend {
        match self {
            Self::Cpu => ScanBackend::CpuFallback,
            Self::Simd => ScanBackend::SimdCpu,
            Self::GpuCuda => ScanBackend::GpuCuda,
            Self::GpuWgpu => ScanBackend::GpuWgpu,
            Self::GpuMetal => ScanBackend::GpuMetal,
        }
    }

    pub fn from_scan_backend(backend: ScanBackend) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.scan_backend() == backend)
    }

    pub const fn is_gpu(self) -> bool {
        matches!(self, Self::GpuCuda | Self::GpuWgpu | Self::GpuMetal)
    }

    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Cpu),
            2 => Some(Self::Simd),
            3 => Some(Self::GpuCuda),
            4 => Some(Self::GpuWgpu),
            5 => Some(Self::GpuMetal),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ExecutionPackPolicy {
    Default = 1,
    Fast = 2,
    Deep = 3,
    Precision = 4,
}

impl ExecutionPackPolicy {
    pub const ALL: [Self; 4] = [Self::Default, Self::Fast, Self::Deep, Self::Precision];

    pub const fn lowercase_name(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Fast => "fast",
            Self::Deep => "deep",
            Self::Precision => "precision",
        }
    }
    pub fn from_lowercase_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|policy| policy.lowercase_name() == name)
    }

    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Default),
            2 => Some(Self::Fast),
            3 => Some(Self::Deep),
            4 => Some(Self::Precision),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionPackIdentity {
    pub detector_digest: [u8; 32],
    pub config_digest: [u8; 32],
    pub target_digest: [u8; 32],
    pub compiler_abi: [u8; 32],
    pub binary_digest: [u8; 32],
    pub feature_digest: [u8; 32],
    pub backend_digest: [u8; 32],
    pub policy: ExecutionPackPolicy,
    pub backend: ExecutionPackBackend,
}

impl ExecutionPackIdentity {
    pub const fn new(
        detector_digest: [u8; 32],
        config_digest: [u8; 32],
        target_digest: [u8; 32],
        binary_digest: [u8; 32],
        feature_digest: [u8; 32],
        backend_digest: [u8; 32],
        policy: ExecutionPackPolicy,
        backend: ExecutionPackBackend,
    ) -> Self {
        Self {
            detector_digest,
            config_digest,
            target_digest,
            compiler_abi: EXECUTION_PACK_COMPILER_ABI,
            binary_digest,
            feature_digest,
            backend_digest,
            policy,
            backend,
        }
    }

    pub fn digest(self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"keyhog-execution-pack-identity-v1\0");
        hasher.update(&EXECUTION_PACK_FORMAT_VERSION.to_le_bytes());
        hasher.update(&self.detector_digest);
        hasher.update(&self.config_digest);
        hasher.update(&self.target_digest);
        hasher.update(&self.compiler_abi);
        hasher.update(&self.binary_digest);
        hasher.update(&self.feature_digest);
        hasher.update(&self.backend_digest);
        hasher.update(&[self.policy as u8, self.backend as u8]);
        *hasher.finalize().as_bytes()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SectionEntry {
    pub kind: ExecutionPackSectionKind,
    pub schema_version: u16,
    pub offset: u64,
    pub len: u64,
    pub alignment: u32,
}

#[cfg(test)]
mod tests {
    use super::{ExecutionPackBackend, ExecutionPackPolicy};

    #[test]
    fn execution_pack_identity_names_and_scan_conversions_round_trip_exhaustively() {
        for backend in ExecutionPackBackend::ALL {
            assert_eq!(
                ExecutionPackBackend::from_lowercase_name(backend.lowercase_name()),
                Some(backend)
            );
            assert_eq!(
                ExecutionPackBackend::from_pascal_name(backend.pascal_name()),
                Some(backend)
            );
            assert_eq!(
                ExecutionPackBackend::from_scan_backend(backend.scan_backend()),
                Some(backend)
            );
        }
        for policy in ExecutionPackPolicy::ALL {
            assert_eq!(
                ExecutionPackPolicy::from_lowercase_name(policy.lowercase_name()),
                Some(policy)
            );
        }
        assert_eq!(ExecutionPackBackend::from_lowercase_name("GPU-CUDA"), None);
        assert_eq!(ExecutionPackBackend::from_pascal_name("GPUCuda"), None);
        assert_eq!(ExecutionPackPolicy::from_lowercase_name("DEFAULT"), None);
        assert_eq!(
            ExecutionPackPolicy::ALL.map(ExecutionPackPolicy::lowercase_name),
            ["default", "fast", "deep", "precision"]
        );
    }
}
