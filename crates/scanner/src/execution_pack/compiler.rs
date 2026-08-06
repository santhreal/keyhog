use super::format::{
    ExecutionPackBackend, ExecutionPackIdentity, ExecutionPackSectionKind, SectionEntry,
    EXECUTION_PACK_FORMAT_VERSION, EXECUTION_PACK_HEADER_LEN, EXECUTION_PACK_MAGIC,
    EXECUTION_PACK_SECTION_ENTRY_LEN,
};
use super::ExecutionPackError;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug)]
pub struct CompileSection<'a> {
    pub kind: ExecutionPackSectionKind,
    pub alignment: u32,
    pub bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug)]
pub struct ExecutionPackCompileInput<'a> {
    pub identity: ExecutionPackIdentity,
    pub sections: &'a [CompileSection<'a>],
}

#[derive(Clone, Copy, Debug)]
pub enum BackendPlan<'a> {
    Cpu(&'a [u8]),
    Simd(&'a [u8]),
    VyreGpu {
        backend: ExecutionPackBackend,
        orchestration_receipt: &'a [u8],
    },
}

impl BackendPlan<'_> {
    const fn backend(self) -> ExecutionPackBackend {
        match self {
            Self::Cpu(_) => ExecutionPackBackend::Cpu,
            Self::Simd(_) => ExecutionPackBackend::Simd,
            Self::VyreGpu { backend, .. } => backend,
        }
    }
}

/// One complete policy plan. Every policy carries every correctness section;
/// policy-specific behavior changes section bytes and the exact policy/config
/// identity, never the required runtime graph.
#[derive(Clone, Copy, Debug)]
pub struct PolicyPlanSections<'a> {
    pub detector_ir: &'a [u8],
    pub literal_index: &'a [u8],
    pub regex_programs: &'a [u8],
    pub suppression_policy: &'a [u8],
    pub backend_plan: BackendPlan<'a>,
}

pub fn compose_policy_execution_pack(
    identity: ExecutionPackIdentity,
    plan: PolicyPlanSections<'_>,
) -> Result<CompiledExecutionPack, ExecutionPackError> {
    if plan.backend_plan.backend() != identity.backend {
        return Err(ExecutionPackError::InvalidCompilerInput(format!(
            "backend plan {:?} does not match pack identity {:?}",
            plan.backend_plan.backend(),
            identity.backend
        )));
    }
    let backend_program: std::borrow::Cow<'_, [u8]> = match plan.backend_plan {
        BackendPlan::Cpu(bytes) | BackendPlan::Simd(bytes) => std::borrow::Cow::Borrowed(bytes),
        BackendPlan::VyreGpu {
            backend,
            orchestration_receipt,
        } => {
            if !backend.is_gpu() {
                return Err(ExecutionPackError::InvalidCompilerInput(
                    "VYRE orchestration plan names a non-GPU backend".to_owned(),
                ));
            }
            if orchestration_receipt.is_empty() {
                return Err(ExecutionPackError::InvalidCompilerInput(
                    "VYRE GPU orchestration receipt is empty".to_owned(),
                ));
            }
            let mut bytes = Vec::with_capacity(17 + orchestration_receipt.len());
            bytes.extend_from_slice(b"KHVYRE\0\x01");
            bytes.push(backend as u8);
            bytes.extend_from_slice(&(orchestration_receipt.len() as u64).to_le_bytes());
            bytes.extend_from_slice(orchestration_receipt);
            std::borrow::Cow::Owned(bytes)
        }
    };
    let detector_ir = super::CanonicalDetectorExecutionIr::decode(plan.detector_ir)?;
    if detector_ir.digest() != identity.detector_digest {
        return Err(ExecutionPackError::InvalidCompilerInput(
            "detector-plan input DetectorIr digest does not match pack identity".to_owned(),
        ));
    }
    let detector_plan = super::CompiledDetectorPlanSection::compile(&detector_ir)?;
    let sections = [
        CompileSection {
            kind: ExecutionPackSectionKind::DetectorIr,
            alignment: 8,
            bytes: plan.detector_ir,
        },
        CompileSection {
            kind: ExecutionPackSectionKind::LiteralIndex,
            alignment: 64,
            bytes: plan.literal_index,
        },
        CompileSection {
            kind: ExecutionPackSectionKind::RegexPrograms,
            alignment: 64,
            bytes: plan.regex_programs,
        },
        CompileSection {
            kind: ExecutionPackSectionKind::SuppressionPolicy,
            alignment: 8,
            bytes: plan.suppression_policy,
        },
        CompileSection {
            kind: ExecutionPackSectionKind::BackendProgram,
            alignment: 64,
            bytes: backend_program.as_ref(),
        },
        CompileSection {
            kind: ExecutionPackSectionKind::DetectorPlan,
            alignment: 8,
            bytes: detector_plan.as_bytes(),
        },
    ];
    compile_execution_pack(ExecutionPackCompileInput {
        identity,
        sections: &sections,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledExecutionPack {
    bytes: Vec<u8>,
    identity: ExecutionPackIdentity,
    content_digest: [u8; 32],
}

impl CompiledExecutionPack {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub const fn identity(&self) -> ExecutionPackIdentity {
        self.identity
    }

    pub const fn content_digest(&self) -> [u8; 32] {
        self.content_digest
    }
}

pub fn compile_execution_pack(
    input: ExecutionPackCompileInput<'_>,
) -> Result<CompiledExecutionPack, ExecutionPackError> {
    if input.sections.is_empty() {
        return Err(ExecutionPackError::InvalidCompilerInput(
            "execution pack has no sections".to_owned(),
        ));
    }
    let mut seen = BTreeSet::new();
    for section in input.sections {
        if !seen.insert(section.kind) {
            return Err(ExecutionPackError::InvalidCompilerInput(format!(
                "execution pack repeats section {}",
                section.kind
            )));
        }
        if section.bytes.is_empty() {
            return Err(ExecutionPackError::InvalidCompilerInput(format!(
                "execution pack section {} is empty",
                section.kind
            )));
        }
        if section.alignment == 0
            || !section.alignment.is_power_of_two()
            || section.alignment > 4096
        {
            return Err(ExecutionPackError::InvalidCompilerInput(format!(
                "execution pack section {} alignment {} is not a power of two in 1..=4096",
                section.kind, section.alignment
            )));
        }
    }
    for required in ExecutionPackSectionKind::ALL {
        if !seen.contains(&required) {
            return Err(ExecutionPackError::InvalidCompilerInput(format!(
                "execution pack has no required {required} section"
            )));
        }
    }

    let table_len = input
        .sections
        .len()
        .checked_mul(EXECUTION_PACK_SECTION_ENTRY_LEN)
        .ok_or_else(|| {
            ExecutionPackError::InvalidCompilerInput("section table overflows".to_owned())
        })?;
    let mut cursor = EXECUTION_PACK_HEADER_LEN
        .checked_add(table_len)
        .ok_or_else(|| {
            ExecutionPackError::InvalidCompilerInput("pack header overflows".to_owned())
        })?;
    let mut entries = Vec::with_capacity(input.sections.len());
    for section in input.sections {
        cursor = align_up(cursor, section.alignment as usize)?;
        let end = cursor.checked_add(section.bytes.len()).ok_or_else(|| {
            ExecutionPackError::InvalidCompilerInput(format!(
                "execution pack section {} overflows addressable size",
                section.kind
            ))
        })?;
        entries.push(SectionEntry {
            kind: section.kind,
            schema_version: section.kind.schema_version(),
            offset: cursor as u64,
            len: section.bytes.len() as u64,
            alignment: section.alignment,
        });
        cursor = end;
    }

    let mut bytes = vec![0_u8; cursor];
    write_header_prefix(&mut bytes, input.identity, input.sections.len(), cursor)?;
    for (index, entry) in entries.iter().enumerate() {
        let base = EXECUTION_PACK_HEADER_LEN + index * EXECUTION_PACK_SECTION_ENTRY_LEN;
        bytes[base..base + 2].copy_from_slice(&(entry.kind as u16).to_le_bytes());
        bytes[base + 2..base + 4].copy_from_slice(&entry.schema_version.to_le_bytes());
        bytes[base + 4..base + 12].copy_from_slice(&entry.offset.to_le_bytes());
        bytes[base + 12..base + 20].copy_from_slice(&entry.len.to_le_bytes());
        bytes[base + 20..base + 24].copy_from_slice(&entry.alignment.to_le_bytes());
    }
    for (section, entry) in input.sections.iter().zip(&entries) {
        let start = entry.offset as usize;
        bytes[start..start + section.bytes.len()].copy_from_slice(section.bytes);
    }
    let content_digest = *blake3::hash(&bytes[EXECUTION_PACK_HEADER_LEN..]).as_bytes();
    bytes[248..280].copy_from_slice(&content_digest);
    bytes[280..312].copy_from_slice(&input.identity.digest());
    Ok(CompiledExecutionPack {
        bytes,
        identity: input.identity,
        content_digest,
    })
}

fn align_up(value: usize, alignment: usize) -> Result<usize, ExecutionPackError> {
    value
        .checked_add(alignment - 1)
        .map(|sum| sum & !(alignment - 1))
        .ok_or_else(|| {
            ExecutionPackError::InvalidCompilerInput("section alignment overflows".to_owned())
        })
}

fn write_header_prefix(
    bytes: &mut [u8],
    identity: ExecutionPackIdentity,
    section_count: usize,
    total_len: usize,
) -> Result<(), ExecutionPackError> {
    let section_count = u32::try_from(section_count).map_err(|_| {
        ExecutionPackError::InvalidCompilerInput("section count exceeds u32".to_owned())
    })?;
    let total_len = u64::try_from(total_len).map_err(|_| {
        ExecutionPackError::InvalidCompilerInput("pack length exceeds u64".to_owned())
    })?;
    bytes[0..8].copy_from_slice(&EXECUTION_PACK_MAGIC);
    bytes[8..10].copy_from_slice(&EXECUTION_PACK_FORMAT_VERSION.to_le_bytes());
    bytes[10..12].copy_from_slice(&(EXECUTION_PACK_HEADER_LEN as u16).to_le_bytes());
    bytes[12..16].copy_from_slice(&section_count.to_le_bytes());
    bytes[16..24].copy_from_slice(&total_len.to_le_bytes());
    bytes[24..56].copy_from_slice(&identity.detector_digest);
    bytes[56..88].copy_from_slice(&identity.config_digest);
    bytes[88..120].copy_from_slice(&identity.target_digest);
    bytes[120..152].copy_from_slice(&identity.compiler_abi);
    bytes[152..184].copy_from_slice(&identity.binary_digest);
    bytes[184..216].copy_from_slice(&identity.feature_digest);
    bytes[216..248].copy_from_slice(&identity.backend_digest);
    bytes[312] = identity.policy as u8;
    bytes[313] = identity.backend as u8;
    Ok(())
}
