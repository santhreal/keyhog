//! Install-time Hyperscan execution-program compiler.

use super::{CanonicalDetectorExecutionIr, ExecutionPackError, ScalarCpuExecutionProgram};
use std::collections::{BTreeMap, HashMap, HashSet};

const MAGIC: &[u8; 8] = b"KHSIMD\0\x03";
pub const HYPERSCAN_SIMD_PROGRAM_VERSION: u16 = 3;
#[cfg(debug_assertions)]
static VERIFIED_SHARD_BYTES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[derive(Clone, Debug, Eq, PartialEq)]
enum SerializedHyperscanShardStorage {
    Owned(std::sync::Arc<[u8]>),
    Mapped(super::runtime::ExecutionPackMappedBytes),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SerializedHyperscanShard(SerializedHyperscanShardStorage);

impl SerializedHyperscanShard {
    fn from_mapped(bytes: super::runtime::ExecutionPackMappedBytes) -> Self {
        Self(SerializedHyperscanShardStorage::Mapped(bytes))
    }

    pub fn make_mut(&mut self) -> &mut [u8] {
        if let SerializedHyperscanShardStorage::Mapped(mapped) = &self.0 {
            self.0 = SerializedHyperscanShardStorage::Owned(std::sync::Arc::from(mapped.as_ref()));
        }
        let SerializedHyperscanShardStorage::Owned(bytes) = &mut self.0 else {
            unreachable!("mapped shard converted to owned storage")
        };
        std::sync::Arc::make_mut(bytes)
    }

    pub fn release_resident_pages(&self) -> Result<(), ExecutionPackError> {
        match &self.0 {
            SerializedHyperscanShardStorage::Owned(_) => Ok(()),
            SerializedHyperscanShardStorage::Mapped(bytes) => bytes.release_resident_pages(),
        }
    }

    fn release_resident_range(
        &self,
        range: std::ops::Range<usize>,
    ) -> Result<(), ExecutionPackError> {
        match &self.0 {
            SerializedHyperscanShardStorage::Owned(_) => Ok(()),
            SerializedHyperscanShardStorage::Mapped(bytes) => bytes.release_resident_range(range),
        }
    }
}

impl From<Vec<u8>> for SerializedHyperscanShard {
    fn from(bytes: Vec<u8>) -> Self {
        Self(SerializedHyperscanShardStorage::Owned(bytes.into()))
    }
}

impl From<&[u8]> for SerializedHyperscanShard {
    fn from(bytes: &[u8]) -> Self {
        Self(SerializedHyperscanShardStorage::Owned(bytes.into()))
    }
}

impl std::ops::Deref for SerializedHyperscanShard {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match &self.0 {
            SerializedHyperscanShardStorage::Owned(bytes) => bytes,
            SerializedHyperscanShardStorage::Mapped(bytes) => bytes,
        }
    }
}

impl AsRef<[u8]> for SerializedHyperscanShard {
    fn as_ref(&self) -> &[u8] {
        self
    }
}
const SHARD_STREAM_CHUNK_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HyperscanPatternProgram {
    pub detector_index: u32,
    pub pattern_index: u32,
    pub reports_start: bool,
    pub regex: String,
    /// Canonical scalar detector-pattern rows with this exact regex. This is
    /// identity metadata only; runtime routing uses `ac_map_indices`.
    pub scalar_pattern_indices: Vec<u32>,
    /// Canonical phase-one AC rows activated by this Hyperscan pattern.
    pub ac_map_indices: Vec<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HyperscanPhase2Scope {
    Full = 0,
    AnchorResidual = 1,
    LocalizedResidual = 2,
}

impl HyperscanPhase2Scope {
    const ALL: [Self; 3] = [Self::Full, Self::AnchorResidual, Self::LocalizedResidual];
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HyperscanPhase2DatabaseProgram {
    /// Canonical phase-two indices submitted to Hyperscan, in database input-id order.
    pub pattern_indices: Vec<u32>,
    /// Input IDs rejected by Hyperscan and retained on the host regex path.
    pub unsupported_pattern_ids: Vec<u32>,
    /// Native bytes are shared by digest when policy scopes compile identically.
    pub serialized_shards: Vec<SerializedHyperscanShard>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HyperscanPhase2ScopeProgram {
    pub scope: HyperscanPhase2Scope,
    /// Exact runtime ownership indices for this scope, including host-only patterns.
    pub pattern_indices: Vec<u32>,
    pub full: Option<HyperscanPhase2DatabaseProgram>,
    pub ascii_lean: Option<HyperscanPhase2DatabaseProgram>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HyperscanSimdExecutionProgram {
    pub version: u16,
    pub detector_ir_digest: [u8; 32],
    pub patterns: Vec<HyperscanPatternProgram>,
    pub unsupported_pattern_ids: Vec<u32>,
    pub serialized_shards: Vec<SerializedHyperscanShard>,
    pub phase2_scopes: Vec<HyperscanPhase2ScopeProgram>,
}

impl HyperscanSimdExecutionProgram {
    #[cfg(feature = "simd")]
    pub fn compile(ir: &CanonicalDetectorExecutionIr) -> Result<Self, ExecutionPackError> {
        let state = crate::compiler::build_compile_state(ir.detectors()).map_err(|error| {
            ExecutionPackError::InvalidCompilerInput(format!(
                "cannot compile canonical SIMD phase-one state: {error}"
            ))
        })?;
        let scalar = ScalarCpuExecutionProgram::compile(ir)?;
        let mut scalar_by_regex: BTreeMap<&str, Vec<u32>> = BTreeMap::new();
        for (index, pattern) in scalar.patterns.iter().enumerate() {
            scalar_by_regex
                .entry(pattern.regex.as_str())
                .or_default()
                .push(u32::try_from(index).map_err(|_| {
                    ExecutionPackError::InvalidCompilerInput(
                        "SIMD scalar pattern index exceeds the execution-pack u32 limit".into(),
                    )
                })?);
        }

        let mut regex_to_hs_id: HashMap<String, usize> = HashMap::new();
        let mut patterns = Vec::new();
        for (ac_index, entry) in state.ac_map.iter().enumerate() {
            let regex = entry.regex.as_str();
            let hs_id = match regex_to_hs_id.get(regex).copied() {
                Some(id) => id,
                None => {
                    let id = patterns.len();
                    let pattern_index = u32::try_from(id).map_err(|_| {
                        ExecutionPackError::InvalidCompilerInput(
                            "SIMD pattern count exceeds the execution-pack u32 limit".into(),
                        )
                    })?;
                    let detector_index = u32::try_from(entry.detector_index).map_err(|_| {
                        ExecutionPackError::InvalidCompilerInput(
                            "SIMD detector index exceeds the execution-pack u32 limit".into(),
                        )
                    })?;
                    patterns.push(HyperscanPatternProgram {
                        detector_index,
                        pattern_index,
                        reports_start: entry.group.is_some(),
                        regex: regex.to_owned(),
                        // LAW10: a regex without scalar companions intentionally records an empty exact companion set.
                        scalar_pattern_indices: scalar_by_regex
                            .get(regex)
                            .cloned()
                            // LAW10: absence means this regex has no exact scalar companions.
                            .unwrap_or_default(),
                        ac_map_indices: Vec::new(),
                    });
                    regex_to_hs_id.insert(regex.to_owned(), id);
                    id
                }
            };
            if patterns[hs_id].reports_start != entry.group.is_some() {
                return Err(ExecutionPackError::InvalidCompilerInput(format!(
                    "canonical SIMD regex {:?} has inconsistent capture reporting across AC rows",
                    regex
                )));
            }
            patterns[hs_id]
                .ac_map_indices
                .push(u32::try_from(ac_index).map_err(|_| {
                    ExecutionPackError::InvalidCompilerInput(
                        "SIMD AC pattern index exceeds the execution-pack u32 limit".into(),
                    )
                })?);
        }

        let refs: Vec<_> = patterns
            .iter()
            .map(|pattern| {
                (
                    pattern.detector_index as usize,
                    pattern.pattern_index as usize,
                    pattern.regex.as_str(),
                    pattern.reports_start,
                )
            })
            .collect();
        let options = crate::simd::backend::HsCompileOpts {
            singlematch: true,
            utf8: true,
            ucp: true,
            ..Default::default()
        };
        let (scanner, unsupported) =
            crate::simd::backend::HsScanner::compile_with_opts(&refs, options)
                .map_err(ExecutionPackError::InvalidPack)?;
        let unsupported_set: HashSet<usize> = unsupported.iter().copied().collect();
        let expected_map = patterns
            .iter()
            .enumerate()
            .filter(|(id, _)| !unsupported_set.contains(id))
            .map(|(id, pattern)| {
                (
                    id,
                    pattern.detector_index as usize,
                    pattern.pattern_index as usize,
                    pattern.reports_start,
                )
            })
            .collect::<Vec<_>>();
        if scanner.execution_pattern_map() != expected_map {
            return Err(ExecutionPackError::InvalidPack(
                "Hyperscan compiler changed the canonical SIMD pattern mapping".into(),
            ));
        }
        let serialized_shards = scanner
            .serialize_database_shards()
            .map_err(ExecutionPackError::InvalidPack)?
            .into_iter()
            .map(SerializedHyperscanShard::from)
            .collect();
        let unsupported_pattern_ids = unsupported
            .into_iter()
            .map(|id| {
                u32::try_from(id).map_err(|_| {
                    ExecutionPackError::InvalidPack(
                        "Hyperscan unsupported pattern id exceeds the execution-pack u32 limit"
                            .into(),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let phase2_always_active =
            crate::compiler::phase2_always_active_indices(&state.phase2_patterns);
        let phase2_anchor =
            crate::engine::Phase2AnchorIndex::build(&state.phase2_patterns, &phase2_always_active);
        let phase2_indices = crate::engine::canonical_phase2_scope_indices(
            &state.phase2_patterns,
            &phase2_always_active,
            phase2_anchor.as_ref(),
        );
        let phase2_scopes = HyperscanPhase2Scope::ALL
            .into_iter()
            .zip(phase2_indices)
            .map(|(scope, indices)| {
                crate::engine::compile_phase2_scope_program(&state.phase2_patterns, scope, &indices)
                    .map_err(ExecutionPackError::InvalidPack)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let program = Self {
            version: HYPERSCAN_SIMD_PROGRAM_VERSION,
            detector_ir_digest: ir.digest(),
            patterns,
            unsupported_pattern_ids,
            serialized_shards,
            phase2_scopes,
        };
        program.validate_structure()?;
        Ok(program)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExecutionPackError> {
        self.validate_structure()?;
        let pattern_count = u32::try_from(self.patterns.len()).map_err(|_| {
            ExecutionPackError::InvalidPack("SIMD pattern count exceeds u32".into())
        })?;
        let unsupported_count =
            u32::try_from(self.unsupported_pattern_ids.len()).map_err(|_| {
                ExecutionPackError::InvalidPack("SIMD unsupported count exceeds u32".into())
            })?;
        let shard_count = u32::try_from(self.serialized_shards.len()).map_err(|_| {
            ExecutionPackError::InvalidPack("Hyperscan shard count exceeds u32".into())
        })?;
        let phase2_scope_count = u32::try_from(self.phase2_scopes.len()).map_err(|_| {
            ExecutionPackError::InvalidPack("Hyperscan phase-two scope count exceeds u32".into())
        })?;
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&[0; 6]);
        out.extend_from_slice(&self.detector_ir_digest);
        out.extend_from_slice(&pattern_count.to_le_bytes());
        out.extend_from_slice(&unsupported_count.to_le_bytes());
        out.extend_from_slice(&shard_count.to_le_bytes());
        out.extend_from_slice(&phase2_scope_count.to_le_bytes());
        for pattern in &self.patterns {
            out.extend_from_slice(&pattern.detector_index.to_le_bytes());
            out.extend_from_slice(&pattern.pattern_index.to_le_bytes());
            out.push(u8::from(pattern.reports_start));
            out.extend_from_slice(&[0; 3]);
            write_bytes(&mut out, pattern.regex.as_bytes())?;
            write_indices(
                &mut out,
                &pattern.scalar_pattern_indices,
                "SIMD scalar fanout",
            )?;
            write_indices(&mut out, &pattern.ac_map_indices, "SIMD AC fanout")?;
        }
        for id in &self.unsupported_pattern_ids {
            out.extend_from_slice(&id.to_le_bytes());
        }
        for shard in &self.serialized_shards {
            out.extend_from_slice(blake3::hash(shard).as_bytes());
            write_bytes(&mut out, shard)?;
        }
        for scope in &self.phase2_scopes {
            out.push(scope.scope as u8);
            out.extend_from_slice(&[0; 3]);
            write_indices(
                &mut out,
                &scope.pattern_indices,
                "Hyperscan phase-two scope mapping",
            )?;
            write_phase2_database(&mut out, scope.full.as_ref())?;
            write_phase2_database(&mut out, scope.ascii_lean.as_ref())?;
        }
        Ok(out)
    }

    #[cfg(feature = "simd")]
    pub fn decode(bytes: &[u8], expected_ir_digest: [u8; 32]) -> Result<Self, ExecutionPackError> {
        Self::decode_with_storage(bytes, expected_ir_digest, |_| Ok(None), |_| Ok(()), true)
    }

    #[cfg(feature = "simd")]
    pub fn decode_with_release(
        bytes: &[u8],
        expected_ir_digest: [u8; 32],
        release: impl FnMut(&[u8]) -> Result<(), ExecutionPackError>,
    ) -> Result<Self, ExecutionPackError> {
        Self::decode_with_storage(bytes, expected_ir_digest, |_| Ok(None), release, true)
    }

    #[cfg(feature = "simd")]
    pub fn decode_mapped_with_release(
        bytes: &[u8],
        expected_ir_digest: [u8; 32],
        mut mapped: impl FnMut(
            &[u8],
        )
            -> Result<super::runtime::ExecutionPackMappedBytes, ExecutionPackError>,
        release: impl FnMut(&[u8]) -> Result<(), ExecutionPackError>,
    ) -> Result<Self, ExecutionPackError> {
        Self::decode_with_storage(
            bytes,
            expected_ir_digest,
            |bytes| mapped(bytes).map(Some),
            release,
            true,
        )
    }

    /// Decode native shards whose exact framing and bytes were already covered
    /// by the installation signature, without hashing the full payload again.
    #[cfg(feature = "simd")]
    pub(crate) fn decode_authenticated_mapped_with_release(
        bytes: &[u8],
        expected_ir_digest: [u8; 32],
        mut mapped: impl FnMut(
            &[u8],
        )
            -> Result<super::runtime::ExecutionPackMappedBytes, ExecutionPackError>,
        release: impl FnMut(&[u8]) -> Result<(), ExecutionPackError>,
    ) -> Result<Self, ExecutionPackError> {
        Self::decode_with_storage(
            bytes,
            expected_ir_digest,
            |bytes| mapped(bytes).map(Some),
            release,
            false,
        )
    }

    #[cfg(feature = "simd")]
    fn decode_with_storage(
        bytes: &[u8],
        expected_ir_digest: [u8; 32],
        mut mapped: impl FnMut(
            &[u8],
        ) -> Result<
            Option<super::runtime::ExecutionPackMappedBytes>,
            ExecutionPackError,
        >,
        mut release: impl FnMut(&[u8]) -> Result<(), ExecutionPackError>,
        verify_shard_digests: bool,
    ) -> Result<Self, ExecutionPackError> {
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != MAGIC {
            return Err(ExecutionPackError::InvalidPack(
                "Hyperscan SIMD program magic is invalid".into(),
            ));
        }
        let version = cursor.u16()?;
        if version != HYPERSCAN_SIMD_PROGRAM_VERSION {
            return Err(ExecutionPackError::Incompatible(format!(
                "Hyperscan SIMD program version {version} is unsupported; this binary requires {HYPERSCAN_SIMD_PROGRAM_VERSION}"
            )));
        }
        if cursor.take(6)?.iter().any(|byte| *byte != 0) {
            return Err(ExecutionPackError::InvalidPack(
                "Hyperscan SIMD program reserved bytes are nonzero".into(),
            ));
        }
        let detector_ir_digest: [u8; 32] = cursor.take(32)?.try_into().expect("fixed digest");
        if detector_ir_digest != expected_ir_digest {
            return Err(ExecutionPackError::InvalidPack(
                "Hyperscan SIMD program detector IR identity does not match its pack".into(),
            ));
        }
        let pattern_count = cursor.count("SIMD pattern")?;
        let unsupported_count = cursor.count("SIMD unsupported")?;
        let shard_count = cursor.count("Hyperscan shard")?;
        let phase2_scope_count = cursor.count("Hyperscan phase-two scope")?;
        let mut patterns = Vec::with_capacity(pattern_count);
        for _ in 0..pattern_count {
            let detector_index = cursor.u32()?;
            let pattern_index = cursor.u32()?;
            let reports_start = match cursor.take(1)?[0] {
                0 => false,
                1 => true,
                _ => {
                    return Err(ExecutionPackError::InvalidPack(
                        "SIMD reports-start flag is invalid".into(),
                    ))
                }
            };
            if cursor.take(3)?.iter().any(|byte| *byte != 0) {
                return Err(ExecutionPackError::InvalidPack(
                    "SIMD pattern reserved bytes are nonzero".into(),
                ));
            }
            let regex = String::from_utf8(cursor.bytes()?.to_vec()).map_err(|error| {
                ExecutionPackError::InvalidPack(format!("SIMD regex is not UTF-8: {error}"))
            })?;
            let scalar_pattern_indices = cursor.indices("SIMD scalar fanout")?;
            let ac_map_indices = cursor.indices("SIMD AC fanout")?;
            patterns.push(HyperscanPatternProgram {
                detector_index,
                pattern_index,
                reports_start,
                regex,
                scalar_pattern_indices,
                ac_map_indices,
            });
        }
        let mut unsupported_pattern_ids = Vec::with_capacity(unsupported_count);
        for _ in 0..unsupported_count {
            unsupported_pattern_ids.push(cursor.u32()?);
        }
        let mut shard_interner = HashMap::<[u8; 32], SerializedHyperscanShard>::new();
        let mut serialized_shards = Vec::with_capacity(shard_count);
        for index in 0..shard_count {
            serialized_shards.push(read_shared_shard(
                &mut cursor,
                index,
                "Hyperscan SIMD",
                &mut shard_interner,
                &mut mapped,
                &mut release,
                verify_shard_digests,
            )?);
        }
        let mut phase2_scopes = Vec::with_capacity(phase2_scope_count);
        for _ in 0..phase2_scope_count {
            let scope = match cursor.take(1)?[0] {
                0 => HyperscanPhase2Scope::Full,
                1 => HyperscanPhase2Scope::AnchorResidual,
                2 => HyperscanPhase2Scope::LocalizedResidual,
                value => {
                    return Err(ExecutionPackError::InvalidPack(format!(
                        "Hyperscan phase-two scope id {value} is invalid"
                    )))
                }
            };
            if cursor.take(3)?.iter().any(|byte| *byte != 0) {
                return Err(ExecutionPackError::InvalidPack(
                    "Hyperscan phase-two scope reserved bytes are nonzero".into(),
                ));
            }
            let pattern_indices = cursor.indices("Hyperscan phase-two scope mapping")?;
            let full = read_phase2_database(
                &mut cursor,
                &mut shard_interner,
                &mut mapped,
                &mut release,
                verify_shard_digests,
            )?;
            let ascii_lean = read_phase2_database(
                &mut cursor,
                &mut shard_interner,
                &mut mapped,
                &mut release,
                verify_shard_digests,
            )?;
            phase2_scopes.push(HyperscanPhase2ScopeProgram {
                scope,
                pattern_indices,
                full,
                ascii_lean,
            });
        }
        if !cursor.is_empty() {
            return Err(ExecutionPackError::InvalidPack(
                "Hyperscan SIMD program has trailing bytes".into(),
            ));
        }
        let program = Self {
            version,
            detector_ir_digest,
            patterns,
            unsupported_pattern_ids,
            serialized_shards,
            phase2_scopes,
        };
        program.validate_structure()?;
        // Every field has one fixed-width encoding, byte fields carry exact
        // lengths, reserved bytes are zero, rows are canonically ordered, and
        // trailing bytes are rejected above. Re-encoding here previously
        // allocated a second copy of every native shard, adding the entire
        // backend section to scan-time peak RSS without strengthening parsing.
        Ok(program)
    }

    fn validate_structure(&self) -> Result<(), ExecutionPackError> {
        if self.version != HYPERSCAN_SIMD_PROGRAM_VERSION {
            return Err(ExecutionPackError::Incompatible(format!(
                "Hyperscan SIMD program version {} is unsupported; this binary requires {}",
                self.version, HYPERSCAN_SIMD_PROGRAM_VERSION
            )));
        }
        let mut seen_ac = HashSet::new();
        for (index, pattern) in self.patterns.iter().enumerate() {
            if pattern.pattern_index as usize != index {
                return Err(ExecutionPackError::InvalidPack(format!(
                    "SIMD pattern row {index} claims canonical pattern id {}",
                    pattern.pattern_index
                )));
            }
            if pattern.regex.is_empty() {
                return Err(ExecutionPackError::InvalidPack(format!(
                    "SIMD pattern row {index} has an empty regex"
                )));
            }
            validate_strict_indices(
                &pattern.scalar_pattern_indices,
                &format!("SIMD pattern {index} scalar mapping"),
            )?;
            validate_strict_indices(
                &pattern.ac_map_indices,
                &format!("SIMD pattern {index} AC mapping"),
            )?;
            if pattern.ac_map_indices.is_empty() {
                return Err(ExecutionPackError::InvalidPack(format!(
                    "SIMD pattern row {index} has no canonical AC mapping"
                )));
            }
            for &ac_index in &pattern.ac_map_indices {
                if !seen_ac.insert(ac_index) {
                    return Err(ExecutionPackError::InvalidPack(format!(
                        "SIMD AC mapping index {ac_index} is owned by more than one pattern"
                    )));
                }
            }
        }
        validate_strict_indices(
            &self.unsupported_pattern_ids,
            "SIMD unsupported pattern IDs",
        )?;
        for &id in &self.unsupported_pattern_ids {
            if id as usize >= self.patterns.len() {
                return Err(ExecutionPackError::InvalidPack(format!(
                    "SIMD unsupported pattern id {id} exceeds pattern count {}",
                    self.patterns.len()
                )));
            }
        }
        let supported_count = self
            .patterns
            .len()
            .saturating_sub(self.unsupported_pattern_ids.len());
        if self.serialized_shards.is_empty() != (supported_count == 0) {
            return Err(ExecutionPackError::InvalidPack(format!(
                "SIMD program has {} supported pattern(s) but {} native shard(s)",
                supported_count,
                self.serialized_shards.len()
            )));
        }
        if self.serialized_shards.iter().any(|shard| shard.is_empty()) {
            return Err(ExecutionPackError::InvalidPack(
                "SIMD program contains an empty native shard".into(),
            ));
        }
        if self.phase2_scopes.len() != HyperscanPhase2Scope::ALL.len() {
            return Err(ExecutionPackError::InvalidPack(format!(
                "SIMD program has {} phase-two scopes; exactly {} are required",
                self.phase2_scopes.len(),
                HyperscanPhase2Scope::ALL.len()
            )));
        }
        for (scope, expected_scope) in self.phase2_scopes.iter().zip(HyperscanPhase2Scope::ALL) {
            if scope.scope != expected_scope {
                return Err(ExecutionPackError::InvalidPack(
                    "SIMD phase-two scopes are not in canonical order".into(),
                ));
            }
            validate_strict_indices(
                &scope.pattern_indices,
                &format!("SIMD phase-two {:?} scope mapping", scope.scope),
            )?;
            if let Some(database) = &scope.full {
                validate_phase2_database(database, &scope.pattern_indices, "full")?;
            }
            if let Some(database) = &scope.ascii_lean {
                validate_phase2_database(database, &scope.pattern_indices, "ASCII")?;
            }
            if scope.full.is_none() && scope.ascii_lean.is_some() {
                return Err(ExecutionPackError::InvalidPack(format!(
                    "SIMD phase-two {:?} scope has an ASCII database without a full database",
                    scope.scope
                )));
            }
        }
        Ok(())
    }

    #[doc(hidden)]
    #[cfg(feature = "simd")]
    pub fn compile_with_opts_invocations() -> usize {
        crate::simd::backend::HsScanner::compile_with_opts_invocations()
    }

    #[doc(hidden)]
    #[cfg(all(feature = "simd", debug_assertions))]
    pub fn verified_shard_bytes() -> usize {
        VERIFIED_SHARD_BYTES.load(std::sync::atomic::Ordering::Relaxed)
    }
}

fn validate_phase2_database(
    database: &HyperscanPhase2DatabaseProgram,
    scope_indices: &[u32],
    label: &str,
) -> Result<(), ExecutionPackError> {
    validate_strict_indices(
        &database.pattern_indices,
        &format!("SIMD phase-two {label} database mapping"),
    )?;
    if database
        .pattern_indices
        .iter()
        .any(|index| scope_indices.binary_search(index).is_err())
    {
        return Err(ExecutionPackError::InvalidPack(format!(
            "SIMD phase-two {label} database maps a pattern outside its scope"
        )));
    }
    validate_strict_indices(
        &database.unsupported_pattern_ids,
        &format!("SIMD phase-two {label} unsupported IDs"),
    )?;
    if database
        .unsupported_pattern_ids
        .iter()
        .any(|&id| id as usize >= database.pattern_indices.len())
    {
        return Err(ExecutionPackError::InvalidPack(format!(
            "SIMD phase-two {label} database has an unsupported ID outside its mapping"
        )));
    }
    let supported_count = database
        .pattern_indices
        .len()
        .saturating_sub(database.unsupported_pattern_ids.len());
    if database.serialized_shards.is_empty() != (supported_count == 0) {
        return Err(ExecutionPackError::InvalidPack(format!(
            "SIMD phase-two {label} database has {supported_count} supported pattern(s) but {} shard(s)",
            database.serialized_shards.len()
        )));
    }
    if database
        .serialized_shards
        .iter()
        .any(|shard| shard.is_empty())
    {
        return Err(ExecutionPackError::InvalidPack(format!(
            "SIMD phase-two {label} database contains an empty shard"
        )));
    }
    Ok(())
}

fn write_phase2_database(
    out: &mut Vec<u8>,
    database: Option<&HyperscanPhase2DatabaseProgram>,
) -> Result<(), ExecutionPackError> {
    let Some(database) = database else {
        out.push(0);
        return Ok(());
    };
    out.push(1);
    write_indices(
        out,
        &database.pattern_indices,
        "Hyperscan phase-two database mapping",
    )?;
    write_indices(
        out,
        &database.unsupported_pattern_ids,
        "Hyperscan phase-two unsupported IDs",
    )?;
    let shard_count = u32::try_from(database.serialized_shards.len()).map_err(|_| {
        ExecutionPackError::InvalidPack("Hyperscan phase-two shard count exceeds u32".into())
    })?;
    out.extend_from_slice(&shard_count.to_le_bytes());
    for shard in &database.serialized_shards {
        out.extend_from_slice(blake3::hash(shard).as_bytes());
        write_bytes(out, shard)?;
    }
    Ok(())
}

fn read_shared_shard(
    cursor: &mut Cursor<'_>,
    index: usize,
    label: &str,
    interner: &mut HashMap<[u8; 32], SerializedHyperscanShard>,
    mapped: &mut impl FnMut(
        &[u8],
    ) -> Result<
        Option<super::runtime::ExecutionPackMappedBytes>,
        ExecutionPackError,
    >,
    release: &mut impl FnMut(&[u8]) -> Result<(), ExecutionPackError>,
    verify_digest: bool,
) -> Result<SerializedHyperscanShard, ExecutionPackError> {
    let expected_digest: [u8; 32] = cursor.take(32)?.try_into().expect("fixed digest");
    let bytes = cursor.bytes()?;
    if !verify_digest {
        if let Some(shared) = interner.get(&expected_digest) {
            if shared.len() != bytes.len() {
                return Err(ExecutionPackError::InvalidPack(format!(
                    "{label} shard {index} repeats a signed digest with a different length"
                )));
            }
            release(bytes)?;
            return Ok(shared.clone());
        }
        let shared = if let Some(mapped) = mapped(bytes)? {
            SerializedHyperscanShard::from_mapped(mapped)
        } else {
            SerializedHyperscanShard::from(bytes)
        };
        release(bytes)?;
        interner.insert(expected_digest, shared.clone());
        return Ok(shared);
    }
    #[cfg(debug_assertions)]
    VERIFIED_SHARD_BYTES.fetch_add(bytes.len(), std::sync::atomic::Ordering::Relaxed);
    let mut hasher = blake3::Hasher::new();
    let shared = if let Some(shared) = interner.get(&expected_digest) {
        let mut exact_match = shared.len() == bytes.len();
        for start in (0..bytes.len()).step_by(SHARD_STREAM_CHUNK_BYTES) {
            let end = start
                .saturating_add(SHARD_STREAM_CHUNK_BYTES)
                .min(bytes.len());
            let chunk = &bytes[start..end];
            hasher.update(chunk);
            if exact_match && &shared[start..end] != chunk {
                exact_match = false;
            }
            release(chunk)?;
            shared.release_resident_range(start..end)?;
        }
        if *hasher.finalize().as_bytes() != expected_digest {
            return Err(ExecutionPackError::InvalidPack(format!(
                "{label} shard {index} is corrupt; its content digest does not match"
            )));
        }
        if !exact_match {
            return Err(ExecutionPackError::InvalidPack(format!(
                "{label} shard {index} collides with different authenticated bytes"
            )));
        }
        shared.clone()
    } else if let Some(mapped) = mapped(bytes)? {
        for chunk in bytes.chunks(SHARD_STREAM_CHUNK_BYTES) {
            hasher.update(chunk);
            release(chunk)?;
        }
        if *hasher.finalize().as_bytes() != expected_digest {
            return Err(ExecutionPackError::InvalidPack(format!(
                "{label} shard {index} is corrupt; its content digest does not match"
            )));
        }
        let shared = SerializedHyperscanShard::from_mapped(mapped);
        interner.insert(expected_digest, shared.clone());
        shared
    } else {
        let mut owned = std::sync::Arc::<[u8]>::new_uninit_slice(bytes.len());
        let target = std::sync::Arc::get_mut(&mut owned)
            .expect("new native shard allocation is uniquely owned");
        for start in (0..bytes.len()).step_by(SHARD_STREAM_CHUNK_BYTES) {
            let end = start
                .saturating_add(SHARD_STREAM_CHUNK_BYTES)
                .min(bytes.len());
            let chunk = &bytes[start..end];
            hasher.update(chunk);
            // SAFETY: chunk is valid memory of chunk.len() bytes; target has capacity bytes.len() and chunks are non-overlapping.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    chunk.as_ptr(),
                    target.as_mut_ptr().add(start).cast::<u8>(),
                    chunk.len(),
                );
            }
            release(chunk)?;
        }
        if *hasher.finalize().as_bytes() != expected_digest {
            return Err(ExecutionPackError::InvalidPack(format!(
                "{label} shard {index} is corrupt; its content digest does not match"
            )));
        }
        // SAFETY: every byte from 0..bytes.len() was written by the chunk loop above.
        let shared = SerializedHyperscanShard(SerializedHyperscanShardStorage::Owned(unsafe {
            owned.assume_init()
        }));
        interner.insert(expected_digest, shared.clone());
        shared
    };
    Ok(shared)
}

fn read_phase2_database(
    cursor: &mut Cursor<'_>,
    interner: &mut HashMap<[u8; 32], SerializedHyperscanShard>,
    mapped: &mut impl FnMut(
        &[u8],
    ) -> Result<
        Option<super::runtime::ExecutionPackMappedBytes>,
        ExecutionPackError,
    >,
    release: &mut impl FnMut(&[u8]) -> Result<(), ExecutionPackError>,
    verify_shard_digests: bool,
) -> Result<Option<HyperscanPhase2DatabaseProgram>, ExecutionPackError> {
    match cursor.take(1)?[0] {
        0 => Ok(None),
        1 => {
            let pattern_indices = cursor.indices("Hyperscan phase-two database mapping")?;
            let unsupported_pattern_ids = cursor.indices("Hyperscan phase-two unsupported IDs")?;
            let shard_count = cursor.count("Hyperscan phase-two shard")?;
            let mut serialized_shards = Vec::with_capacity(shard_count);
            for index in 0..shard_count {
                serialized_shards.push(read_shared_shard(
                    cursor,
                    index,
                    "Hyperscan phase-two",
                    interner,
                    mapped,
                    release,
                    verify_shard_digests,
                )?);
            }
            Ok(Some(HyperscanPhase2DatabaseProgram {
                pattern_indices,
                unsupported_pattern_ids,
                serialized_shards,
            }))
        }
        value => Err(ExecutionPackError::InvalidPack(format!(
            "Hyperscan phase-two database presence flag {value} is invalid"
        ))),
    }
}

fn validate_strict_indices(indices: &[u32], label: &str) -> Result<(), ExecutionPackError> {
    if indices.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ExecutionPackError::InvalidPack(format!(
            "{label} are not strictly increasing"
        )));
    }
    Ok(())
}

fn write_indices(
    out: &mut Vec<u8>,
    indices: &[u32],
    label: &str,
) -> Result<(), ExecutionPackError> {
    let count = u32::try_from(indices.len())
        .map_err(|_| ExecutionPackError::InvalidPack(format!("{label} exceeds u32")))?;
    out.extend_from_slice(&count.to_le_bytes());
    for index in indices {
        out.extend_from_slice(&index.to_le_bytes());
    }
    Ok(())
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ExecutionPackError> {
    let len = u64::try_from(bytes.len())
        .map_err(|_| ExecutionPackError::InvalidPack("SIMD byte field exceeds u64".into()))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ExecutionPackError> {
        let end = self.offset.checked_add(len).ok_or_else(|| {
            ExecutionPackError::InvalidPack("Hyperscan SIMD program length overflow".into())
        })?;
        let value = self.bytes.get(self.offset..end).ok_or_else(|| {
            ExecutionPackError::InvalidPack("Hyperscan SIMD program is truncated".into())
        })?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, ExecutionPackError> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("fixed u16"),
        ))
    }

    fn u32(&mut self) -> Result<u32, ExecutionPackError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("fixed u32"),
        ))
    }

    fn count(&mut self, label: &str) -> Result<usize, ExecutionPackError> {
        let count = self.u32()? as usize;
        if count > self.bytes.len().saturating_sub(self.offset) / 4 {
            return Err(ExecutionPackError::InvalidPack(format!(
                "{label} count exceeds the remaining program bytes"
            )));
        }
        Ok(count)
    }

    fn indices(&mut self, label: &str) -> Result<Vec<u32>, ExecutionPackError> {
        let count = self.count(label)?;
        (0..count).map(|_| self.u32()).collect()
    }

    fn bytes(&mut self) -> Result<&'a [u8], ExecutionPackError> {
        let len = usize::try_from(u64::from_le_bytes(
            self.take(8)?.try_into().expect("fixed u64"),
        ))
        .map_err(|_| ExecutionPackError::InvalidPack("SIMD byte length exceeds usize".into()))?;
        self.take(len)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
