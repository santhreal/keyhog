use super::format::{
    ExecutionPackIdentity, ExecutionPackSectionKind, SectionEntry, EXECUTION_PACK_FORMAT_VERSION,
    EXECUTION_PACK_HEADER_LEN, EXECUTION_PACK_MAGIC, EXECUTION_PACK_SECTION_ENTRY_LEN,
};
use super::{ExecutionPackError, ExecutionPackSignature, ExecutionPackSigningKey};
use memmap2::{Mmap, MmapOptions};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::ops::Range;
use std::path::{Path, PathBuf};

const AUTHENTICATION_HASH_CHUNK_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResidentByteOwner {
    PackMetadata,
    DetectorIr,
    DetectorPlan,
    RouteClassifier,
    RegexPrograms,
    SuppressionPolicy,
    SelectedBackend,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResidentByteOwnership {
    pub owner: ResidentByteOwner,
    pub mapped_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionPackByteLedger {
    pub mapped_bytes: u64,
    pub ownership: Vec<ResidentByteOwnership>,
}

impl ExecutionPackByteLedger {
    pub fn owned_bytes(&self) -> u64 {
        self.ownership
            .iter()
            .fold(0_u64, |total, row| total.saturating_add(row.mapped_bytes))
    }
}

#[derive(Clone)]
pub struct ExecutionPackMappedBytes {
    mapping: std::sync::Arc<Mmap>,
    range: Range<usize>,
    path: PathBuf,
}

impl ExecutionPackMappedBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.mapping[self.range.clone()]
    }

    pub fn release_resident_pages(&self) -> Result<(), ExecutionPackError> {
        release_mapping_slice(
            &self.mapping,
            &self.path,
            self.as_bytes(),
            "discard validated native shard pages",
        )
    }

    pub fn release_resident_range(&self, range: Range<usize>) -> Result<(), ExecutionPackError> {
        if range.start > range.end || range.end > self.range.len() {
            return Err(ExecutionPackError::InvalidPack(
                "native shard release range is outside its mapped bytes".into(),
            ));
        }
        let absolute = (self.range.start + range.start)..(self.range.start + range.end);
        release_mapping_slice(
            &self.mapping,
            &self.path,
            &self.mapping[absolute],
            "discard compared native shard pages",
        )
    }
}

impl std::fmt::Debug for ExecutionPackMappedBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutionPackMappedBytes")
            .field("len", &self.range.len())
            .finish_non_exhaustive()
    }
}

impl std::ops::Deref for ExecutionPackMappedBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl AsRef<[u8]> for ExecutionPackMappedBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl PartialEq for ExecutionPackMappedBytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for ExecutionPackMappedBytes {}

pub struct ExecutionPack {
    mapping: std::sync::Arc<Mmap>,
    path: PathBuf,
    identity: ExecutionPackIdentity,
    content_digest: [u8; 32],
    sections: Vec<SectionEntry>,
    signature_authenticated: bool,
}

impl std::fmt::Debug for ExecutionPack {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutionPack")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .field(
                "content_digest",
                &keyhog_core::hex_encode(&self.content_digest),
            )
            .field("signature_authenticated", &self.signature_authenticated)
            .finish_non_exhaustive()
    }
}

impl ExecutionPack {
    pub fn open(
        path: impl AsRef<Path>,
        expected: ExecutionPackIdentity,
    ) -> Result<Self, ExecutionPackError> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|source| ExecutionPackError::Io {
            operation: "open",
            path: path.to_path_buf(),
            source,
        })?;
        // The mapping is read-only and the file handle is never exposed for mutation.
        // Install/update publication must rename an immutable generation into place;
        // replacing the path cannot change pages held by this mapping.
        let mapping =
            unsafe { MmapOptions::new().map(&file) }.map_err(|source| ExecutionPackError::Io {
                operation: "map",
                path: path.to_path_buf(),
                source,
            })?;
        Self::from_mapping(mapping, path.to_path_buf(), Some(expected), None, true)
    }

    /// Maps and authenticates one immutable pack generation before exposing any section.
    pub fn open_authenticated(
        path: impl AsRef<Path>,
        signature_path: impl AsRef<Path>,
        expected: ExecutionPackIdentity,
        signing_key: &ExecutionPackSigningKey,
    ) -> Result<Self, ExecutionPackError> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|source| ExecutionPackError::Io {
            operation: "open",
            path: path.to_path_buf(),
            source,
        })?;
        let mapping =
            unsafe { MmapOptions::new().map(&file) }.map_err(|source| ExecutionPackError::Io {
                operation: "map",
                path: path.to_path_buf(),
                source,
            })?;
        let pack = Self::from_mapping(
            mapping,
            path.to_path_buf(),
            Some(expected),
            Some((signature_path.as_ref(), signing_key)),
            false,
        )?;
        pack.release_resident_pages()?;
        Ok(pack)
    }

    /// Maps a signed pack and discovers its full identity from the authenticated header.
    /// Callers must still compare the returned identity with their selected manifest row.
    pub fn open_authenticated_discover(
        path: impl AsRef<Path>,
        signature_path: impl AsRef<Path>,
        signing_key: &ExecutionPackSigningKey,
    ) -> Result<Self, ExecutionPackError> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|source| ExecutionPackError::Io {
            operation: "open",
            path: path.to_path_buf(),
            source,
        })?;
        let mapping =
            unsafe { MmapOptions::new().map(&file) }.map_err(|source| ExecutionPackError::Io {
                operation: "map",
                path: path.to_path_buf(),
                source,
            })?;
        let pack = Self::from_mapping(
            mapping,
            path.to_path_buf(),
            None,
            Some((signature_path.as_ref(), signing_key)),
            false,
        )?;
        pack.release_resident_pages()?;
        Ok(pack)
    }

    /// Drop validation/authentication pages from this process before callers
    /// decode individual sections. The immutable file remains in the page cache,
    /// so later section faults do not repeat storage I/O, but the whole pack no
    /// longer overlaps decoded runtime state in RSS.
    pub fn release_resident_pages(&self) -> Result<(), ExecutionPackError> {
        release_entire_mapping(&self.mapping, &self.path, "discard authenticated pages")
    }
    /// Drop full pages covered by one decoded section field while retaining the
    /// immutable mapping and any partial edge pages. Callers must pass a slice
    /// borrowed from this pack; rejecting foreign slices prevents `madvise`
    /// from touching allocator-owned memory.
    pub fn release_mapped_bytes(&self, bytes: &[u8]) -> Result<(), ExecutionPackError> {
        release_mapping_slice(
            &self.mapping,
            &self.path,
            bytes,
            "discard decoded shard pages",
        )
    }

    /// Hash one mapped field in bounded windows and discard each window after
    /// consumption so identity validation cannot establish the RSS high-water.
    pub fn digest_mapped_bytes_and_release(
        &self,
        bytes: &[u8],
    ) -> Result<[u8; 32], ExecutionPackError> {
        let range = mapping_slice_range(&self.mapping, bytes)?;
        let mut hasher = blake3::Hasher::new();
        update_mapping_and_release(
            &self.mapping,
            &self.path,
            range,
            "discard section-identity pages",
            |chunk| {
                hasher.update(chunk);
            },
        )?;
        Ok(*hasher.finalize().as_bytes())
    }
    /// Retain an immutable zero-copy view of a validated field in this pack.
    /// The view keeps the mapping alive after the pack metadata is dropped.
    pub fn mapped_bytes(
        &self,
        bytes: &[u8],
    ) -> Result<ExecutionPackMappedBytes, ExecutionPackError> {
        let range = mapping_slice_range(&self.mapping, bytes)?;
        Ok(ExecutionPackMappedBytes {
            mapping: std::sync::Arc::clone(&self.mapping),
            range,
            path: self.path.clone(),
        })
    }

    pub const fn identity(&self) -> ExecutionPackIdentity {
        self.identity
    }

    pub const fn content_digest(&self) -> [u8; 32] {
        self.content_digest
    }

    /// The full immutable mapping has already matched its installation signature.
    pub(crate) const fn signature_authenticated(&self) -> bool {
        self.signature_authenticated
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Attribute every mapped byte to one architectural owner. File-backed
    /// pages may not all be physically resident at once; this ledger defines
    /// ownership for any page the kernel does make resident.
    pub fn byte_ledger(&self) -> ExecutionPackByteLedger {
        use ResidentByteOwner as Owner;
        let mut totals = std::collections::BTreeMap::<Owner, u64>::new();
        let mut section_bytes = 0_u64;
        for section in &self.sections {
            let owner = match section.kind {
                ExecutionPackSectionKind::DetectorIr => Owner::DetectorIr,
                ExecutionPackSectionKind::DetectorPlan => Owner::DetectorPlan,
                ExecutionPackSectionKind::LiteralIndex => Owner::RouteClassifier,
                ExecutionPackSectionKind::RegexPrograms => Owner::RegexPrograms,
                ExecutionPackSectionKind::SuppressionPolicy => Owner::SuppressionPolicy,
                ExecutionPackSectionKind::BackendProgram => Owner::SelectedBackend,
            };
            section_bytes = section_bytes.saturating_add(section.len);
            let total = totals.entry(owner).or_default();
            *total = total.saturating_add(section.len);
        }
        let mapped_bytes = self.mapping.len() as u64;
        totals.insert(
            Owner::PackMetadata,
            mapped_bytes.saturating_sub(section_bytes),
        );
        ExecutionPackByteLedger {
            mapped_bytes,
            ownership: totals
                .into_iter()
                .map(|(owner, mapped_bytes)| ResidentByteOwnership {
                    owner,
                    mapped_bytes,
                })
                .collect(),
        }
    }

    pub fn section(&self, kind: ExecutionPackSectionKind) -> Option<&[u8]> {
        let entry = self.sections.iter().find(|entry| entry.kind == kind)?;
        let start = entry.offset as usize;
        let end = start + entry.len as usize;
        Some(&self.mapping[start..end])
    }

    fn from_mapping(
        mapping: Mmap,
        path: PathBuf,
        expected: Option<ExecutionPackIdentity>,
        signature_auth: Option<(&Path, &ExecutionPackSigningKey)>,
        verify_content_digest: bool,
    ) -> Result<Self, ExecutionPackError> {
        let bytes = mapping.as_ref();
        if bytes.len() < EXECUTION_PACK_HEADER_LEN {
            return Err(ExecutionPackError::InvalidPack(format!(
                "{} is {} bytes; execution-pack header needs {} bytes",
                path.display(),
                bytes.len(),
                EXECUTION_PACK_HEADER_LEN
            )));
        }
        if bytes[0..8] != EXECUTION_PACK_MAGIC {
            return Err(ExecutionPackError::InvalidPack(format!(
                "{} has an invalid execution-pack magic",
                path.display()
            )));
        }
        let version = read_u16(bytes, 8);
        if version != EXECUTION_PACK_FORMAT_VERSION {
            return Err(ExecutionPackError::Incompatible(format!(
                "{} uses execution-pack format {version}; this binary requires {}",
                path.display(),
                EXECUTION_PACK_FORMAT_VERSION
            )));
        }
        let header_len = read_u16(bytes, 10) as usize;
        if header_len != EXECUTION_PACK_HEADER_LEN {
            return Err(ExecutionPackError::InvalidPack(format!(
                "{} declares header length {header_len}; expected {}",
                path.display(),
                EXECUTION_PACK_HEADER_LEN
            )));
        }
        if bytes[314..EXECUTION_PACK_HEADER_LEN]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(ExecutionPackError::Incompatible(format!(
                "{} uses nonzero reserved execution-pack header bytes",
                path.display()
            )));
        }
        let content_digest = array32(bytes, 248);

        let mut signature_authenticated = false;
        if let Some((signature_path, signing_key)) = signature_auth {
            authenticate_pack_signature(
                &mapping,
                &path,
                content_digest,
                signature_path,
                signing_key,
            )?;
            signature_authenticated = true;
        } else if verify_content_digest {
            verify_content_digest_mapping(&mapping, &path, content_digest)?;
        }

        let declared_len = usize::try_from(read_u64(bytes, 16)).map_err(|_| {
            ExecutionPackError::InvalidPack(format!(
                "{} length does not fit this target",
                path.display()
            ))
        })?;
        if declared_len != bytes.len() {
            return Err(ExecutionPackError::InvalidPack(format!(
                "{} declares {declared_len} bytes but maps {} bytes",
                path.display(),
                bytes.len()
            )));
        }
        let section_count = read_u32(bytes, 12) as usize;
        if section_count == 0 || section_count > 64 {
            return Err(ExecutionPackError::InvalidPack(format!(
                "{} declares invalid section count {section_count}",
                path.display()
            )));
        }
        let identity = decode_identity_header(bytes, &path)?;
        let stored_identity_digest = array32(bytes, 280);
        if stored_identity_digest != identity.digest() {
            return Err(ExecutionPackError::InvalidPack(format!(
                "{} execution-pack identity digest mismatch; reinstall this generation",
                path.display()
            )));
        }
        if let Some(expected) = expected {
            validate_identity(&path, identity, expected)?;
        }

        let table_end = EXECUTION_PACK_HEADER_LEN
            .checked_add(section_count * EXECUTION_PACK_SECTION_ENTRY_LEN)
            .ok_or_else(|| {
                ExecutionPackError::InvalidPack(format!(
                    "{} section table overflows",
                    path.display()
                ))
            })?;
        if table_end > bytes.len() {
            return Err(ExecutionPackError::InvalidPack(format!(
                "{} section table extends beyond the mapped file",
                path.display()
            )));
        }

        let mut seen = BTreeSet::new();
        let mut sections = Vec::with_capacity(section_count);
        let mut previous_end = table_end;
        for index in 0..section_count {
            let base = EXECUTION_PACK_HEADER_LEN + index * EXECUTION_PACK_SECTION_ENTRY_LEN;
            let raw_kind = read_u16(bytes, base);
            let kind = ExecutionPackSectionKind::from_u16(raw_kind).ok_or_else(|| {
                ExecutionPackError::Incompatible(format!(
                    "{} uses unknown execution-pack section kind {raw_kind}",
                    path.display()
                ))
            })?;
            if !seen.insert(kind) {
                return Err(ExecutionPackError::InvalidPack(format!(
                    "{} repeats execution-pack section {kind}",
                    path.display()
                )));
            }
            let schema_version = read_u16(bytes, base + 2);
            if schema_version != kind.schema_version() {
                return Err(ExecutionPackError::Incompatible(format!(
                    "{} section {kind} uses schema {schema_version}; this binary requires {}; run keyhog compile-execution-packs to rebuild",
                    path.display(),
                    kind.schema_version()
                )));
            }
            let offset = usize::try_from(read_u64(bytes, base + 4)).map_err(|_| {
                ExecutionPackError::InvalidPack(format!(
                    "{} section {kind} offset does not fit this target",
                    path.display()
                ))
            })?;
            let len = usize::try_from(read_u64(bytes, base + 12)).map_err(|_| {
                ExecutionPackError::InvalidPack(format!(
                    "{} section {kind} length does not fit this target",
                    path.display()
                ))
            })?;
            let alignment = read_u32(bytes, base + 20) as usize;
            let end = offset.checked_add(len).ok_or_else(|| {
                ExecutionPackError::InvalidPack(format!(
                    "{} section {kind} range overflows",
                    path.display()
                ))
            })?;
            if len == 0 || alignment == 0 || !alignment.is_power_of_two() || alignment > 4096 {
                return Err(ExecutionPackError::InvalidPack(format!(
                    "{} section {kind} has invalid length or alignment",
                    path.display()
                )));
            }
            if offset < previous_end || offset % alignment != 0 || end > bytes.len() {
                return Err(ExecutionPackError::InvalidPack(format!(
                    "{} section {kind} is overlapping, misaligned, or out of bounds",
                    path.display()
                )));
            }
            previous_end = end;
            sections.push(SectionEntry {
                kind,
                schema_version,
                offset: offset as u64,
                len: len as u64,
                alignment: alignment as u32,
            });
        }
        for required in ExecutionPackSectionKind::ALL {
            if !seen.contains(&required) {
                return Err(ExecutionPackError::InvalidPack(format!(
                    "{} has no required {required} section",
                    path.display()
                )));
            }
        }

        Ok(Self {
            mapping: std::sync::Arc::new(mapping),
            path,
            identity,
            content_digest,
            signature_authenticated,
            sections,
        })
    }
}

fn verify_content_digest_mapping(
    mapping: &Mmap,
    path: &Path,
    content_digest: [u8; 32],
) -> Result<(), ExecutionPackError> {
    let mut content_hasher = blake3::Hasher::new();
    update_mapping_and_release(
        mapping,
        path,
        EXECUTION_PACK_HEADER_LEN..mapping.len(),
        "discard content-authentication pages",
        |chunk| {
            content_hasher.update(chunk);
        },
    )?;
    let actual_digest = *content_hasher.finalize().as_bytes();
    if actual_digest != content_digest {
        return Err(ExecutionPackError::InvalidPack(format!(
            "{} content digest mismatch; reinstall or recalibrate this generation",
            path.display()
        )));
    }
    Ok(())
}

fn decode_identity_header(
    bytes: &[u8],
    path: &Path,
) -> Result<ExecutionPackIdentity, ExecutionPackError> {
    if bytes.len() < EXECUTION_PACK_HEADER_LEN {
        return Err(ExecutionPackError::InvalidPack(format!(
            "{} is too short to carry an execution-pack identity",
            path.display()
        )));
    }
    let policy = super::format::ExecutionPackPolicy::from_u8(bytes[312]).ok_or_else(|| {
        ExecutionPackError::Incompatible(format!(
            "{} uses unknown execution-pack policy {}",
            path.display(),
            bytes[312]
        ))
    })?;
    let backend = super::format::ExecutionPackBackend::from_u8(bytes[313]).ok_or_else(|| {
        ExecutionPackError::Incompatible(format!(
            "{} uses unknown execution-pack backend {}",
            path.display(),
            bytes[313]
        ))
    })?;
    Ok(ExecutionPackIdentity {
        detector_digest: array32(bytes, 24),
        config_digest: array32(bytes, 56),
        target_digest: array32(bytes, 88),
        compiler_abi: array32(bytes, 120),
        binary_digest: array32(bytes, 152),
        feature_digest: array32(bytes, 184),
        backend_digest: array32(bytes, 216),
        policy,
        backend,
    })
}

fn authenticate_pack_signature(
    mapping: &Mmap,
    path: &Path,
    content_digest: [u8; 32],
    signature_path: &Path,
    signing_key: &ExecutionPackSigningKey,
) -> Result<(), ExecutionPackError> {
    let mut file = File::open(signature_path).map_err(|source| ExecutionPackError::Io {
        operation: "open signature for",
        path: signature_path.to_path_buf(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| ExecutionPackError::Io {
        operation: "inspect signature for",
        path: signature_path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() || metadata.len() != 112 {
        return Err(ExecutionPackError::InvalidPack(format!(
            "execution-pack signature {} must be an exact 112-byte regular file",
            signature_path.display()
        )));
    }
    let mut bytes = [0u8; 112];
    file.read_exact(&mut bytes)
        .map_err(|source| ExecutionPackError::Io {
            operation: "read signature for",
            path: signature_path.to_path_buf(),
            source,
        })?;
    let signature = ExecutionPackSignature::decode(&bytes)?;
    let mut pack_hasher = blake3::Hasher::new();
    let mut content_hasher = blake3::Hasher::new();
    pack_hasher.update(&mapping[..EXECUTION_PACK_HEADER_LEN]);
    update_mapping_and_release(
        mapping,
        path,
        EXECUTION_PACK_HEADER_LEN..mapping.len(),
        "discard pack-authentication pages",
        |chunk| {
            pack_hasher.update(chunk);
            content_hasher.update(chunk);
        },
    )?;
    let actual_content_digest = *content_hasher.finalize().as_bytes();
    if actual_content_digest != content_digest {
        return Err(ExecutionPackError::InvalidPack(format!(
            "{} content digest mismatch; reinstall or recalibrate this generation",
            path.display()
        )));
    }
    signing_key.verify_digest(&signature, *pack_hasher.finalize().as_bytes())
}

fn update_mapping_and_release(
    mapping: &Mmap,
    path: &Path,
    range: Range<usize>,
    release_operation: &'static str,
    mut update: impl FnMut(&[u8]),
) -> Result<(), ExecutionPackError> {
    if range.start > range.end || range.end > mapping.len() {
        return Err(ExecutionPackError::InvalidPack(
            "execution-pack authentication range is outside its immutable mapping".into(),
        ));
    }
    let mut start = range.start;
    while start < range.end {
        let end = start
            .saturating_add(AUTHENTICATION_HASH_CHUNK_BYTES)
            .min(range.end);
        let chunk = &mapping[start..end];
        update(chunk);
        if end > 4096 {
            let release_start = start.max(4096);
            let release_chunk = &mapping[release_start..end];
            release_mapping_slice(mapping, path, release_chunk, release_operation)?;
        }
        start = end;
    }
    Ok(())
}

fn mapping_slice_range(mapping: &Mmap, bytes: &[u8]) -> Result<Range<usize>, ExecutionPackError> {
    let mapping_start = mapping.as_ptr() as usize;
    let mapping_end = mapping_start
        .checked_add(mapping.len())
        .ok_or_else(|| ExecutionPackError::InvalidPack("mapped pack range overflows".into()))?;
    let bytes_start = bytes.as_ptr() as usize;
    let bytes_end = bytes_start.checked_add(bytes.len()).ok_or_else(|| {
        ExecutionPackError::InvalidPack("decoded pack slice range overflows".into())
    })?;
    if bytes_start < mapping_start || bytes_end > mapping_end {
        return Err(ExecutionPackError::InvalidPack(
            "decoded pack slice is outside its immutable mapping".into(),
        ));
    }
    Ok((bytes_start - mapping_start)..(bytes_end - mapping_start))
}

#[cfg(unix)]
fn mapping_page_size(path: &Path) -> Result<usize, ExecutionPackError> {
    let probed = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page = usize::try_from(probed).map_err(|_| ExecutionPackError::Io {
        operation: "query page size for mapped-page discard",
        path: path.to_path_buf(),
        source: std::io::Error::last_os_error(),
    })?;
    if page == 0 {
        return Err(ExecutionPackError::InvalidPack(
            "host page size is zero".into(),
        ));
    }
    Ok(page)
}

fn release_entire_mapping(
    mapping: &Mmap,
    path: &Path,
    operation: &'static str,
) -> Result<(), ExecutionPackError> {
    if mapping.is_empty() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        let page = mapping_page_size(path)?;
        if (mapping.as_ptr() as usize) % page != 0 {
            return Err(ExecutionPackError::InvalidPack(format!(
                "{} mapped-page discard starts outside a host page boundary; reinstall the execution pack",
                path.display()
            )));
        }
        let result = unsafe {
            libc::madvise(
                mapping.as_ptr() as *mut libc::c_void,
                mapping.len(),
                libc::MADV_DONTNEED,
            )
        };
        if result != 0 {
            return Err(ExecutionPackError::Io {
                operation,
                path: path.to_path_buf(),
                source: std::io::Error::last_os_error(),
            });
        }
        let result = unsafe {
            libc::madvise(
                mapping.as_ptr() as *mut libc::c_void,
                mapping.len(),
                libc::MADV_RANDOM,
            )
        };
        if result != 0 {
            return Err(ExecutionPackError::Io {
                operation: "configure lazy mapped-section faults",
                path: path.to_path_buf(),
                source: std::io::Error::last_os_error(),
            });
        }
    }
    Ok(())
}

fn release_mapping_slice(
    mapping: &Mmap,
    path: &Path,
    bytes: &[u8],
    operation: &'static str,
) -> Result<(), ExecutionPackError> {
    if bytes.is_empty() {
        return Ok(());
    }
    let range = mapping_slice_range(mapping, bytes)?;
    #[cfg(unix)]
    {
        let page = mapping_page_size(path)?;
        let relative_start = range.start;
        let relative_end = range.end;
        let aligned_start = relative_start
            .checked_add(page - 1)
            .and_then(|value| value.checked_div(page))
            .and_then(|value| value.checked_mul(page))
            .ok_or_else(|| {
                ExecutionPackError::InvalidPack(format!(
                    "{} mapped-page discard range overflows platform alignment; reinstall the execution pack",
                    path.display()
                ))
            })?;
        let aligned_end = relative_end - (relative_end % page);
        if aligned_start < aligned_end {
            let result = unsafe {
                libc::madvise(
                    mapping.as_ptr().add(aligned_start) as *mut libc::c_void,
                    aligned_end - aligned_start,
                    libc::MADV_DONTNEED,
                )
            };
            if result != 0 {
                return Err(ExecutionPackError::Io {
                    operation,
                    path: path.to_path_buf(),
                    source: std::io::Error::last_os_error(),
                });
            }
        }
    }
    Ok(())
}

fn validate_identity(
    path: &Path,
    actual: ExecutionPackIdentity,
    expected: ExecutionPackIdentity,
) -> Result<(), ExecutionPackError> {
    if actual.policy != expected.policy {
        return Err(ExecutionPackError::Incompatible(format!(
            "{} policy identity does not match this scan; reinstall and recalibrate",
            path.display()
        )));
    }
    if actual.backend != expected.backend {
        return Err(ExecutionPackError::Incompatible(format!(
            "{} backend identity does not match this scan; reinstall and recalibrate",
            path.display()
        )));
    }
    for (name, actual, expected) in [
        ("detector", actual.detector_digest, expected.detector_digest),
        ("config", actual.config_digest, expected.config_digest),
        ("target", actual.target_digest, expected.target_digest),
        ("compiler ABI", actual.compiler_abi, expected.compiler_abi),
        ("binary", actual.binary_digest, expected.binary_digest),
        ("feature", actual.feature_digest, expected.feature_digest),
        ("backend", actual.backend_digest, expected.backend_digest),
    ] {
        if actual != expected {
            return Err(ExecutionPackError::Incompatible(format!(
                "{} {name} identity does not match this scan; reinstall and recalibrate",
                path.display()
            )));
        }
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("bounded header"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("bounded header"),
    )
}

fn array32(bytes: &[u8], offset: usize) -> [u8; 32] {
    bytes[offset..offset + 32]
        .try_into()
        .expect("bounded header")
}
