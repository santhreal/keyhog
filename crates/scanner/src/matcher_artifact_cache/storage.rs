//! Binary envelope parsing, atomic disk persistence, and eviction for MatcherArtifact cache files.

use std::io::Read;
use std::ops::Range;
use std::path::Path;

use crate::execution_pack::matcher_sections::CompiledRouteMatcherSections;
use crate::execution_pack::ExecutionPackBackend;
#[cfg(unix)]
use super::current_uid;
use super::{
    validate_and_tighten_matcher_artifact_cache_dir, MatcherArtifactIdentity,
    MATCHER_ARTIFACT_FILE_BYTES, MATCHER_ARTIFACT_MAGIC, MATCHER_ARTIFACT_VERSION,
};

/// MatcherArtifact v4 body layout (after the 8-byte magic/version header):
/// `identity_json_len:u32` + identity JSON + `identity_digest:[u8;32]` +
/// `content_digest:[u8;32]` + length-prefixed raw `literal_index` /
/// `regex_programs` / `suppression_policy` blobs.

fn read_u32_le(bytes: &[u8], offset: &mut usize, path: &Path) -> std::result::Result<u32, String> {
    let end = offset
        .checked_add(4)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| format!("matcher artifact {} is truncated", path.display()))?;
    let arr: [u8; 4] = bytes[*offset..end]
        .try_into()
        .map_err(|_| format!("matcher artifact {} is truncated", path.display()))?;
    let value = u32::from_le_bytes(arr);
    *offset = end;
    Ok(value)
}

fn read_exact<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    len: usize,
    path: &Path,
) -> std::result::Result<&'a [u8], String> {
    let end = offset
        .checked_add(len)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| format!("matcher artifact {} is truncated", path.display()))?;
    let slice = &bytes[*offset..end];
    *offset = end;
    Ok(slice)
}

/// Loaded MatcherArtifact payload (eager route-matcher sections only).
#[derive(Clone, Debug)]
pub struct LoadedMatcherArtifact {
    /// Route-matcher sections validated against the outer content digest.
    pub sections: CompiledRouteMatcherSections,
}

#[derive(Clone, Debug)]
pub(super) struct MatcherArtifactSectionRanges {
    pub(super) backend: ExecutionPackBackend,
    pub(super) literal_index: Range<usize>,
    pub(super) regex_programs: Range<usize>,
    pub(super) suppression_policy: Range<usize>,
}

#[derive(Debug)]
pub(super) struct BorrowedMatcherArtifact {
    pub(super) bytes: Vec<u8>,
    pub(super) ranges: MatcherArtifactSectionRanges,
}

impl BorrowedMatcherArtifact {
    pub(super) fn section_bytes(&self) -> (&[u8], &[u8], &[u8]) {
        (
            &self.bytes[self.ranges.literal_index.clone()],
            &self.bytes[self.ranges.regex_programs.clone()],
            &self.bytes[self.ranges.suppression_policy.clone()],
        )
    }

    // Public loader compatibility only. The scanner startup path hydrates from
    // `section_bytes` and never materializes this second owned section set.
    #[cfg(test)]
    pub(super) fn to_owned_sections(&self) -> CompiledRouteMatcherSections {
        let (literal_index, regex_programs, suppression_policy) = self.section_bytes();
        CompiledRouteMatcherSections {
            backend: self.ranges.backend,
            literal_index: literal_index.to_vec(),
            regex_programs: regex_programs.to_vec(),
            suppression_policy: suppression_policy.to_vec(),
        }
    }
}

pub(super) fn parse_matcher_artifact_ranges(
    path: &Path,
    bytes: &[u8],
    expected_identity: Option<&MatcherArtifactIdentity>,
) -> std::result::Result<(MatcherArtifactIdentity, MatcherArtifactSectionRanges), String> {
    if bytes.len() < 8 {
        return Err(format!("matcher artifact {} is truncated", path.display()));
    }
    if &bytes[..4] != MATCHER_ARTIFACT_MAGIC {
        return Err(format!(
            "matcher artifact {} has invalid magic",
            path.display()
        ));
    }
    let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if version != MATCHER_ARTIFACT_VERSION {
        return Err(format!(
            "matcher artifact {} version {version} is incompatible with {MATCHER_ARTIFACT_VERSION}",
            path.display()
        ));
    }

    let mut offset = 8usize;
    let identity_len = read_u32_le(bytes, &mut offset, path)? as usize;
    let identity_bytes = read_exact(bytes, &mut offset, identity_len, path)?;
    let decoded_identity: MatcherArtifactIdentity = serde_json::from_slice(identity_bytes)
        .map_err(|error| {
            format!(
                "matcher artifact {} identity is not valid JSON: {error}",
                path.display()
            )
        })?;
    if let Some(expected) = expected_identity {
        if decoded_identity != *expected {
            return Err(format!(
                "matcher artifact {} identity fields do not match the running scan",
                path.display()
            ));
        }
    }
    let stored_identity_digest: [u8; 32] = read_exact(bytes, &mut offset, 32, path)?
        .try_into()
        .map_err(|_| format!("matcher artifact {} is truncated", path.display()))?;
    let expected_digest = decoded_identity.digest();
    if stored_identity_digest != expected_digest {
        return Err(format!(
            "matcher artifact {} identity digest mismatch",
            path.display()
        ));
    }
    let stored_content_digest: [u8; 32] = read_exact(bytes, &mut offset, 32, path)?
        .try_into()
        .map_err(|_| format!("matcher artifact {} is truncated", path.display()))?;

    let literal_len = read_u32_le(bytes, &mut offset, path)? as usize;
    let literal_start = offset;
    read_exact(bytes, &mut offset, literal_len, path)?;
    let literal_index = literal_start..offset;

    let regex_len = read_u32_le(bytes, &mut offset, path)? as usize;
    let regex_start = offset;
    read_exact(bytes, &mut offset, regex_len, path)?;
    let regex_programs = regex_start..offset;

    let supp_len = read_u32_le(bytes, &mut offset, path)? as usize;
    let suppression_start = offset;
    read_exact(bytes, &mut offset, supp_len, path)?;
    let suppression_policy = suppression_start..offset;

    // v4: no trailing detector-IR blob. Reject unexpected trailing bytes so a
    // truncated/extended file cannot be accepted after the section digests.
    if offset != bytes.len() {
        return Err(format!(
            "matcher artifact {} has trailing bytes after the envelope",
            path.display()
        ));
    }

    let backend =
        ExecutionPackBackend::from_pascal_name(&decoded_identity.backend).ok_or_else(|| {
            format!(
                "matcher artifact {} has unknown backend {}",
                path.display(),
                decoded_identity.backend
            )
        })?;
    let content = CompiledRouteMatcherSections::content_digest_for(
        &bytes[literal_index.clone()],
        &bytes[regex_programs.clone()],
        &bytes[suppression_policy.clone()],
    );
    if content != stored_content_digest {
        return Err(format!(
            "matcher artifact {} content digest mismatch",
            path.display()
        ));
    }
    // Hydration re-parses the section envelopes and fails closed. Avoiding a
    // second canonical parse and keeping the sections borrowed from the capped
    // file buffer removes the startup-path copies.
    Ok((
        decoded_identity,
        MatcherArtifactSectionRanges {
            backend,
            literal_index,
            regex_programs,
            suppression_policy,
        },
    ))
}

pub(super) fn load_borrowed_matcher_artifact(
    cache_dir: &Path,
    identity: &MatcherArtifactIdentity,
) -> std::result::Result<BorrowedMatcherArtifact, String> {
    let path = cache_dir.join(identity.cache_filename());
    let bytes = read_matcher_artifact_bytes(&path)?;
    let (_identity, ranges) = parse_matcher_artifact_ranges(&path, &bytes, Some(identity))?;
    Ok(BorrowedMatcherArtifact { bytes, ranges })
}

/// Load a MatcherArtifact for `identity` from `cache_dir`.
pub fn load_matcher_artifact(
    cache_dir: &Path,
    identity: &MatcherArtifactIdentity,
) -> std::result::Result<CompiledRouteMatcherSections, String> {
    Ok(load_matcher_artifact_with_ir(cache_dir, identity)?.sections)
}

/// Load matcher sections plus the canonical detector IR for `identity`.
pub fn load_matcher_artifact_with_ir(
    cache_dir: &Path,
    identity: &MatcherArtifactIdentity,
) -> std::result::Result<LoadedMatcherArtifact, String> {
    let loaded = load_borrowed_matcher_artifact(cache_dir, identity)?;
    Ok(LoadedMatcherArtifact {
        sections: loaded.to_owned_sections(),
    })
}

fn read_capped_matcher_artifact(
    file: std::fs::File,
    metadata_len: u64,
    path: &Path,
) -> std::result::Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(metadata_len.min(MATCHER_ARTIFACT_FILE_BYTES) as usize);
    file.take(MATCHER_ARTIFACT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read matcher artifact {}: {error}", path.display()))?;
    if bytes.len() as u64 > MATCHER_ARTIFACT_FILE_BYTES {
        return Err(format!(
            "matcher artifact {} exceeds {} byte cap",
            path.display(),
            MATCHER_ARTIFACT_FILE_BYTES
        ));
    }
    Ok(bytes)
}

pub(super) fn read_matcher_artifact_bytes(path: &Path) -> std::result::Result<Vec<u8>, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        options.custom_flags(libc::O_NOFOLLOW);
        let file = match options.open(path) {
            Ok(file) => file,
            Err(error) => {
                if error.raw_os_error() == Some(libc::ELOOP) {
                    return Err(format!(
                        "matcher artifact {} is a symlink; refusing to load",
                        path.display()
                    ));
                }
                if error.kind() == std::io::ErrorKind::NotFound {
                    return Err(format!("matcher artifact cache miss: {}", path.display()));
                }
                return Err(format!(
                    "cannot open matcher artifact {}: {error}",
                    path.display()
                ));
            }
        };
        let metadata = file.metadata().map_err(|error| {
            format!("cannot fstat matcher artifact {}: {error}", path.display())
        })?;
        if !metadata.file_type().is_file() {
            return Err(format!(
                "matcher artifact {} is not a regular file; refusing to load",
                path.display()
            ));
        }
        if metadata.uid() != current_uid() {
            return Err(format!(
                "matcher artifact {} is not owned by the current user; refusing to load",
                path.display()
            ));
        }
        if metadata.len() > MATCHER_ARTIFACT_FILE_BYTES {
            return Err(format!(
                "matcher artifact {} exceeds {} byte cap",
                path.display(),
                MATCHER_ARTIFACT_FILE_BYTES
            ));
        }
        return read_capped_matcher_artifact(file, metadata.len(), path);
    }
    #[cfg(not(unix))]
    {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                format!("matcher artifact cache miss: {}", path.display())
            } else {
                format!("cannot stat matcher artifact {}: {error}", path.display())
            }
        })?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "matcher artifact {} is a symlink; refusing to load",
                path.display()
            ));
        }
        if metadata.len() > MATCHER_ARTIFACT_FILE_BYTES {
            return Err(format!(
                "matcher artifact {} exceeds {} byte cap",
                path.display(),
                MATCHER_ARTIFACT_FILE_BYTES
            ));
        }
        let file = std::fs::File::open(path)
            .map_err(|error| format!("cannot open matcher artifact {}: {error}", path.display()))?;
        read_capped_matcher_artifact(file, metadata.len(), path)
    }
}

pub(super) fn checked_matcher_artifact_len(
    identity_len: usize,
    literal_len: usize,
    regex_len: usize,
    suppression_len: usize,
) -> std::result::Result<usize, String> {
    let artifact_len = [
        8usize,
        4,
        identity_len,
        64,
        12,
        literal_len,
        regex_len,
        suppression_len,
    ]
    .into_iter()
    .try_fold(0usize, usize::checked_add)
    .ok_or_else(|| "matcher artifact size overflow".to_owned())?;
    if artifact_len as u64 > MATCHER_ARTIFACT_FILE_BYTES {
        return Err(format!(
            "matcher artifact would exceed {} byte cap",
            MATCHER_ARTIFACT_FILE_BYTES
        ));
    }
    Ok(artifact_len)
}

/// Persist `sections` under `identity`.
pub fn store_matcher_artifact(
    cache_dir: &Path,
    identity: &MatcherArtifactIdentity,
    sections: &CompiledRouteMatcherSections,
) -> std::result::Result<(), String> {
    let expected_backend = ExecutionPackBackend::from_pascal_name(&identity.backend)
        .ok_or_else(|| "unknown identity backend".to_owned())?;
    if sections.backend != expected_backend {
        return Err("matcher artifact backend does not match identity".to_owned());
    }
    // Only tighten mode on directories we create. Do not chmod a pre-existing
    // operator-supplied path (for example $HOME or $HOME/.cache).
    let created_cache_dir = !cache_dir.exists();
    validate_and_tighten_matcher_artifact_cache_dir(cache_dir, created_cache_dir)?;
    std::fs::create_dir_all(cache_dir).map_err(|error| {
        format!(
            "cannot create matcher-artifact cache dir {}: {error}",
            cache_dir.display()
        )
    })?;
    #[cfg(unix)]
    if created_cache_dir {
        use std::os::unix::fs::PermissionsExt;
        if created_cache_dir {
            if let Ok(meta) = std::fs::symlink_metadata(cache_dir) {
                // LAW10: best-effort permissions check on newly created cache dir; failure surfaced if chmod fails
                if !meta.file_type().is_symlink() && (meta.permissions().mode() & 0o077 != 0) {
                    std::fs::set_permissions(cache_dir, std::fs::Permissions::from_mode(0o700))
                        .map_err(|error| {
                            format!(
                                "cannot tighten matcher-artifact cache dir {}: {error}; repair with `chmod 700 {}`",
                                cache_dir.display(),
                                cache_dir.display()
                            )
                        })?;
                }
            }
        }
    }
    let path = cache_dir.join(identity.cache_filename());
    let identity_json = serde_json::to_vec(identity)
        .map_err(|error| format!("cannot serialize matcher artifact identity: {error}"))?;
    let identity_digest = identity.digest();
    let content_digest = sections.content_digest();

    let identity_len = u32::try_from(identity_json.len())
        .map_err(|_| "matcher artifact identity exceeds u32 length".to_owned())?;
    let literal_len = u32::try_from(sections.literal_index.len())
        .map_err(|_| "matcher artifact literal index exceeds u32 length".to_owned())?;
    let regex_len = u32::try_from(sections.regex_programs.len())
        .map_err(|_| "matcher artifact regex programs exceed u32 length".to_owned())?;
    let suppression_len = u32::try_from(sections.suppression_policy.len())
        .map_err(|_| "matcher artifact suppression policy exceeds u32 length".to_owned())?;
    let artifact_len = checked_matcher_artifact_len(
        identity_json.len(),
        sections.literal_index.len(),
        sections.regex_programs.len(),
        sections.suppression_policy.len(),
    )?;

    write_matcher_artifact_atomically(&path, artifact_len, |tmp| {
        use std::io::Write as _;
        tmp.write_all(MATCHER_ARTIFACT_MAGIC)?;
        tmp.write_all(&MATCHER_ARTIFACT_VERSION.to_le_bytes())?;
        tmp.write_all(&identity_len.to_le_bytes())?;
        tmp.write_all(&identity_json)?;
        tmp.write_all(&identity_digest)?;
        tmp.write_all(&content_digest)?;
        tmp.write_all(&literal_len.to_le_bytes())?;
        tmp.write_all(&sections.literal_index)?;
        tmp.write_all(&regex_len.to_le_bytes())?;
        tmp.write_all(&sections.regex_programs)?;
        tmp.write_all(&suppression_len.to_le_bytes())?;
        tmp.write_all(&sections.suppression_policy)?;
        Ok(())
    })
    .map_err(|error| format!("cannot write matcher artifact {}: {error}", path.display()))?;
    evict_old_matcher_artifacts(cache_dir);
    Ok(())
}

pub(crate) fn write_matcher_artifact_atomically<F>(
    path: &Path,
    expected_len: usize,
    writer: F,
) -> std::io::Result<()>
where
    F: FnOnce(&mut tempfile::NamedTempFile) -> std::io::Result<()>,
{
    if path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .is_none()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "matcher artifact path must have a parent directory",
        ));
    }
    keyhog_core::state_file::write_atomically_with_writer(path, |tmp| {
        writer(tmp)?;
        let actual_len = usize::try_from(tmp.as_file().metadata()?.len()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "matcher artifact length exceeds usize",
            )
        })?;
        if actual_len != expected_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "matcher artifact writer produced {actual_len} bytes, expected {expected_len}"
                ),
            ));
        }
        Ok(())
    })
}

pub(super) fn evict_old_matcher_artifacts(cache_dir: &Path) {
    let policy = keyhog_core::CacheKind::MatcherArtifacts.default_policy();
    crate::cache_eviction::evict_cache_dir_with_policy(
        cache_dir,
        keyhog_core::CacheKind::MatcherArtifacts,
        policy,
    );
}

