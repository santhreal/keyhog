use keyhog_core::{Chunk, ChunkMetadata, SourceError};
use std::path::{Component, Path};

use super::walk_util::is_default_excluded;

/// Sanitize an archive entry name so it cannot contain path traversal
/// components (`../`, leading `/`, Windows-drive prefixes, NUL bytes).
///
/// This does NOT prevent openpack from reading the entry at that name — it
/// protects the **reported** path that ends up in `ChunkMetadata::path` and
/// flows into every finding the operator reads. Without this guard an entry
/// named `../../etc/passwd` would produce a finding whose path field says
/// `foo.zip//../../etc/passwd`, which is confusing and can mislead any
/// downstream tool that tries to reconstruct or display the path.
///
/// The sanitization mirrors `sanitize_path` in `git/history.rs`: walk the
/// `Path::components()` iterator and collect only `Normal` segments, joining
/// them with `/`. Returns `None` when the name is entirely traversal
/// (e.g. `../../` alone) or empty after stripping.
fn sanitize_archive_entry_name(name: &str) -> Option<String> {
    // Reject names containing NUL bytes — they can't appear in valid archive
    // entry names and are used to craft `safe\0../../etc/passwd` bypass attempts.
    if name.contains('\0') {
        return None;
    }
    // Normalise backslash-encoded Windows-style paths, then walk components.
    let normalized = name.replace('\\', "/");
    let mut segments: Vec<String> = Vec::new();
    for component in Path::new(&normalized).components() {
        match component {
            Component::Normal(part) => {
                segments.push(part.to_string_lossy().into_owned());
            }
            Component::CurDir => {} // `.` — skip
            Component::ParentDir => {
                // `..` — pop one level; if we're at the root this would escape
                // the archive, so abort the whole entry rather than letting it
                // slide to the top-level name. A valid archive entry should never
                // need to traverse upward from its own name.
                if segments.pop().is_none() {
                    // Already at top — traversal attempt, refuse the name.
                    return None;
                }
            }
            // Absolute root or Windows prefix — both are traversal attempts.
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if segments.is_empty() {
        None
    } else {
        Some(segments.join("/"))
    }
}

/// Unpack zip-family archives with symlink guard, per-entry cap, and 4× budget.
pub(super) fn extract_archive_chunks(
    path: &Path,
    max_size: u64,
) -> Vec<Result<Chunk, SourceError>> {
    // SSRF/path-traversal defense: refuse to open archive paths
    // that resolve through a symlink. The walker's
    // `follow_symlinks=false` lists the symlink file itself, and
    // openpack::open_default does NOT honor O_NOFOLLOW — a
    // symlink named secret.zip → /etc/shadow would otherwise let
    // an attacker stage an archive that openpack reads from the
    // (privileged) target. symlink_metadata() does not follow
    // links; if file_type().is_symlink() we skip the archive
    // entirely. Kimi sources-audit HIGH finding.
    if std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        tracing::warn!(
            archive = %path.display(),
            "refusing to open archive at a symlink path — \
             prevents the link-swap attack class"
        );
        return Vec::new();
    }
    // Per-entry uncompressed-size cap to defeat zip-bomb DoS.
    // openpack's central directory exposes uncompressed_size; skip
    // any entry that exceeds max_size (per-file cap) and the total
    // uncompressed budget.
    let mut archive_chunks = Vec::new();
    let mut total_uncompressed: u64 = 0;
    let total_budget: u64 = max_size.saturating_mul(4); // 4x file cap budget for archives
    if let Ok(pack) = openpack::OpenPack::open_default(path) {
        if let Ok(entries) = pack.entries() {
            for archive_entry in entries {
                if archive_entry.is_dir || is_default_excluded(&archive_entry.name) {
                    continue;
                }
                // Path-traversal guard: sanitize the entry name before embedding
                // it in any reported path. An entry named `../../etc/passwd`
                // would otherwise produce a finding whose path field reads
                // `foo.zip//../../etc/passwd`, misleading operators and any
                // downstream tooling that reconstructs paths from findings.
                // Entries whose names cannot be sanitized to a clean relative
                // path are skipped entirely — they are either traversal attacks
                // or malformed and not worth scanning.
                let safe_name = match sanitize_archive_entry_name(&archive_entry.name) {
                    Some(n) => n,
                    None => {
                        tracing::warn!(
                            archive = %path.display(),
                            entry = %archive_entry.name,
                            "skipping archive entry: name contains path traversal or \
                             NUL byte (zip-slip guard)"
                        );
                        continue;
                    }
                };
                if archive_entry.uncompressed_size > max_size {
                    tracing::warn!(
                        archive = %path.display(),
                        entry = %safe_name,
                        size = archive_entry.uncompressed_size,
                        "skipping archive entry: uncompressed size exceeds per-file cap"
                    );
                    continue;
                }
                total_uncompressed =
                    total_uncompressed.saturating_add(archive_entry.uncompressed_size);
                if total_uncompressed > total_budget {
                    tracing::warn!(
                        archive = %path.display(),
                        "aborting archive extraction: total uncompressed size exceeds 4x file cap (zip-bomb guard)"
                    );
                    break;
                }
                if let Ok(content) = pack.read_entry(&archive_entry.name) {
                    if let Ok(s) = String::from_utf8(content.clone()) {
                        archive_chunks.push(Ok(Chunk {
                            data: s.into(),
                            metadata: ChunkMetadata {
                                source_type: "filesystem/archive".into(),
                                path: Some(format!(
                                    "{}//{}",
                                    path.display(),
                                    safe_name
                                )),
                                ..Default::default()
                            },
                        }));
                    } else {
                        let strings = crate::strings::extract_printable_strings(&content, 8);
                        if !strings.is_empty() {
                            archive_chunks.push(Ok(Chunk {
                                data: keyhog_core::SensitiveString::join(&strings, "\n"),
                                metadata: ChunkMetadata {
                                    source_type: "filesystem/archive-binary".into(),
                                    path: Some(format!(
                                        "{}//{}",
                                        path.display(),
                                        safe_name
                                    )),
                                    ..Default::default()
                                },
                            }));
                        }
                    }
                }
            }
        }
    }
    archive_chunks
}
