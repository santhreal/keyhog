use std::collections::VecDeque;
use std::process::Command;

use keyhog_core::{Chunk, ChunkMetadata, SourceError};

use super::git_unscanned_object_error;

const GIT_TAG_REF_LINE_BYTES: usize = 4096;

#[derive(Debug, Clone)]
pub(crate) struct GitTagMessageRef {
    oid: gix::ObjectId,
    path: String,
    source_type: &'static str,
}

pub(crate) fn collect_reachable_tag_messages(
    repo_arg: &str,
) -> Result<VecDeque<GitTagMessageRef>, SourceError> {
    let mut command = Command::new(super::git_bin()?);
    command.args([
        "-C",
        repo_arg,
        "for-each-ref",
        "refs/tags",
        "--format=%(objecttype) %(objectname) %(refname)",
    ]);
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    let mut child = super::spawn_git_child(command)?;
    let stdout = child
        .take_stdout()
        .ok_or_else(|| SourceError::Io(std::io::Error::other("missing for-each-ref stdout")))?;
    let mut reader = std::io::BufReader::new(stdout);
    let mut tags = VecDeque::new();
    let mut line_buf = Vec::new();
    while super::read_capped_line(&mut reader, &mut line_buf, GIT_TAG_REF_LINE_BYTES)
        .map_err(SourceError::Io)?
        > 0
    {
        let line = String::from_utf8_lossy(&line_buf);
        let line = line.trim_end_matches('\n').trim_end_matches('\r');
        let mut parts = line.splitn(3, ' ');
        let Some(object_type) = parts.next() else {
            continue;
        };
        if object_type != "tag" {
            continue;
        }
        let Some(object_id) = parts.next() else {
            continue;
        };
        let Some(ref_name) = parts.next() else {
            continue;
        };
        let Some(oid) = parse_git_object_id_line(object_id, "tag") else {
            continue;
        };
        tags.push_back(GitTagMessageRef {
            oid,
            path: ref_name.to_owned(),
            source_type: "git/tag",
        });
    }
    super::wait_for_git_child(
        &mut child,
        "git for-each-ref",
        "enumerating annotated git tags",
    )?;
    Ok(tags)
}

pub(crate) fn decode_unreachable_tag_message_chunks(
    repo: &gix::Repository,
    tags: &mut VecDeque<gix::ObjectId>,
    limits: crate::SourceLimits,
    total_bytes: &mut usize,
    chunk_count: &mut usize,
    errors: &mut VecDeque<SourceError>,
) -> VecDeque<Chunk> {
    let mut chunks = VecDeque::new();
    while super::git_history_cap_status(*total_bytes, *chunk_count, limits).is_none() {
        let Some(oid) = tags.pop_front() else {
            break;
        };
        let tag_ref = GitTagMessageRef {
            oid,
            path: format!(".git/unreachable/{oid}"),
            source_type: "git/unreachable",
        };
        let chunk = match decode_tag_message_chunk(repo, tag_ref, limits) {
            Ok(Some(chunk)) => chunk,
            Ok(None) => continue,
            Err(error) => {
                errors.push_back(error);
                continue;
            }
        };
        *total_bytes = total_bytes.saturating_add(chunk.data.len());
        *chunk_count += 1;
        chunks.push_back(chunk);
    }
    chunks
}

pub(crate) fn decode_tag_message_chunks(
    repo: &gix::Repository,
    tags: &mut VecDeque<GitTagMessageRef>,
    limits: crate::SourceLimits,
    total_bytes: &mut usize,
    chunk_count: &mut usize,
    errors: &mut VecDeque<SourceError>,
) -> VecDeque<Chunk> {
    let mut chunks = VecDeque::new();
    while super::git_history_cap_status(*total_bytes, *chunk_count, limits).is_none() {
        let Some(tag_ref) = tags.pop_front() else {
            break;
        };
        let chunk = match decode_tag_message_chunk(repo, tag_ref, limits) {
            Ok(Some(chunk)) => chunk,
            Ok(None) => continue,
            Err(error) => {
                errors.push_back(error);
                continue;
            }
        };
        *total_bytes = total_bytes.saturating_add(chunk.data.len());
        *chunk_count += 1;
        chunks.push_back(chunk);
    }
    chunks
}

fn decode_tag_message_chunk(
    repo: &gix::Repository,
    tag_ref: GitTagMessageRef,
    limits: crate::SourceLimits,
) -> Result<Option<Chunk>, SourceError> {
    let obj = match repo.find_object(tag_ref.oid) {
        Ok(obj) => obj,
        Err(error) => {
            tracing::warn!(
                %error,
                tag = %tag_ref.oid,
                "git tag object unreadable; tag message was NOT scanned"
            );
            record_git_object_unreadable();
            return Err(git_unscanned_object_error(format!(
                "git tag object {} ({}) unreadable ({error}); tag message was not scanned",
                tag_ref.oid, tag_ref.path
            )));
        }
    };
    let tag = match obj.try_into_tag() {
        Ok(tag) => tag,
        Err(error) => {
            tracing::warn!(
                %error,
                tag = %tag_ref.oid,
                "git object is not an annotated tag; tag message was NOT scanned"
            );
            record_git_object_unreadable();
            return Err(git_unscanned_object_error(format!(
                "git object {} ({}) is not an annotated tag ({error}); tag message was not scanned",
                tag_ref.oid, tag_ref.path
            )));
        }
    };
    let decoded = match tag.decode() {
        Ok(decoded) => decoded,
        Err(error) => {
            tracing::warn!(
                %error,
                tag = %tag_ref.oid,
                "git tag object could not be decoded; tag message was NOT scanned"
            );
            record_git_object_unreadable();
            return Err(git_unscanned_object_error(format!(
                "git tag object {} ({}) could not be decoded ({error}); tag message was not scanned",
                tag_ref.oid, tag_ref.path
            )));
        }
    };
    let message_bytes: &[u8] = decoded.message.as_ref();
    if message_bytes.is_empty() {
        return Ok(None);
    }
    if message_bytes.len() as u64 > limits.git_blob_bytes {
        tracing::warn!(
            tag = %tag_ref.oid,
            size = message_bytes.len(),
            cap = limits.git_blob_bytes,
            "git tag message exceeds the per-blob size cap; NOT scanned"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
        return Err(git_unscanned_object_error(format!(
            "git tag message {} ({}) exceeded the {}-byte per-blob size cap; tag message was not scanned",
            tag_ref.oid, tag_ref.path, limits.git_blob_bytes
        )));
    }
    let Some(file_text) = crate::filesystem::decode_text_file(message_bytes) else {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
        return Err(git_unscanned_object_error(format!(
            "git tag message {} ({}) was binary or undecodable text; tag message was not scanned",
            tag_ref.oid, tag_ref.path
        )));
    };
    let author = match decoded.tagger() {
        Ok(Some(tagger)) => {
            let name = String::from_utf8_lossy(tagger.name.as_ref())
                .trim()
                .to_string();
            if name.is_empty() {
                None
            } else {
                Some(name)
            }
        }
        Ok(None) => None,
        Err(error) => {
            tracing::warn!(
                %error,
                tag = %tag_ref.oid,
                "git tag tagger metadata could not be decoded; tag message will be scanned without author"
            );
            None
        }
    };
    Ok(Some(Chunk {
        data: file_text.into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: tag_ref.source_type.into(),
            path: Some(tag_ref.path),
            commit: None,
            author,
            date: None,
            mtime_ns: None,
            size_bytes: Some(message_bytes.len() as u64),
            decoded_span: None,
        },
    }))
}

fn parse_git_object_id_line(line: &str, object_label: &'static str) -> Option<gix::ObjectId> {
    let Some(object_id) = line.split_whitespace().next() else {
        return None;
    };
    match gix::ObjectId::from_hex(object_id.as_bytes()) {
        Ok(id) => Some(id),
        Err(error) => {
            tracing::warn!(
                %error,
                object = object_id,
                object_kind = object_label,
                "git reported an unparsable object id; object NOT scanned"
            );
            record_git_object_unreadable();
            None
        }
    }
}

fn record_git_object_unreadable() {
    let _event = crate::record_skip_event(crate::SourceSkipEvent::GitObjectUnreadable);
}
