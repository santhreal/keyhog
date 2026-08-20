#[cfg(feature = "decode")]
use std::collections::HashSet;
#[cfg(feature = "decode")]
use std::sync::Arc;

#[cfg(feature = "decode")]
use keyhog_core::{Chunk, RawMatch, SensitiveString};

#[cfg(feature = "decode")]
pub(crate) fn union_unique_matches(dest: &mut Vec<RawMatch>, src: Vec<RawMatch>) {
    if src.is_empty() {
        return;
    }
    if dest.is_empty() && src.len() <= 1 {
        *dest = src;
        return;
    }
    let mut seen: HashSet<(Arc<str>, SensitiveString)> = dest
        .iter()
        .map(|m| (Arc::clone(&m.detector_id), m.credential.clone()))
        .collect();
    for m in src {
        if seen.insert((Arc::clone(&m.detector_id), m.credential.clone())) {
            dest.push(m);
        }
    }
}

#[cfg(feature = "decode")]
pub(crate) fn decode_source_windows(
    limit: usize,
    chunk: &Chunk,
    mut visit: impl FnMut(&Chunk) -> crate::error::Result<()>,
) -> crate::error::Result<()> {
    let text = chunk.data.as_str();
    if text.is_empty() || limit == 0 {
        return Ok(());
    }
    let mut start = 0usize;
    let mut base_line = chunk.metadata.base_line;

    while start < text.len() {
        let mut end = start.saturating_add(limit).min(text.len());
        while end > start && !text.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            if let Some((idx, _)) = text[start..].char_indices().nth(1) {
                end = start + idx;
            } else {
                end = text.len();
            }
        }

        let mut metadata = chunk.metadata.clone();
        metadata.base_offset = chunk
            .metadata
            .base_offset
            .checked_add(start)
            .ok_or_else(|| {
                crate::ScanError::Config(
                    "bounded decode window base offset exceeds usize".to_string(),
                )
            })?;
        metadata.base_line = base_line;
        let window = Chunk {
            data: text[start..end].to_owned().into(),
            metadata,
        };
        visit(&window)?;
        if end >= text.len() {
            break;
        }

        let max_overlap = (end - start).saturating_sub(1);
        let actual_overlap = overlap.min(max_overlap);

        let mut next = end.saturating_sub(overlap);
        while next < end && !text.is_char_boundary(next) {
            next += 1;
        }
        if next <= start {
            if let Some((idx, _)) = text[start..end].char_indices().nth(1) {
                next = start + idx;
            } else {
                next = end;
            }
        }
        assert!(next > start, "bounded decode windows must make progress");
        base_line = base_line
            .checked_add(
                text[start..next]
                    .bytes()
                    .filter(|byte| *byte == b'\n')
                    .count(),
            )
            .ok_or_else(|| {
                crate::ScanError::Config(
                    "bounded decode window base line exceeds usize".to_string(),
                )
            })?;
        start = next;
    }
    Ok(())
}
