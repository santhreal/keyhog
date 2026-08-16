#[cfg(feature = "decode")]
use std::collections::HashSet;
#[cfg(feature = "decode")]
use std::sync::Arc;

#[cfg(feature = "decode")]
use keyhog_core::{Chunk, RawMatch, SensitiveString};

#[cfg(feature = "decode")]
pub(crate) fn union_unique_matches(dest: &mut Vec<RawMatch>, src: Vec<RawMatch>) {
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
    let overlap = crate::types::WINDOW_OVERLAP_BYTES.min(limit / 2);
    let mut start = 0usize;
    let mut base_line = chunk.metadata.base_line;

    while start < text.len() {
        let mut end = start.saturating_add(limit).min(text.len());
        while end > start && !text.is_char_boundary(end) {
            end -= 1;
        }
        debug_assert!(
            end > start,
            "a four-byte decode window fits one UTF-8 scalar"
        );

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
        if end == text.len() {
            break;
        }

        let mut next = end.saturating_sub(overlap);
        while next < end && !text.is_char_boundary(next) {
            next += 1;
        }
        debug_assert!(next > start, "bounded decode windows must make progress");
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
