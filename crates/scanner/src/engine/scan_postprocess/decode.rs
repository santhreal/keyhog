#[cfg(feature = "decode")]
use std::collections::hash_map::Entry;
#[cfg(feature = "decode")]
use std::collections::HashMap;
#[cfg(feature = "decode")]
use std::sync::Arc;

#[cfg(feature = "decode")]
use keyhog_core::{Chunk, RawMatch, SensitiveString};

/// Union decoded findings into the raw findings of the same chunk.
///
/// A decoded twin of an already-reported `(detector, credential)` adds no new
/// location: the raw coordinate is the one an operator can open, so it stays
/// primary. Its evidence is a different matter. The decoded text is often the
/// only place the source role is parseable (a base64 `data:` value in a k8s
/// Secret decodes to `KEY=value`), so dropping the twin outright downgraded the
/// finding to `review` and stopped it blocking. The twin's verdict is unioned
/// into the survivor instead; evidence only ever moves up.
#[cfg(feature = "decode")]
pub(crate) fn union_unique_matches(dest: &mut Vec<RawMatch>, src: Vec<RawMatch>) {
    if src.is_empty() {
        return;
    }
    if dest.is_empty() && src.len() <= 1 {
        *dest = src;
        return;
    }
    let mut seen: HashMap<(Arc<str>, SensitiveString), usize> = dest
        .iter()
        .enumerate()
        .map(|(index, m)| ((Arc::clone(&m.detector_id), m.credential.clone()), index))
        .collect();
    for m in src {
        match seen.entry((Arc::clone(&m.detector_id), m.credential.clone())) {
            Entry::Vacant(slot) => {
                slot.insert(dest.len());
                dest.push(m);
            }
            Entry::Occupied(slot) => {
                let existing = &mut dest[*slot.get()];
                existing.evidence = existing.evidence.stronger(m.evidence);
            }
        }
    }
}

#[cfg(feature = "decode")]
pub(crate) fn decode_source_windows(
    limit: usize,
    chunk: &Chunk,
    overlap: usize,
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

        let mut next = end.saturating_sub(actual_overlap);
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
