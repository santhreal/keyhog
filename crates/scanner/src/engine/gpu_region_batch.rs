//! Batch scratch and validation helpers for coalesced GPU region presence.

use std::cell::RefCell;

#[derive(Default)]
pub(super) struct RegionPresenceScratch {
    haystack: Vec<u8>,
    region_starts: Vec<u32>,
}

impl RegionPresenceScratch {
    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.haystack.is_empty() && self.region_starts.is_empty()
    }
}

thread_local! {
    static REGION_PRESENCE_BATCH_SCRATCH: RefCell<RegionPresenceScratch> =
        RefCell::new(RegionPresenceScratch::default());
}

pub(super) struct ZeroRegionPresenceScratch<'a> {
    scratch: &'a mut RegionPresenceScratch,
}

impl<'a> ZeroRegionPresenceScratch<'a> {
    pub(super) fn new(scratch: &'a mut RegionPresenceScratch) -> Self {
        Self { scratch }
    }

    pub(super) fn as_mut(&mut self) -> &mut RegionPresenceScratch {
        &mut *self.scratch
    }

    pub(super) fn haystack(&self) -> &[u8] {
        &self.scratch.haystack
    }

    pub(super) fn region_starts(&self) -> &[u32] {
        &self.scratch.region_starts
    }
}

impl Drop for ZeroRegionPresenceScratch<'_> {
    fn drop(&mut self) {
        self.scratch.haystack.fill(0);
        self.scratch.haystack.clear();
        self.scratch.region_starts.clear();
    }
}

pub(super) fn build_region_presence_batch(
    chunks: &[keyhog_core::Chunk],
    scratch: &mut RegionPresenceScratch,
) -> std::result::Result<(), String> {
    let mut total = chunks.len().saturating_sub(1);
    for chunk in chunks {
        total = total.checked_add(chunk.data.len()).ok_or_else(|| {
            "coalesced GPU region-presence batch length overflows host usize".to_string()
        })?;
    }
    if total > u32::MAX as usize {
        return Err(format!(
            "coalesced GPU region-presence batch is {total} byte(s), above the u32 GPU ABI; split the batch before dispatch"
        ));
    }

    scratch.haystack.clear();
    scratch.region_starts.clear();
    scratch
        .haystack
        .try_reserve(total)
        .map_err(|error| format!("coalesced GPU region-presence reserve failed: {error}"))?;
    scratch
        .region_starts
        .try_reserve(chunks.len())
        .map_err(|error| format!("coalesced GPU region-start reserve failed: {error}"))?;
    for (idx, chunk) in chunks.iter().enumerate() {
        let start = u32::try_from(scratch.haystack.len()).map_err(|_| {
            "coalesced GPU region-presence start offset exceeds the u32 GPU ABI".to_string()
        })?;
        scratch.region_starts.push(start);
        crate::ascii_ci::extend_ascii_lowercase_from(&mut scratch.haystack, chunk.data.as_bytes());
        if idx + 1 != chunks.len() {
            scratch.haystack.push(0);
        }
    }
    Ok(())
}

pub(super) fn with_region_presence_batch<R>(
    chunks: &[keyhog_core::Chunk],
    f: impl FnOnce(&[u8], &[u32]) -> std::result::Result<R, String>,
) -> std::result::Result<R, String> {
    REGION_PRESENCE_BATCH_SCRATCH
        .try_with(|cell| {
            let mut scratch = cell.try_borrow_mut().map_err(|_| {
                "coalesced GPU region-presence scratch already borrowed on this thread; recursive \
                 GPU batch dispatch is unsupported"
                    .to_string()
            })?;
            let mut zero_on_drop = ZeroRegionPresenceScratch::new(&mut scratch);
            build_region_presence_batch(chunks, zero_on_drop.as_mut())?;
            f(zero_on_drop.haystack(), zero_on_drop.region_starts())
        })
        .map_err(|_| {
            "coalesced GPU region-presence scratch unavailable during thread shutdown".to_string()
        })?
}

pub(super) fn trigger_bit_is_set(triggers: &[Option<Vec<u64>>], ci: usize, det: usize) -> bool {
    triggers
        .get(ci)
        .and_then(|slot| slot.as_ref())
        .and_then(|words| words.get(det / 64))
        .is_some_and(|word| ((word >> (det % 64)) & 1) == 1)
}

pub(super) fn set_trigger_bit(
    triggers: &mut [Option<Vec<u64>>],
    ci: usize,
    det: usize,
    words: usize,
) {
    if let Some(slot) = triggers.get_mut(ci) {
        let bits = slot.get_or_insert_with(|| vec![0u64; words]);
        if bits.len() < words {
            bits.resize(words, 0);
        }
        bits[det / 64] |= 1u64 << (det % 64);
    }
}

pub(super) fn validation_window_range(
    text: &str,
    match_offset: usize,
    max_match_width: usize,
) -> Option<(usize, usize)> {
    if text.is_empty() || max_match_width == 0 {
        return None;
    }
    let hit = match_offset.min(text.len());
    let start = super::floor_char_boundary(text, hit.saturating_sub(max_match_width));
    let end = super::ceil_char_boundary(text, hit.saturating_add(max_match_width).min(text.len()));
    (start < end).then_some((start, end))
}

pub(super) fn validate_detector_match(
    text: &str,
    rx: &regex::Regex,
    match_offset: Option<usize>,
    max_match_width: Option<usize>,
) -> bool {
    let Some(match_offset) = match_offset else {
        return rx.is_match(text);
    };
    let Some(max_match_width) = max_match_width else {
        return rx.is_match(text);
    };
    let Some((start, end)) = validation_window_range(text, match_offset, max_match_width) else {
        return false;
    };
    rx.is_match(&text[start..end])
}
