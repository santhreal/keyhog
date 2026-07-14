//! Batch scratch and validation helpers for coalesced GPU region presence.

#[cfg(test)]
use std::cell::Cell;
use std::cell::RefCell;
use std::ops::Range;

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

#[cfg(test)]
thread_local! {
    static TEST_REGION_PRESENCE_BYTE_LIMIT: Cell<Option<usize>> = const { Cell::new(None) };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RegionPresenceBatchMode {
    BorrowedSingleChunk,
    FoldedScratch,
    ShardedScratch,
    Windowed,
}

impl RegionPresenceBatchMode {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::BorrowedSingleChunk => "borrowed-single-chunk",
            Self::FoldedScratch => "folded-scratch",
            Self::ShardedScratch => "sharded-scratch",
            Self::Windowed => "windowed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RegionPresenceShard {
    pub(super) chunks: Range<usize>,
    pub(super) coalesced_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RegionPresenceBatchSummary {
    pub(super) dispatches: usize,
    pub(super) coalesced_bytes: usize,
    pub(super) max_dispatch_bytes: usize,
    pub(super) mode: RegionPresenceBatchMode,
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

/// VYRE's production byte-scan guard is stricter than the u32 wire ABI.
pub(super) const REGION_PRESENCE_BATCH_BYTE_LIMIT: usize =
    vyre_libs::scan::dispatch_io::DEFAULT_MAX_SCAN_BYTES as usize;

/// VYRE byte-scan kernels launch one 128-thread workgroup per byte block.
pub(super) const WGPU_BYTE_SCAN_DISPATCH_LIMIT: usize = 65_535 * 128;

/// Bound overlap amplification from pathological custom detector literals.
/// A selected GPU route fails visibly instead of issuing an effectively
/// unbounded sequence of tiny-progress dispatches.
pub(super) const MAX_REGION_PRESENCE_REQUEST_DISPATCHES: usize = 4_096;

pub(super) fn region_presence_batch_byte_limit(backend_id: &str) -> usize {
    let live = region_presence_batch_byte_limit_for_input_budget(
        backend_id,
        super::gpu_input_budget::gpu_batch_input_limit(),
    );
    #[cfg(test)]
    {
        return TEST_REGION_PRESENCE_BYTE_LIMIT
            .with(|limit| limit.get().map_or(live, |test_limit| live.min(test_limit)));
    }
    #[cfg(not(test))]
    live
}

#[cfg(test)]
struct TestRegionPresenceByteLimitGuard(Option<usize>);

#[cfg(test)]
impl Drop for TestRegionPresenceByteLimitGuard {
    fn drop(&mut self) {
        TEST_REGION_PRESENCE_BYTE_LIMIT.with(|limit| limit.set(self.0));
    }
}

#[cfg(test)]
pub(super) fn with_test_region_presence_byte_limit<R>(limit: usize, f: impl FnOnce() -> R) -> R {
    assert!(limit > 0 && limit <= REGION_PRESENCE_BATCH_BYTE_LIMIT);
    let previous = TEST_REGION_PRESENCE_BYTE_LIMIT.with(|cell| cell.replace(Some(limit)));
    let _guard = TestRegionPresenceByteLimitGuard(previous);
    f()
}

fn region_presence_batch_byte_limit_for_input_budget(
    backend_id: &str,
    input_budget: usize,
) -> usize {
    let backend_ceiling = if backend_id == "wgpu" {
        WGPU_BYTE_SCAN_DISPATCH_LIMIT
    } else {
        REGION_PRESENCE_BATCH_BYTE_LIMIT
    };
    backend_ceiling.min(input_budget)
}

pub(super) fn validate_region_presence_batch_len(total: usize) -> Result<(), String> {
    if total > REGION_PRESENCE_BATCH_BYTE_LIMIT {
        return Err(format!(
            "coalesced GPU region-presence batch is {total} byte(s), above VYRE's {}-byte scan ceiling. Fix: lower the GPU batch cap or split the request at chunk boundaries before dispatch",
            REGION_PRESENCE_BATCH_BYTE_LIMIT
        ));
    }
    Ok(())
}

fn region_presence_batch_len_by(
    chunk_count: usize,
    mut chunk_len: impl FnMut(usize) -> usize,
) -> Result<usize, String> {
    let mut total = chunk_count.saturating_sub(1);
    for idx in 0..chunk_count {
        total = total.checked_add(chunk_len(idx)).ok_or_else(|| {
            "coalesced GPU region-presence batch length overflows host usize".to_string()
        })?;
    }
    Ok(total)
}

pub(super) fn region_presence_batch_len(chunks: &[keyhog_core::Chunk]) -> Result<usize, String> {
    region_presence_batch_len_by(chunks.len(), |idx| chunks[idx].data.len())
}

pub(super) fn region_presence_ref_batch_len(
    chunks: &[&keyhog_core::Chunk],
) -> Result<usize, String> {
    region_presence_batch_len_by(chunks.len(), |idx| chunks[idx].data.len())
}

fn next_region_presence_shard(
    chunk_count: usize,
    mut chunk_len: impl FnMut(usize) -> usize,
    start: usize,
    byte_limit: usize,
) -> Result<RegionPresenceShard, String> {
    if start >= chunk_count {
        return Err(format!(
            "coalesced GPU region-presence shard starts beyond chunk index {start}"
        ));
    }
    let first_len = chunk_len(start);
    if first_len > byte_limit {
        return Err(format!(
            "GPU region-presence chunk {start} is {first_len} byte(s), above the selected backend's {byte_limit}-byte dispatch ceiling, and has no safe chunk boundary at which to split. Fix: lower the source chunk size while retaining the detector overlap"
        ));
    }

    let mut end = start + 1;
    let mut coalesced_bytes = first_len;
    while end < chunk_count {
        let Some(candidate) = coalesced_bytes
            .checked_add(1)
            .and_then(|total| total.checked_add(chunk_len(end)))
        else {
            return Err(
                "coalesced GPU region-presence batch length overflows host usize".to_string(),
            );
        };
        if candidate > byte_limit {
            break;
        }
        coalesced_bytes = candidate;
        end += 1;
    }

    Ok(RegionPresenceShard {
        chunks: start..end,
        coalesced_bytes,
    })
}

/// Split only between existing chunks, preserving source-window overlap and row multiplicity.
fn region_presence_shards_with_limit<'a>(
    chunk_count: usize,
    mut chunk_len: impl FnMut(usize) -> usize + 'a,
    byte_limit: usize,
) -> Result<impl Iterator<Item = Result<RegionPresenceShard, String>> + 'a, String> {
    if byte_limit == 0 || byte_limit > REGION_PRESENCE_BATCH_BYTE_LIMIT {
        return Err(format!(
            "GPU region-presence shard limit {byte_limit} is outside the supported range 1..={REGION_PRESENCE_BATCH_BYTE_LIMIT}"
        ));
    }
    let mut start = 0usize;
    let mut finished = false;
    Ok(std::iter::from_fn(move || {
        if finished || start >= chunk_count {
            return None;
        }
        match next_region_presence_shard(chunk_count, &mut chunk_len, start, byte_limit) {
            Ok(shard) => {
                start = shard.chunks.end;
                Some(Ok(shard))
            }
            Err(error) => {
                finished = true;
                Some(Err(error))
            }
        }
    }))
}

pub(super) fn region_presence_shards(
    chunks: &[keyhog_core::Chunk],
    byte_limit: usize,
) -> Result<impl Iterator<Item = Result<RegionPresenceShard, String>> + '_, String> {
    region_presence_shards_with_limit(chunks.len(), |idx| chunks[idx].data.len(), byte_limit)
}

pub(super) fn region_presence_ref_shards<'a>(
    chunks: &'a [&keyhog_core::Chunk],
    byte_limit: usize,
) -> Result<impl Iterator<Item = Result<RegionPresenceShard, String>> + 'a, String> {
    region_presence_shards_with_limit(chunks.len(), |idx| chunks[idx].data.len(), byte_limit)
}

fn region_presence_window_ranges(
    len: usize,
    byte_limit: usize,
    max_literal_len: usize,
) -> Result<impl Iterator<Item = Range<usize>>, String> {
    if byte_limit == 0 || byte_limit > REGION_PRESENCE_BATCH_BYTE_LIMIT {
        return Err(format!(
            "GPU region-presence window limit {byte_limit} is outside the supported range 1..={REGION_PRESENCE_BATCH_BYTE_LIMIT}"
        ));
    }
    if max_literal_len == 0 {
        return Err("GPU region-presence windowing requires at least one compiled literal".into());
    }
    if max_literal_len > byte_limit {
        return Err(format!(
            "longest compiled GPU literal is {max_literal_len} byte(s), above the selected backend's {byte_limit}-byte dispatch ceiling"
        ));
    }
    let overlap = max_literal_len - 1;
    let dispatches = region_presence_window_dispatch_count(len, byte_limit, max_literal_len)?;
    if dispatches > MAX_REGION_PRESENCE_REQUEST_DISPATCHES {
        return Err(format!(
            "GPU region-presence needs {dispatches} overlap window dispatches, above the request safety limit of {MAX_REGION_PRESENCE_REQUEST_DISPATCHES}. Fix: lower the source chunk size or shorten the detector literal"
        ));
    }
    let mut start = 0usize;
    Ok(std::iter::from_fn(move || {
        if start >= len {
            return None;
        }
        let end = start.saturating_add(byte_limit).min(len);
        let range = start..end;
        start = if end == len { len } else { end - overlap };
        Some(range)
    }))
}

fn region_presence_window_dispatch_count(
    len: usize,
    byte_limit: usize,
    max_literal_len: usize,
) -> Result<usize, String> {
    if max_literal_len == 0 || max_literal_len > byte_limit {
        return Err("GPU region-presence window count received invalid literal bounds".to_string());
    }
    let overlap = max_literal_len - 1;
    let step = byte_limit.checked_sub(overlap).ok_or_else(|| {
        "GPU region-presence window progress underflows the dispatch ceiling".to_string()
    })?;
    if len == 0 {
        return Ok(0);
    }
    if len <= byte_limit {
        return Ok(1);
    }
    1usize
        .checked_add((len - byte_limit).div_ceil(step))
        .ok_or_else(|| "GPU region-presence window count overflows host usize".to_string())
}

pub(super) fn validate_region_presence_request_plan(
    chunks: &[keyhog_core::Chunk],
    byte_limit: usize,
    max_literal_len: usize,
) -> Result<usize, String> {
    let mut dispatches = 0usize;
    let mut cursor = 0usize;
    while cursor < chunks.len() {
        if chunks[cursor].data.len() > byte_limit {
            dispatches = dispatches
                .checked_add(region_presence_window_dispatch_count(
                    chunks[cursor].data.len(),
                    byte_limit,
                    max_literal_len,
                )?)
                .ok_or_else(|| {
                    "GPU region-presence request dispatch count overflows host usize".to_string()
                })?;
            cursor += 1;
        } else {
            let run_start = cursor;
            let run_end = chunks[run_start..]
                .iter()
                .position(|chunk| chunk.data.len() > byte_limit)
                .map_or(chunks.len(), |offset| run_start + offset);
            for shard in region_presence_shards(&chunks[run_start..run_end], byte_limit)? {
                shard?;
                dispatches = dispatches.checked_add(1).ok_or_else(|| {
                    "GPU region-presence request dispatch count overflows host usize".to_string()
                })?;
            }
            cursor = run_end;
        }
        if dispatches > MAX_REGION_PRESENCE_REQUEST_DISPATCHES {
            return Err(format!(
                "GPU region-presence request needs {dispatches} dispatches, above the request safety limit of {MAX_REGION_PRESENCE_REQUEST_DISPATCHES}. Fix: lower the fused batch size or source chunk size"
            ));
        }
    }
    Ok(dispatches)
}

pub(super) fn for_each_region_presence_window(
    bytes: &[u8],
    byte_limit: usize,
    max_literal_len: usize,
    mut f: impl FnMut(&[u8], Range<usize>) -> Result<(), String>,
) -> Result<RegionPresenceBatchSummary, String> {
    let ranges = region_presence_window_ranges(bytes.len(), byte_limit, max_literal_len)?;
    let mut dispatches = 0usize;
    let mut coalesced_bytes = 0usize;
    let mut max_dispatch_bytes = 0usize;
    REGION_PRESENCE_BATCH_SCRATCH
        .try_with(|cell| {
            let mut scratch = cell.try_borrow_mut().map_err(|_| {
                "GPU region-presence window scratch already borrowed on this thread; recursive GPU dispatch is unsupported".to_string()
            })?;
            let mut zero_on_drop = ZeroRegionPresenceScratch::new(&mut scratch);
            for range in ranges {
                let window = &bytes[range.clone()];
                dispatches += 1;
                coalesced_bytes = coalesced_bytes.checked_add(window.len()).ok_or_else(|| {
                    "GPU region-presence window accounting overflows host usize".to_string()
                })?;
                max_dispatch_bytes = max_dispatch_bytes.max(window.len());
                if !crate::ascii_ci::has_ascii_uppercase(window) {
                    f(window, range)?;
                    continue;
                }
                let scratch = zero_on_drop.as_mut();
                scratch.haystack.fill(0);
                scratch.haystack.clear();
                scratch
                    .haystack
                    .try_reserve(window.len())
                    .map_err(|error| format!("GPU region-presence window reserve failed: {error}"))?;
                crate::ascii_ci::write_ascii_lowercase_into(
                    &mut scratch.haystack.spare_capacity_mut()[..window.len()],
                    window,
                );
                // SAFETY: the reserved spare-capacity prefix was initialized
                // exactly once by `write_ascii_lowercase_into` above.
                unsafe {
                    scratch.haystack.set_len(window.len());
                }
                f(&scratch.haystack, range)?;
            }
            Ok::<(), String>(())
        })
        .map_err(|_| {
            "GPU region-presence window scratch unavailable during thread shutdown".to_string()
        })??;
    Ok(RegionPresenceBatchSummary {
        dispatches,
        coalesced_bytes,
        max_dispatch_bytes,
        mode: RegionPresenceBatchMode::Windowed,
    })
}

pub(super) fn build_region_presence_batch(
    chunks: &[keyhog_core::Chunk],
    scratch: &mut RegionPresenceScratch,
) -> std::result::Result<(), String> {
    let total = region_presence_batch_len(chunks)?;
    validate_region_presence_batch_len(total)?;

    scratch.haystack.fill(0);
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
    let spare = &mut scratch.haystack.spare_capacity_mut()[..total];
    let mut offset = 0usize;
    for (idx, chunk) in chunks.iter().enumerate() {
        scratch.region_starts.push(offset as u32);
        let bytes = chunk.data.as_bytes();
        let end = offset + bytes.len();
        crate::ascii_ci::write_ascii_lowercase_into(&mut spare[offset..end], bytes);
        offset = end;
        if idx + 1 != chunks.len() {
            spare[offset].write(0);
            offset += 1;
        }
    }
    debug_assert_eq!(offset, total);
    // SAFETY: total capacity was reserved above, each chunk slice and separator
    // slot in `spare[..total]` was initialized exactly once, and all fallible
    // checks run before writes begin.
    unsafe {
        scratch.haystack.set_len(total);
    }
    Ok(())
}

fn for_each_region_presence_batch_with_limit(
    chunks: &[keyhog_core::Chunk],
    byte_limit: usize,
    mut f: impl FnMut(
        &[u8],
        &[u32],
        RegionPresenceBatchMode,
        &RegionPresenceShard,
    ) -> std::result::Result<(), String>,
) -> std::result::Result<RegionPresenceBatchSummary, String> {
    if chunks.is_empty() {
        return Ok(RegionPresenceBatchSummary {
            dispatches: 0,
            coalesced_bytes: 0,
            max_dispatch_bytes: 0,
            mode: RegionPresenceBatchMode::FoldedScratch,
        });
    }
    if byte_limit == 0 || byte_limit > REGION_PRESENCE_BATCH_BYTE_LIMIT {
        return Err(format!(
            "GPU region-presence shard limit {byte_limit} is outside the supported range 1..={REGION_PRESENCE_BATCH_BYTE_LIMIT}"
        ));
    }
    let total = region_presence_batch_len(chunks)?;
    if total <= byte_limit {
        let shard = RegionPresenceShard {
            chunks: 0..chunks.len(),
            coalesced_bytes: total,
        };
        if let [chunk] = chunks {
            let bytes = chunk.data.as_bytes();
            if !crate::ascii_ci::has_ascii_uppercase(bytes) {
                f(
                    bytes,
                    &[0],
                    RegionPresenceBatchMode::BorrowedSingleChunk,
                    &shard,
                )?;
                return Ok(RegionPresenceBatchSummary {
                    dispatches: 1,
                    coalesced_bytes: total,
                    max_dispatch_bytes: total,
                    mode: RegionPresenceBatchMode::BorrowedSingleChunk,
                });
            }
        }
        return dispatch_region_presence_shards(
            chunks,
            std::iter::once(Ok(shard)),
            RegionPresenceBatchMode::FoldedScratch,
            &mut f,
        );
    }

    let shards =
        region_presence_shards_with_limit(chunks.len(), |idx| chunks[idx].data.len(), byte_limit)?;
    dispatch_region_presence_shards(
        chunks,
        shards,
        RegionPresenceBatchMode::ShardedScratch,
        &mut f,
    )
}

fn dispatch_region_presence_shards(
    chunks: &[keyhog_core::Chunk],
    shards: impl IntoIterator<Item = Result<RegionPresenceShard, String>>,
    overall_mode: RegionPresenceBatchMode,
    f: &mut impl FnMut(
        &[u8],
        &[u32],
        RegionPresenceBatchMode,
        &RegionPresenceShard,
    ) -> std::result::Result<(), String>,
) -> std::result::Result<RegionPresenceBatchSummary, String> {
    let mut coalesced_bytes = 0usize;
    let mut max_dispatch_bytes = 0usize;
    let mut dispatches = 0usize;
    REGION_PRESENCE_BATCH_SCRATCH
        .try_with(|cell| {
            let mut scratch = cell.try_borrow_mut().map_err(|_| {
                "coalesced GPU region-presence scratch already borrowed on this thread; recursive \
                 GPU batch dispatch is unsupported"
                    .to_string()
            })?;
            let mut zero_on_drop = ZeroRegionPresenceScratch::new(&mut scratch);
            for shard in shards {
                let shard = shard?;
                dispatches += 1;
                coalesced_bytes = coalesced_bytes
                    .checked_add(shard.coalesced_bytes)
                    .ok_or_else(|| {
                        "coalesced GPU region-presence shard accounting overflows host usize"
                            .to_string()
                    })?;
                max_dispatch_bytes = max_dispatch_bytes.max(shard.coalesced_bytes);
                let shard_chunks = &chunks[shard.chunks.clone()];
                if let [chunk] = shard_chunks {
                    let bytes = chunk.data.as_bytes();
                    if !crate::ascii_ci::has_ascii_uppercase(bytes) {
                        f(
                            bytes,
                            &[0],
                            RegionPresenceBatchMode::BorrowedSingleChunk,
                            &shard,
                        )?;
                        continue;
                    }
                }
                build_region_presence_batch(shard_chunks, zero_on_drop.as_mut())?;
                f(
                    zero_on_drop.haystack(),
                    zero_on_drop.region_starts(),
                    RegionPresenceBatchMode::FoldedScratch,
                    &shard,
                )?;
            }
            Ok::<(), String>(())
        })
        .map_err(|_| {
            "coalesced GPU region-presence scratch unavailable during thread shutdown".to_string()
        })??;

    Ok(RegionPresenceBatchSummary {
        dispatches,
        coalesced_bytes,
        max_dispatch_bytes,
        mode: overall_mode,
    })
}

pub(super) fn for_each_region_presence_batch(
    chunks: &[keyhog_core::Chunk],
    backend_id: &str,
    f: impl FnMut(
        &[u8],
        &[u32],
        RegionPresenceBatchMode,
        &RegionPresenceShard,
    ) -> std::result::Result<(), String>,
) -> std::result::Result<RegionPresenceBatchSummary, String> {
    for_each_region_presence_batch_with_limit(
        chunks,
        region_presence_batch_byte_limit(backend_id),
        f,
    )
}

/// Capture what [`with_region_presence_batch`] hands its callback for `chunks`:
/// the exact haystack bytes the GPU region-presence DFA will scan, the region
/// start offsets, and whether the borrowed-single-chunk fast path ran (`true`) or
/// the folded-scratch path (`false`). The single owner both paths flow through, so
/// a differential test can prove they present BYTE-IDENTICAL input for the same
/// case-folded content, a stray NUL separator or a lowercasing divergence between
/// the paths would make the GPU DFA see different bytes and emit different presence
/// bits (a silent GPU/CPU parity break). Exposed to `crate::testing` for that test.
pub(crate) fn region_presence_batch_capture(
    chunks: &[keyhog_core::Chunk],
) -> std::result::Result<(Vec<u8>, Vec<u32>, bool), String> {
    with_region_presence_batch(chunks, |haystack, region_starts, mode| {
        Ok((
            haystack.to_vec(),
            region_starts.to_vec(),
            matches!(mode, RegionPresenceBatchMode::BorrowedSingleChunk),
        ))
    })
}

pub(super) fn with_region_presence_batch<R>(
    chunks: &[keyhog_core::Chunk],
    f: impl FnOnce(&[u8], &[u32], RegionPresenceBatchMode) -> std::result::Result<R, String>,
) -> std::result::Result<R, String> {
    if let [chunk] = chunks {
        let bytes = chunk.data.as_bytes();
        if !crate::ascii_ci::has_ascii_uppercase(bytes) {
            let region_starts = [0u32];
            return f(
                bytes,
                &region_starts,
                RegionPresenceBatchMode::BorrowedSingleChunk,
            );
        }
    }

    REGION_PRESENCE_BATCH_SCRATCH
        .try_with(|cell| {
            let mut scratch = cell.try_borrow_mut().map_err(|_| {
                "coalesced GPU region-presence scratch already borrowed on this thread; recursive \
                 GPU batch dispatch is unsupported"
                    .to_string()
            })?;
            let mut zero_on_drop = ZeroRegionPresenceScratch::new(&mut scratch);
            build_region_presence_batch(chunks, zero_on_drop.as_mut())?;
            f(
                zero_on_drop.haystack(),
                zero_on_drop.region_starts(),
                RegionPresenceBatchMode::FoldedScratch,
            )
        })
        .map_err(|_| {
            "coalesced GPU region-presence scratch unavailable during thread shutdown".to_string()
        })?
}

#[cfg(test)]
#[path = "../../tests/unit/gpu_region_batch_sharding.rs"]
mod sharding_tests;

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
