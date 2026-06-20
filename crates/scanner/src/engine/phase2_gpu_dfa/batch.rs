//! Packed upload-batch scratch for phase-2 GPU regex-DFA admission.

use std::cell::RefCell;

#[derive(Default)]
pub(super) struct Phase2GpuDfaScratch {
    #[cfg(test)]
    pub(super) haystack: Vec<u8>,
    pub(super) haystack_len: usize,
    pub(super) region_starts: Vec<u32>,
    pub(super) dispatch: vyre_libs::scan::dispatch_io::ScanDispatchScratch,
    pub(super) matches: Vec<vyre_libs::scan::LiteralMatch>,
}

thread_local! {
    static PHASE2_GPU_DFA_SCRATCH: RefCell<Phase2GpuDfaScratch> =
        RefCell::new(Phase2GpuDfaScratch::default());
}

pub(super) struct ZeroPhase2GpuDfaScratch<'a> {
    pub(super) scratch: &'a mut Phase2GpuDfaScratch,
}

impl<'a> ZeroPhase2GpuDfaScratch<'a> {
    pub(super) fn new(scratch: &'a mut Phase2GpuDfaScratch) -> Self {
        Self { scratch }
    }
}

impl Drop for ZeroPhase2GpuDfaScratch<'_> {
    fn drop(&mut self) {
        #[cfg(test)]
        {
            self.scratch.haystack.fill(0);
            self.scratch.haystack.clear();
        }
        self.scratch.haystack_len = 0;
        self.scratch.region_starts.clear();
        self.scratch.dispatch.haystack_bytes.fill(0);
        self.scratch.dispatch.haystack_bytes.clear();
        self.scratch.dispatch.hit_bytes.fill(0);
        self.scratch.dispatch.hit_bytes.clear();
        self.scratch.matches.clear();
    }
}

pub(super) fn with_phase2_gpu_dfa_scratch<R>(
    f: impl FnOnce(&mut Phase2GpuDfaScratch) -> std::result::Result<R, String>,
) -> std::result::Result<R, String> {
    PHASE2_GPU_DFA_SCRATCH
        .try_with(|cell| {
            let mut scratch = cell.try_borrow_mut().map_err(|_| {
                "phase-2 GPU regex-DFA scratch already borrowed on this thread; recursive \
                 phase-2 GPU admission dispatch is unsupported"
                    .to_string()
            })?;
            let zero_on_drop = ZeroPhase2GpuDfaScratch::new(&mut scratch);
            f(zero_on_drop.scratch)
        })
        .map_err(|_| {
            "phase-2 GPU regex-DFA scratch unavailable during thread shutdown".to_string()
        })?
}

pub(super) fn build_packed_region_batch(
    chunks: &[keyhog_core::Chunk],
    scratch: &mut Phase2GpuDfaScratch,
) -> std::result::Result<(), String> {
    build_packed_region_batch_iter(chunks.iter(), chunks.len(), scratch)
}

pub(super) fn build_packed_region_batch_refs(
    chunks: &[&keyhog_core::Chunk],
    scratch: &mut Phase2GpuDfaScratch,
) -> std::result::Result<(), String> {
    build_packed_region_batch_iter(chunks.iter().copied(), chunks.len(), scratch)
}

fn build_packed_region_batch_iter<'a, I>(
    chunks: I,
    chunk_count: usize,
    scratch: &mut Phase2GpuDfaScratch,
) -> std::result::Result<(), String>
where
    I: Clone + Iterator<Item = &'a keyhog_core::Chunk>,
{
    let mut total = chunk_count.saturating_sub(1);
    for chunk in chunks.clone() {
        total = total.checked_add(chunk.data.len()).ok_or_else(|| {
            "phase-2 GPU regex-DFA coalesced batch length overflows host usize".to_string()
        })?;
    }
    if total > u32::MAX as usize {
        return Err(format!(
            "phase-2 GPU regex-DFA coalesced batch is {total} byte(s), above the u32 GPU ABI; split the batch before dispatch"
        ));
    }
    let padded_len = vyre_libs::scan::dispatch_io::haystack_padded_u32_byte_len(total)
        .map_err(|error| error.to_string())?;

    #[cfg(test)]
    {
        scratch.haystack.clear();
        scratch.haystack.try_reserve(total).map_err(|error| {
            format!("phase-2 GPU regex-DFA replay haystack reserve failed: {error}")
        })?;
    }
    scratch.haystack_len = total;
    scratch.region_starts.clear();
    scratch
        .region_starts
        .try_reserve(chunk_count)
        .map_err(|error| format!("phase-2 GPU regex-DFA region-start reserve failed: {error}"))?;
    scratch.dispatch.haystack_bytes.clear();
    scratch
        .dispatch
        .haystack_bytes
        .try_reserve(padded_len)
        .map_err(|error| {
            format!("phase-2 GPU regex-DFA packed haystack reserve failed: {error}")
        })?;
    for (idx, chunk) in chunks.enumerate() {
        let start = u32::try_from(scratch.dispatch.haystack_bytes.len()).map_err(|_| {
            "phase-2 GPU regex-DFA region start exceeds the u32 GPU ABI".to_string()
        })?;
        scratch.region_starts.push(start);
        scratch
            .dispatch
            .haystack_bytes
            .extend_from_slice(chunk.data.as_bytes());
        #[cfg(test)]
        scratch.haystack.extend_from_slice(chunk.data.as_bytes());
        if idx + 1 != chunk_count {
            scratch.dispatch.haystack_bytes.push(0);
            #[cfg(test)]
            scratch.haystack.push(0);
        }
    }
    scratch.dispatch.haystack_bytes.resize(padded_len, 0);
    Ok(())
}
