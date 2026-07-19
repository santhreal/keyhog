//! Regex-DFA shard dispatch and direct region admission for phase-2 GPU scanning.

#[derive(Debug)]
pub(super) struct Phase2GpuDfaShard {
    pub(super) pipeline: vyre_libs::scan::RegexDfaPipeline,
    pub(super) phase2_indices: Vec<usize>,
}

pub(in crate::engine) fn match_region(
    region_starts: &[u32],
    haystack_len: usize,
    start: u32,
    end: u32,
) -> Option<usize> {
    if end <= start {
        return None;
    }
    let start_region = region_for_offset(region_starts, start)?;
    let last = end.saturating_sub(1);
    let end_region = region_for_offset(region_starts, last)?;
    if start_region != end_region {
        tracing::warn!(
            target: "keyhog::gpu",
            start,
            end,
            "phase-2 GPU regex-DFA match crossed a coalesced region boundary; ignoring admission hit"
        );
        return None;
    }
    let next_start = region_starts
        .get(start_region + 1)
        .map_or(haystack_len, |&offset| offset as usize);
    let region_end = if start_region + 1 < region_starts.len() {
        next_start.saturating_sub(1)
    } else {
        haystack_len
    };
    let start_usize = match usize::try_from(start) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(
                target: "keyhog::gpu",
                start,
                %error,
                "phase-2 GPU regex-DFA match start does not fit host usize; ignoring admission hit"
            );
            return None;
        }
    };
    let end_usize = match usize::try_from(end) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(
                target: "keyhog::gpu",
                end,
                %error,
                "phase-2 GPU regex-DFA match end does not fit host usize; ignoring admission hit"
            );
            return None;
        }
    };
    if start_usize < region_end && end_usize <= region_end {
        Some(start_region)
    } else {
        tracing::warn!(
            target: "keyhog::gpu",
            start,
            end,
            region = start_region,
            next_start,
            region_end,
            "phase-2 GPU regex-DFA match touches a coalesced separator/outside span; ignoring admission hit"
        );
        None
    }
}

fn region_for_offset(region_starts: &[u32], offset: u32) -> Option<usize> {
    if region_starts.is_empty() {
        return None;
    }
    region_starts
        .partition_point(|&start| start <= offset)
        .checked_sub(1)
}
