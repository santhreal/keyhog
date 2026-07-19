//! Regex-DFA shard dispatch and direct region admission for phase-2 GPU scanning.

use super::batch::Phase2GpuDfaScratch;

#[derive(Debug)]
pub(super) struct Phase2GpuDfaShard {
    pub(super) pipeline: vyre_libs::scan::RegexDfaPipeline,
    pub(super) phase2_indices: Vec<usize>,
}

impl Phase2GpuDfaShard {
    pub(super) fn scan_admission_into(
        &self,
        backend: &dyn vyre::VyreBackend,
        scratch: &mut Phase2GpuDfaScratch,
        haystack_len: u32,
        admitted: &mut [bool],
    ) -> std::result::Result<usize, String> {
        use vyre_libs::scan::dispatch_io;

        let region_count = u32::try_from(scratch.region_starts.len()).map_err(|error| {
            format!(
                "phase-2 GPU regex-DFA region count {} exceeds the u32 GPU ABI: {error}",
                scratch.region_starts.len()
            )
        })?;
        if region_count == 0 || scratch.region_starts.first().copied() != Some(0) {
            return Err(
                "phase-2 GPU regex-DFA admission requires at least one region beginning at byte 0"
                    .to_string(),
            );
        }
        if admitted.len() != scratch.region_starts.len() {
            return Err(format!(
                "phase-2 GPU regex-DFA admission has {} output row(s), need {region_count}",
                admitted.len()
            ));
        }

        let pattern_count = u32::try_from(self.phase2_indices.len()).map_err(|error| {
            format!(
                "phase-2 GPU regex-DFA shard pattern count {} exceeds the u32 GPU ABI: {error}",
                self.phase2_indices.len()
            )
        })?;
        let presence_words =
            vyre_libs::scan::regex_admission_presence_words(pattern_count) as usize;
        let bitmap_words = scratch
            .region_starts
            .len()
            .checked_mul(presence_words)
            .ok_or_else(|| {
                "phase-2 GPU regex-DFA admission bitmap word count overflows host usize"
                    .to_string()
            })?;
        let bitmap_bytes = bitmap_words
            .checked_mul(std::mem::size_of::<u32>())
            .ok_or_else(|| {
                "phase-2 GPU regex-DFA admission bitmap byte count overflows host usize"
                    .to_string()
            })?;

        let transition_bytes = dispatch_io::u32_words_as_le_bytes(&self.pipeline.dfa.transitions);
        let output_offset_bytes =
            dispatch_io::u32_words_as_le_bytes(&self.pipeline.dfa.output_offsets);
        let output_record_bytes =
            dispatch_io::u32_words_as_le_bytes(&self.pipeline.dfa.output_records);
        let region_start_bytes = dispatch_io::u32_words_as_le_bytes(&scratch.region_starts);
        let region_base_bytes = 0u32.to_le_bytes();
        let haystack_len_bytes = haystack_len.to_le_bytes();
        scratch.dispatch.hit_bytes.clear();
        scratch
            .dispatch
            .hit_bytes
            .try_reserve(bitmap_bytes)
            .map_err(|error| {
                format!(
                    "phase-2 GPU regex-DFA admission bitmap reserve failed for {bitmap_bytes} byte(s): {error}"
                )
            })?;
        scratch.dispatch.hit_bytes.resize(bitmap_bytes, 0);

        let log2_max_regions = (32 - (region_count.max(2) - 1).leading_zeros()).max(1);
        let program = vyre_libs::scan::regex_admission_by_region_program(
            "haystack",
            "transitions",
            "output_offsets",
            "output_records",
            "region_starts",
            "region_base",
            "haystack_len",
            "presence",
            self.pipeline.dfa.state_count,
            u32::try_from(self.pipeline.dfa.output_records.len()).map_err(|error| {
                format!(
                    "phase-2 GPU regex-DFA output record count {} exceeds the u32 GPU ABI: {error}",
                    self.pipeline.dfa.output_records.len()
                )
            })?,
            region_count,
            presence_words as u32,
            self.pipeline.dfa.max_pattern_len,
            log2_max_regions,
        );
        let config = dispatch_io::byte_scan_dispatch_config(
            haystack_len,
            program.workgroup_size[0],
        );
        let inputs = [
            scratch.dispatch.haystack_bytes.as_slice(),
            transition_bytes.as_ref(),
            output_offset_bytes.as_ref(),
            output_record_bytes.as_ref(),
            region_start_bytes.as_ref(),
            region_base_bytes.as_slice(),
            haystack_len_bytes.as_slice(),
            scratch.dispatch.hit_bytes.as_slice(),
        ];
        backend
            .dispatch_borrowed_into(&program, &inputs, &config, &mut scratch.outputs)
            .map_err(|error| error.to_string())?;
        let presence = dispatch_io::try_output_bytes(
            &scratch.outputs,
            0,
            "phase-2 GPU regex-DFA admission bitmap",
        )
        .map_err(|error| error.to_string())?;
        if presence.len() < bitmap_bytes {
            return Err(format!(
                "phase-2 GPU regex-DFA admission returned {} bitmap byte(s), need {bitmap_bytes}",
                presence.len()
            ));
        }

        let row_bytes = presence_words * std::mem::size_of::<u32>();
        let mut evidence_bits = 0usize;
        for (region, row) in presence[..bitmap_bytes]
            .chunks_exact(row_bytes)
            .enumerate()
        {
            let mut row_admitted = false;
            for word in row.chunks_exact(std::mem::size_of::<u32>()) {
                let word = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
                row_admitted |= word != 0;
                evidence_bits = evidence_bits.saturating_add(word.count_ones() as usize);
            }
            admitted[region] |= row_admitted;
        }
        Ok(evidence_bits)
    }
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
