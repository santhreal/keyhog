//! Regex-DFA shard dispatch and match attribution for phase-2 GPU admission.

use super::batch::Phase2GpuDfaScratch;
use super::PHASE2_GPU_DFA_MAX_MATCHES;

#[derive(Debug)]
pub(super) struct Phase2GpuDfaShard {
    pub(super) pipeline: vyre_libs::scan::RegexDfaPipeline,
    pub(super) phase2_indices: Vec<usize>,
}

impl Phase2GpuDfaShard {
    /// `marked`, when `Some`, receives per-region the phase-2 pattern indices that
    /// the GPU regex-DFA matched (the SAME indices `scratch.mark` uses on the CPU
    /// path). This is the step-1 seam that lets the caller use the GPU-marked active
    /// set to bypass the CPU always-active RegexSet for covered patterns, inert
    /// (behavior-identical) while callers pass `None`.
    pub(super) fn scan_admission_into(
        &self,
        backend: &dyn vyre::VyreBackend,
        scratch: &mut Phase2GpuDfaScratch,
        haystack_len: u32,
        admitted: &mut [bool],
        mut marked: Option<&mut [Vec<usize>]>,
    ) -> std::result::Result<bool, String> {
        use vyre_libs::scan::dispatch_io;

        let transition_bytes = dispatch_io::u32_words_as_le_bytes(&self.pipeline.dfa.transitions);
        let output_offset_bytes =
            dispatch_io::u32_words_as_le_bytes(&self.pipeline.dfa.output_offsets);
        let output_record_bytes =
            dispatch_io::u32_words_as_le_bytes(&self.pipeline.dfa.output_records);
        let pattern_length_bytes =
            dispatch_io::u32_words_as_le_bytes(&self.pipeline.pattern_lengths);
        let haystack_len_bytes = haystack_len.to_le_bytes();
        let match_count_bytes = [0u8; 4];
        let config = dispatch_io::byte_scan_dispatch_config(
            haystack_len,
            self.pipeline.program.workgroup_size[0],
        );
        let inputs = [
            scratch.dispatch.haystack_bytes.as_slice(),
            transition_bytes.as_ref(),
            output_offset_bytes.as_ref(),
            output_record_bytes.as_ref(),
            pattern_length_bytes.as_ref(),
            haystack_len_bytes.as_slice(),
            match_count_bytes.as_slice(),
        ];
        let outputs = backend
            .dispatch_borrowed(&self.pipeline.program, &inputs, &config)
            .map_err(|error| error.to_string())?;
        let count_bytes =
            dispatch_io::try_output_bytes(&outputs, 0, "phase-2 GPU regex-DFA match count")
                .map_err(|error| error.to_string())?;
        let count =
            dispatch_io::try_read_u32_prefix(count_bytes, "phase-2 GPU regex-DFA match count")
                .map_err(|error| error.to_string())?;
        let triples_bytes =
            dispatch_io::try_output_bytes(&outputs, 1, "phase-2 GPU regex-DFA matches")
                .map_err(|error| error.to_string())?;
        let overflowed = count > PHASE2_GPU_DFA_MAX_MATCHES;
        let decoded_count = count.min(PHASE2_GPU_DFA_MAX_MATCHES);
        // `try_unpack_match_triples_exact_prefix_into` validates that
        // `triples_bytes` holds `decoded_count` triples (Vyre owns the triple
        // byte-width), so no local length pre-check or triple-size constant is
        // duplicated here.
        dispatch_io::try_unpack_match_triples_exact_prefix_into(
            triples_bytes,
            decoded_count,
            &mut scratch.matches,
        )
        .map_err(|error| error.to_string())?;

        let mut unattributed_matches = 0usize;
        for m in &scratch.matches {
            let Some(&phase2_index) = self.phase2_indices.get(m.pattern_id as usize) else {
                return Err(format!(
                    "phase-2 GPU regex-DFA reported pattern id {} outside shard size {}",
                    m.pattern_id,
                    self.phase2_indices.len()
                ));
            };
            if let Some(region) =
                match_region(&scratch.region_starts, scratch.haystack_len, m.start, m.end)
            {
                if let Some(slot) = admitted.get_mut(region) {
                    *slot = true;
                }
                // Step-1 marking: record WHICH phase-2 pattern hit in this region so
                // the caller can substitute the GPU-marked active set for the CPU
                // always-active RegexSet (recall-identical for covered patterns).
                if let Some(marks) = marked.as_deref_mut() {
                    if let Some(region_marks) = marks.get_mut(region) {
                        region_marks.push(phase2_index);
                    }
                }
            } else {
                unattributed_matches = unattributed_matches.saturating_add(1);
            }
        }
        if overflowed {
            tracing::warn!(
                target: "keyhog::gpu",
                count,
                cap = PHASE2_GPU_DFA_MAX_MATCHES,
                "phase-2 GPU regex-DFA admission hit cap; decoded hits can admit chunks, misses still consult CPU admission"
            );
        }
        if unattributed_matches > 0 {
            tracing::warn!(
                target: "keyhog::gpu",
                unattributed = unattributed_matches,
                "phase-2 GPU regex-DFA admission saw unattributed hit(s); decoded hits can admit chunks, misses still consult CPU admission"
            );
        }
        Ok(overflowed || unattributed_matches > 0)
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
