//! Immutable DFA tables and private admission output for one catalog shard.

use super::{allocate, free_resources, SHARD_BINDINGS, SHARED_BINDINGS, U32_BYTES};
use std::sync::Arc;
use vyre::backend::{ResidentDispatchStep, ResidentReadRange, Resource};
use vyre::{Program, VyreBackend};

pub(super) struct ShardResident {
    program: Program,
    resources: Vec<Resource>,
    presence_words: usize,
}

impl ShardResident {
    pub(super) fn prepare(
        pipeline: &vyre_libs::scan::RegexDfaPipeline,
        backend: &Arc<dyn VyreBackend>,
        region_capacity: u32,
    ) -> Result<Self, String> {
        let pattern_count = u32::try_from(pipeline.pattern_lengths.len()).map_err(|error| {
            format!(
                "phase-2 GPU resident pattern count {} exceeds the u32 GPU ABI: {error}",
                pipeline.pattern_lengths.len()
            )
        })?;
        let presence_words =
            vyre_libs::scan::regex_admission_presence_words(pattern_count) as usize;
        let output_records = u32::try_from(pipeline.dfa.output_records.len()).map_err(|error| {
            format!(
                "phase-2 GPU resident output record count {} exceeds the u32 GPU ABI: {error}",
                pipeline.dfa.output_records.len()
            )
        })?;
        let log2_max_regions = (32 - (region_capacity.max(2) - 1).leading_zeros()).max(1);
        let program = vyre_libs::scan::regex_admission_by_region_program(
            "haystack",
            "transitions",
            "output_offsets",
            "output_records",
            "region_starts",
            "region_base",
            "haystack_len",
            "presence",
            pipeline.dfa.state_count,
            output_records,
            region_capacity,
            presence_words as u32,
            pipeline.dfa.max_pattern_len,
            log2_max_regions,
        );
        let presence_bytes = (region_capacity as usize)
            .checked_mul(presence_words)
            .and_then(|words| words.checked_mul(U32_BYTES))
            .ok_or_else(|| {
                "phase-2 GPU resident presence buffer size overflows host usize. Fix: reduce the batch size."
                    .to_string()
            })?;
        let transitions =
            vyre_libs::scan::dispatch_io::u32_words_as_le_bytes(&pipeline.dfa.transitions);
        let output_offsets =
            vyre_libs::scan::dispatch_io::u32_words_as_le_bytes(&pipeline.dfa.output_offsets);
        let output_records =
            vyre_libs::scan::dispatch_io::u32_words_as_le_bytes(&pipeline.dfa.output_records);
        let mut resources = Vec::with_capacity(SHARD_BINDINGS);
        let prepare = (|| {
            allocate(
                &mut resources,
                backend,
                transitions.len(),
                Some(transitions.as_ref()),
            )?;
            allocate(
                &mut resources,
                backend,
                output_offsets.len(),
                Some(output_offsets.as_ref()),
            )?;
            allocate(
                &mut resources,
                backend,
                output_records.len(),
                Some(output_records.as_ref()),
            )?;
            allocate(&mut resources, backend, presence_bytes, None)?;
            Ok::<(), String>(())
        })();
        if let Err(error) = prepare {
            let cleanup = free_resources(backend.as_ref(), resources);
            return Err(match cleanup {
                Ok(()) => error,
                Err(cleanup) => format!("{error}; partial preparation cleanup failed: {cleanup}"),
            });
        }
        Ok(Self {
            program,
            resources,
            presence_words,
        })
    }

    pub(super) fn used_presence_bytes(&self, regions: usize) -> Result<usize, String> {
        regions
            .checked_mul(self.presence_words)
            .and_then(|words| words.checked_mul(U32_BYTES))
            .ok_or_else(|| {
                "phase-2 GPU resident used presence size overflows host usize. Fix: reduce the batch size."
                    .to_string()
            })
    }

    pub(super) fn presence_resource(&self) -> Result<&Resource, String> {
        if self.resources.len() != SHARD_BINDINGS {
            return Err(format!(
                "phase-2 GPU resident shard has {} binding(s), need {SHARD_BINDINGS}. Fix: restart the scanner and inspect resident preparation.",
                self.resources.len()
            ));
        }
        Ok(&self.resources[3])
    }

    pub(super) fn bindings(&self, shared: &[Resource]) -> Result<[Resource; 8], String> {
        if shared.len() != SHARED_BINDINGS || self.resources.len() != SHARD_BINDINGS {
            return Err(
                "phase-2 GPU resident binding cardinality changed after validation. Fix: restart the scanner and inspect resident preparation."
                    .to_string(),
            );
        }
        Ok([
            shared[0].clone(),
            self.resources[0].clone(),
            self.resources[1].clone(),
            self.resources[2].clone(),
            shared[1].clone(),
            shared[2].clone(),
            shared[3].clone(),
            self.resources[3].clone(),
        ])
    }

    pub(super) fn dispatch_step<'a>(
        &'a self,
        bindings: &'a [Resource; 8],
        haystack_len: u32,
    ) -> ResidentDispatchStep<'a> {
        let config = vyre_libs::scan::dispatch_io::byte_scan_dispatch_config(
            haystack_len,
            self.program.workgroup_size[0],
        );
        ResidentDispatchStep {
            program: &self.program,
            resources: bindings,
            grid_override: config.grid_override,
            workgroup_override: config.workgroup_override,
        }
    }

    pub(super) fn read_range(&self, byte_len: usize) -> Result<ResidentReadRange<'_>, String> {
        Ok(ResidentReadRange {
            resource: self.presence_resource()?,
            byte_offset: 0,
            byte_len,
        })
    }

    pub(super) fn decode_into(
        &self,
        presence: &[u8],
        expected_bytes: usize,
        admitted: &mut [bool],
    ) -> Result<usize, String> {
        if presence.len() != expected_bytes {
            return Err(format!(
                "phase-2 GPU resident admission returned {} bitmap byte(s), need {expected_bytes}",
                presence.len()
            ));
        }
        let row_bytes = self.presence_words.checked_mul(U32_BYTES).ok_or_else(|| {
            "phase-2 GPU resident row size overflows host usize. Fix: reduce the detector shard size."
                .to_string()
        })?;
        if row_bytes == 0 || expected_bytes / row_bytes != admitted.len() {
            return Err(
                "phase-2 GPU resident presence rows do not match the admission output. Fix: rebuild the DFA catalog."
                    .to_string(),
            );
        }
        let mut evidence_bits = 0usize;
        for (region, row) in presence.chunks_exact(row_bytes).enumerate() {
            let mut row_admitted = false;
            for word in row.chunks_exact(U32_BYTES) {
                let word = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
                row_admitted |= word != 0;
                evidence_bits = evidence_bits.saturating_add(word.count_ones() as usize);
            }
            admitted[region] |= row_admitted;
        }
        Ok(evidence_bits)
    }

    pub(super) fn free(self, backend: &dyn VyreBackend) -> Result<(), String> {
        free_resources(backend, self.resources)
    }
}
