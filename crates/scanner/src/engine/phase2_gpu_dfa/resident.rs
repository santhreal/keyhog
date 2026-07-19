//! Resident Vyrë execution for one phase-two regex-DFA admission shard.

use super::batch::Phase2GpuDfaScratch;
use std::sync::{Arc, Mutex};
use vyre::backend::{ResidentDispatchStep, ResidentReadRange, Resource};
use vyre::{Program, VyreBackend};

const U32_BYTES: usize = std::mem::size_of::<u32>();
const RESIDENT_BINDINGS: usize = 8;

pub(super) struct Phase2GpuDfaResident {
    slot: Mutex<ResidentSlot>,
}

impl std::fmt::Debug for Phase2GpuDfaResident {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Phase2GpuDfaResident")
            .finish_non_exhaustive()
    }
}

impl Default for Phase2GpuDfaResident {
    fn default() -> Self {
        Self {
            slot: Mutex::new(ResidentSlot::Empty),
        }
    }
}

enum ResidentSlot {
    Empty,
    Ready(ResidentState),
    Failed(String),
}

struct ResidentState {
    backend: Arc<dyn VyreBackend>,
    program: Program,
    resources: Vec<Resource>,
    haystack_capacity: usize,
    region_capacity: u32,
    presence_words: usize,
}

#[derive(Clone, Copy)]
struct ResidentCapacity {
    haystack_bytes: usize,
    regions: u32,
}

impl ResidentCapacity {
    fn for_batch(packed_haystack_bytes: usize, regions: usize) -> Result<Self, String> {
        if packed_haystack_bytes > vyre_libs::scan::dispatch_io::DEFAULT_MAX_SCAN_BYTES as usize {
            return Err(format!(
                "phase-2 GPU resident admission haystack is {packed_haystack_bytes} byte(s), above Vyrë's {}-byte scan ceiling. Fix: split the batch before dispatch.",
                vyre_libs::scan::dispatch_io::DEFAULT_MAX_SCAN_BYTES
            ));
        }
        let regions = u32::try_from(regions).map_err(|error| {
            format!("phase-2 GPU resident admission region count exceeds the u32 GPU ABI: {error}")
        })?;
        if regions == 0 {
            return Err("phase-2 GPU resident admission requires at least one region".to_string());
        }
        let region_capacity = regions.checked_next_power_of_two().ok_or_else(|| {
            format!(
                "phase-2 GPU resident admission region capacity overflows u32 for {regions} regions"
            )
        })?;
        let ceiling = vyre_libs::scan::dispatch_io::DEFAULT_MAX_SCAN_BYTES as usize;
        let growth = packed_haystack_bytes / 4;
        let haystack_bytes = packed_haystack_bytes
            .checked_add(growth)
            .unwrap_or(ceiling)
            .min(ceiling)
            .max(U32_BYTES);
        Ok(Self {
            haystack_bytes,
            regions: region_capacity,
        })
    }

    fn preserving(self, state: Option<&ResidentState>) -> Self {
        let Some(state) = state else {
            return self;
        };
        Self {
            haystack_bytes: self.haystack_bytes.max(state.haystack_capacity),
            regions: self.regions.max(state.region_capacity),
        }
    }
}

impl Phase2GpuDfaResident {
    pub(super) fn scan(
        &self,
        pipeline: &vyre_libs::scan::RegexDfaPipeline,
        backend: &Arc<dyn VyreBackend>,
        scratch: &mut Phase2GpuDfaScratch,
        haystack_len: u32,
        admitted: &mut [bool],
    ) -> Result<usize, String> {
        let needed = ResidentCapacity::for_batch(
            scratch.dispatch.haystack_bytes.len(),
            scratch.region_starts.len(),
        )?;
        let mut slot = self.slot.lock().map_err(|_| {
            "phase-2 GPU resident admission lock is poisoned after an earlier scan panic. Fix: restart the scanner process and inspect the preceding GPU fault."
                .to_string()
        })?;
        if let ResidentSlot::Failed(reason) = &*slot {
            return Err(format!(
                "phase-2 GPU resident admission is unhealthy: {reason}. Fix: restart the scanner process after correcting the reported GPU fault."
            ));
        }

        let rebuild = match &*slot {
            ResidentSlot::Empty => true,
            ResidentSlot::Ready(state) => {
                !Arc::ptr_eq(&state.backend, backend)
                    || state.haystack_capacity < scratch.dispatch.haystack_bytes.len()
                    || state.region_capacity < needed.regions
            }
            ResidentSlot::Failed(_) => false,
        };
        if rebuild {
            let capacity = needed.preserving(match &*slot {
                ResidentSlot::Ready(state) => Some(state),
                ResidentSlot::Empty | ResidentSlot::Failed(_) => None,
            });
            rebuild_state(&mut slot, pipeline, backend, capacity)?;
        }

        let result = match &mut *slot {
            ResidentSlot::Ready(state) => state.scan(scratch, haystack_len, admitted),
            ResidentSlot::Empty | ResidentSlot::Failed(_) => Err(
                "phase-2 GPU resident admission state was not installed after preparation"
                    .to_string(),
            ),
        };
        if let Err(error) = result {
            let prior = std::mem::replace(&mut *slot, ResidentSlot::Failed(error.clone()));
            if let ResidentSlot::Ready(state) = prior {
                if let Err(cleanup) = state.free() {
                    let combined = format!("{error}; resident cleanup also failed: {cleanup}");
                    *slot = ResidentSlot::Failed(combined.clone());
                    return Err(combined);
                }
            }
            return Err(error);
        }
        result
    }
}

impl ResidentState {
    fn prepare(
        pipeline: &vyre_libs::scan::RegexDfaPipeline,
        backend: &Arc<dyn VyreBackend>,
        capacity: ResidentCapacity,
    ) -> Result<Self, String> {
        let pattern_count = u32::try_from(pipeline.pattern_lengths.len()).map_err(|error| {
            format!(
                "phase-2 GPU resident admission pattern count {} exceeds the u32 GPU ABI: {error}",
                pipeline.pattern_lengths.len()
            )
        })?;
        let presence_words =
            vyre_libs::scan::regex_admission_presence_words(pattern_count) as usize;
        let output_records = u32::try_from(pipeline.dfa.output_records.len()).map_err(|error| {
            format!(
                "phase-2 GPU resident admission output record count {} exceeds the u32 GPU ABI: {error}",
                pipeline.dfa.output_records.len()
            )
        })?;
        let log2_max_regions = (32 - (capacity.regions.max(2) - 1).leading_zeros()).max(1);
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
            capacity.regions,
            presence_words as u32,
            pipeline.dfa.max_pattern_len,
            log2_max_regions,
        );

        let region_bytes = (capacity.regions as usize)
            .checked_mul(U32_BYTES)
            .ok_or_else(|| {
                "phase-2 GPU resident admission region buffer size overflows host usize".to_string()
            })?;
        let presence_bytes = region_bytes.checked_mul(presence_words).ok_or_else(|| {
            "phase-2 GPU resident admission presence buffer size overflows host usize".to_string()
        })?;
        let transitions =
            vyre_libs::scan::dispatch_io::u32_words_as_le_bytes(&pipeline.dfa.transitions);
        let output_offsets =
            vyre_libs::scan::dispatch_io::u32_words_as_le_bytes(&pipeline.dfa.output_offsets);
        let output_records =
            vyre_libs::scan::dispatch_io::u32_words_as_le_bytes(&pipeline.dfa.output_records);

        let mut resources = Vec::with_capacity(RESIDENT_BINDINGS);
        let prepare = (|| {
            allocate(&mut resources, backend, capacity.haystack_bytes, None)?;
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
            allocate(&mut resources, backend, region_bytes, None)?;
            allocate(&mut resources, backend, U32_BYTES, None)?;
            allocate(&mut resources, backend, U32_BYTES, None)?;
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
            backend: Arc::clone(backend),
            program,
            resources,
            haystack_capacity: capacity.haystack_bytes,
            region_capacity: capacity.regions,
            presence_words,
        })
    }

    fn scan(
        &mut self,
        scratch: &mut Phase2GpuDfaScratch,
        haystack_len: u32,
        admitted: &mut [bool],
    ) -> Result<usize, String> {
        if admitted.len() != scratch.region_starts.len() {
            return Err(format!(
                "phase-2 GPU resident admission has {} output row(s), need {}",
                admitted.len(),
                scratch.region_starts.len()
            ));
        }
        if scratch.region_starts.first().copied() != Some(0) {
            return Err(
                "phase-2 GPU resident admission requires the first region to begin at byte 0"
                    .to_string(),
            );
        }

        scratch.region_bytes.clear();
        let region_capacity = self.region_capacity as usize;
        scratch
            .region_bytes
            .try_reserve(region_capacity.saturating_mul(U32_BYTES))
            .map_err(|error| {
                format!("phase-2 GPU resident region staging reserve failed: {error}")
            })?;
        for &start in &scratch.region_starts {
            scratch.region_bytes.extend_from_slice(&start.to_le_bytes());
        }
        for _ in scratch.region_starts.len()..region_capacity {
            scratch
                .region_bytes
                .extend_from_slice(&u32::MAX.to_le_bytes());
        }

        let used_presence_bytes = scratch
            .region_starts
            .len()
            .checked_mul(self.presence_words)
            .and_then(|words| words.checked_mul(U32_BYTES))
            .ok_or_else(|| {
                "phase-2 GPU resident admission used presence size overflows host usize".to_string()
            })?;
        scratch.reset_bytes.clear();
        scratch
            .reset_bytes
            .try_reserve(used_presence_bytes)
            .map_err(|error| {
                format!("phase-2 GPU resident presence reset reserve failed: {error}")
            })?;
        scratch.reset_bytes.resize(used_presence_bytes, 0);

        let region_base = 0u32.to_le_bytes();
        let haystack_len_bytes = haystack_len.to_le_bytes();
        let uploads = [
            (
                &self.resources[0],
                0usize,
                scratch.dispatch.haystack_bytes.as_slice(),
            ),
            (&self.resources[4], 0usize, scratch.region_bytes.as_slice()),
            (&self.resources[5], 0usize, region_base.as_slice()),
            (&self.resources[6], 0usize, haystack_len_bytes.as_slice()),
            (&self.resources[7], 0usize, scratch.reset_bytes.as_slice()),
        ];
        self.backend
            .upload_resident_at_many(&uploads)
            .map_err(|error| error.to_string())?;

        let config = vyre_libs::scan::dispatch_io::byte_scan_dispatch_config(
            haystack_len,
            self.program.workgroup_size[0],
        );
        let step = ResidentDispatchStep {
            program: &self.program,
            resources: &self.resources,
            grid_override: config.grid_override,
            workgroup_override: config.workgroup_override,
        };
        let read = ResidentReadRange {
            resource: &self.resources[7],
            byte_offset: 0,
            byte_len: used_presence_bytes,
        };
        if scratch.outputs.is_empty() {
            scratch.outputs.push(Vec::new());
        }
        scratch.outputs.truncate(1);
        self.backend
            .dispatch_resident_sequence_read_ranges_into(
                std::slice::from_ref(&step),
                std::slice::from_ref(&read),
                &mut [&mut scratch.outputs[0]],
            )
            .map_err(|error| error.to_string())?;

        let presence = &scratch.outputs[0];
        if presence.len() != used_presence_bytes {
            return Err(format!(
                "phase-2 GPU resident admission returned {} bitmap byte(s), need {used_presence_bytes}",
                presence.len()
            ));
        }
        let row_bytes = self.presence_words * U32_BYTES;
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

    fn free(mut self) -> Result<(), String> {
        let resources = std::mem::take(&mut self.resources);
        free_resources(self.backend.as_ref(), resources)
    }
}

impl Drop for ResidentState {
    fn drop(&mut self) {
        let resources = std::mem::take(&mut self.resources);
        if resources.is_empty() {
            return;
        }
        if let Err(error) = free_resources(self.backend.as_ref(), resources) {
            tracing::warn!(
                target: "keyhog::gpu",
                %error,
                "phase-2 GPU resident admission cleanup failed during scanner drop"
            );
        }
    }
}

fn allocate(
    resources: &mut Vec<Resource>,
    backend: &Arc<dyn VyreBackend>,
    byte_len: usize,
    upload: Option<&[u8]>,
) -> Result<(), String> {
    let resource = backend
        .allocate_resident(byte_len)
        .map_err(|error| error.to_string())?;
    if let Some(bytes) = upload {
        if let Err(error) = backend.upload_resident(&resource, bytes) {
            let upload_error = error.to_string();
            return match backend.free_resident(resource) {
                Ok(()) => Err(upload_error),
                Err(cleanup) => Err(format!(
                    "{upload_error}; failed to free the rejected resident allocation: {cleanup}"
                )),
            };
        }
    }
    resources.push(resource);
    Ok(())
}

fn free_resources(backend: &dyn VyreBackend, resources: Vec<Resource>) -> Result<(), String> {
    let mut first_error = None;
    for resource in resources {
        if let Err(error) = backend.free_resident(resource) {
            first_error.get_or_insert_with(|| error.to_string());
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn rebuild_state(
    slot: &mut ResidentSlot,
    pipeline: &vyre_libs::scan::RegexDfaPipeline,
    backend: &Arc<dyn VyreBackend>,
    capacity: ResidentCapacity,
) -> Result<(), String> {
    let prior = std::mem::replace(slot, ResidentSlot::Empty);
    if let ResidentSlot::Ready(state) = prior {
        if let Err(error) = state.free() {
            *slot = ResidentSlot::Failed(error.clone());
            return Err(error);
        }
    }
    match ResidentState::prepare(pipeline, backend, capacity) {
        Ok(state) => {
            *slot = ResidentSlot::Ready(state);
            Ok(())
        }
        Err(error) => {
            *slot = ResidentSlot::Failed(error.clone());
            Err(error)
        }
    }
}
