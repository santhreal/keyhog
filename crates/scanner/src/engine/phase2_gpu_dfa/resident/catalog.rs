//! One resident input set and dispatch sequence for a complete DFA catalog.

use super::shard::ShardResident;
use super::{allocate, free_resources, SHARED_BINDINGS, U32_BYTES};
use crate::engine::phase2_gpu_dfa::batch::Phase2GpuDfaScratch;
use crate::engine::phase2_gpu_dfa::shard::Phase2GpuDfaShard;
use std::sync::{Arc, Mutex};
use vyre::backend::{ResidentDispatchStep, ResidentReadRange, Resource};
use vyre::VyreBackend;

pub(in crate::engine::phase2_gpu_dfa) struct Phase2GpuDfaCatalogResident {
    slot: Mutex<ResidentSlot>,
}

impl std::fmt::Debug for Phase2GpuDfaCatalogResident {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Phase2GpuDfaCatalogResident")
            .finish_non_exhaustive()
    }
}

impl Default for Phase2GpuDfaCatalogResident {
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
    shared: Vec<Resource>,
    shards: Vec<ShardResident>,
    haystack_capacity: usize,
    region_capacity: u32,
}

#[derive(Clone, Copy)]
struct ResidentCapacity {
    haystack_bytes: usize,
    regions: u32,
}

impl ResidentCapacity {
    fn for_batch(packed_haystack_bytes: usize, regions: usize) -> Result<Self, String> {
        let ceiling = vyre_libs::scan::dispatch_io::DEFAULT_MAX_SCAN_BYTES as usize;
        if packed_haystack_bytes > ceiling {
            return Err(format!(
                "phase-2 GPU resident admission haystack is {packed_haystack_bytes} byte(s), above Vyrë's {ceiling}-byte scan ceiling. Fix: split the batch before dispatch."
            ));
        }
        let regions = u32::try_from(regions).map_err(|error| {
            format!(
                "phase-2 GPU resident admission region count exceeds the u32 GPU ABI: {error}. Fix: split the batch before dispatch."
            )
        })?;
        if regions == 0 {
            return Err(
                "phase-2 GPU resident admission requires at least one region. Fix: do not dispatch an empty batch."
                    .to_string(),
            );
        }
        let region_capacity = regions.checked_next_power_of_two().ok_or_else(|| {
            format!(
                "phase-2 GPU resident admission region capacity overflows u32 for {regions} regions. Fix: split the batch before dispatch."
            )
        })?;
        if packed_haystack_bytes % U32_BYTES != 0 {
            return Err(format!(
                "phase-2 GPU resident admission haystack capacity is {packed_haystack_bytes} byte(s), not aligned to the {U32_BYTES}-byte GPU element ABI. Fix: pad the packed batch before resident preparation."
            ));
        }
        if ceiling % U32_BYTES != 0 {
            return Err(format!(
                "Vyrë's phase-2 GPU scan ceiling {ceiling} is not aligned to the {U32_BYTES}-byte GPU element ABI. Fix: align the backend scan ceiling."
            ));
        }
        let growth = packed_haystack_bytes / 4;
        let grown = packed_haystack_bytes.checked_add(growth).ok_or_else(|| {
            "phase-2 GPU resident haystack growth overflows host usize. Fix: lower the GPU batch cap."
                .to_string()
        })?;
        let aligned = grown
            .checked_add(U32_BYTES - 1)
            .ok_or_else(|| {
                "phase-2 GPU resident haystack alignment overflows host usize. Fix: lower the GPU batch cap."
                    .to_string()
            })?
            / U32_BYTES
            * U32_BYTES;
        let haystack_bytes = aligned.min(ceiling).max(U32_BYTES);
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

#[cfg(test)]
pub(in crate::engine::phase2_gpu_dfa) fn resident_capacity_for_test(
    packed_haystack_bytes: usize,
    regions: usize,
) -> Result<(usize, u32), String> {
    ResidentCapacity::for_batch(packed_haystack_bytes, regions)
        .map(|capacity| (capacity.haystack_bytes, capacity.regions))
}

impl Phase2GpuDfaCatalogResident {
    pub(in crate::engine::phase2_gpu_dfa) fn scan(
        &self,
        shards: &[Phase2GpuDfaShard],
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
            "phase-2 GPU catalog-resident lock is poisoned after an earlier scan panic. Fix: restart the scanner process and inspect the preceding GPU fault."
                .to_string()
        })?;
        if let ResidentSlot::Failed(reason) = &*slot {
            return Err(format!(
                "phase-2 GPU catalog-resident admission is unhealthy: {reason}. Fix: restart the scanner process after correcting the reported GPU fault."
            ));
        }

        let rebuild = match &*slot {
            ResidentSlot::Empty => true,
            ResidentSlot::Ready(state) => {
                !Arc::ptr_eq(&state.backend, backend)
                    || state.haystack_capacity < scratch.dispatch.haystack_bytes.len()
                    || state.region_capacity < needed.regions
                    || state.shards.len() != shards.len()
            }
            ResidentSlot::Failed(_) => false,
        };
        if rebuild {
            let capacity = needed.preserving(match &*slot {
                ResidentSlot::Ready(state) if Arc::ptr_eq(&state.backend, backend) => Some(state),
                ResidentSlot::Empty | ResidentSlot::Ready(_) | ResidentSlot::Failed(_) => None,
            });
            rebuild_state(&mut slot, shards, backend, capacity)?;
        }

        let result = match &mut *slot {
            ResidentSlot::Ready(state) => state.scan(scratch, haystack_len, admitted),
            ResidentSlot::Empty | ResidentSlot::Failed(_) => Err(
                "phase-2 GPU catalog-resident state was not installed after preparation"
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
        shards: &[Phase2GpuDfaShard],
        backend: &Arc<dyn VyreBackend>,
        capacity: ResidentCapacity,
    ) -> Result<Self, String> {
        let mut shared = Vec::with_capacity(SHARED_BINDINGS);
        let region_bytes = (capacity.regions as usize)
            .checked_mul(U32_BYTES)
            .ok_or_else(|| {
                "phase-2 GPU resident region buffer size overflows host usize. Fix: reduce the batch size."
                    .to_string()
            })?;
        let prepare_shared = (|| {
            allocate(&mut shared, backend, capacity.haystack_bytes, None)?;
            allocate(&mut shared, backend, region_bytes, None)?;
            allocate(&mut shared, backend, U32_BYTES, None)?;
            allocate(&mut shared, backend, U32_BYTES, None)?;
            Ok::<(), String>(())
        })();
        if let Err(error) = prepare_shared {
            return cleanup_after_prepare_error(backend.as_ref(), shared, Vec::new(), error);
        }

        let mut resident_shards = Vec::new();
        if let Err(error) = resident_shards.try_reserve(shards.len()) {
            return cleanup_after_prepare_error(
                backend.as_ref(),
                shared,
                resident_shards,
                format!(
                    "phase-2 GPU resident shard reserve failed for {} shard(s): {error}. Fix: reduce the compiled detector set.",
                    shards.len()
                ),
            );
        }
        for shard in shards {
            match ShardResident::prepare(&shard.pipeline, backend, capacity.regions) {
                Ok(resident) => resident_shards.push(resident),
                Err(error) => {
                    return cleanup_after_prepare_error(
                        backend.as_ref(),
                        shared,
                        resident_shards,
                        error,
                    );
                }
            }
        }
        Ok(Self {
            backend: Arc::clone(backend),
            shared,
            shards: resident_shards,
            haystack_capacity: capacity.haystack_bytes,
            region_capacity: capacity.regions,
        })
    }

    fn scan(
        &mut self,
        scratch: &mut Phase2GpuDfaScratch,
        haystack_len: u32,
        admitted: &mut [bool],
    ) -> Result<usize, String> {
        self.validate_scan(scratch, haystack_len, admitted)?;
        self.stage_region_starts(scratch)?;

        let region_count = scratch.region_starts.len();
        let mut reset_lengths = Vec::new();
        reset_lengths.try_reserve(self.shards.len()).map_err(|error| {
            format!(
                "phase-2 GPU reset-length reserve failed for {} shard(s): {error}. Fix: reduce the compiled detector set.",
                self.shards.len()
            )
        })?;
        for shard in &self.shards {
            reset_lengths.push(shard.used_presence_bytes(region_count)?);
        }
        // LAW10: canonical default; an empty reset set requires zero bytes, while every non-empty shard contributes its exact reset length.
        let reset_bytes = reset_lengths.iter().copied().max().unwrap_or(0);
        scratch.reset_bytes.clear();
        scratch
            .reset_bytes
            .try_reserve(reset_bytes)
            .map_err(|error| {
                format!(
                    "phase-2 GPU resident reset reserve failed: {error}. Fix: reduce the detector or batch size."
                )
            })?;
        scratch.reset_bytes.resize(reset_bytes, 0);

        let region_base = 0u32.to_le_bytes();
        let haystack_len_bytes = haystack_len.to_le_bytes();
        let mut uploads = Vec::new();
        uploads
            .try_reserve(SHARED_BINDINGS.saturating_add(self.shards.len()))
            .map_err(|error| {
                format!(
                    "phase-2 GPU upload-descriptor reserve failed for {} upload(s): {error}. Fix: reduce the compiled detector set.",
                    SHARED_BINDINGS.saturating_add(self.shards.len())
                )
            })?;
        uploads.extend([
            (
                &self.shared[0],
                0usize,
                scratch.dispatch.haystack_bytes.as_slice(),
            ),
            (&self.shared[1], 0usize, scratch.region_bytes.as_slice()),
            (&self.shared[2], 0usize, region_base.as_slice()),
            (&self.shared[3], 0usize, haystack_len_bytes.as_slice()),
        ]);
        for (shard, &byte_len) in self.shards.iter().zip(&reset_lengths) {
            uploads.push((
                shard.presence_resource()?,
                0usize,
                &scratch.reset_bytes[..byte_len],
            ));
        }
        self.backend
            .upload_resident_at_many(&uploads)
            .map_err(|error| error.to_string())?;
        drop(uploads);

        let mut bindings = Vec::new();
        bindings.try_reserve(self.shards.len()).map_err(|error| {
            format!(
                "phase-2 GPU dispatch-binding reserve failed for {} shard(s): {error}. Fix: reduce the compiled detector set.",
                self.shards.len()
            )
        })?;
        for shard in &self.shards {
            bindings.push(shard.bindings(&self.shared)?);
        }

        let mut steps = Vec::<ResidentDispatchStep<'_>>::new();
        let mut reads = Vec::<ResidentReadRange<'_>>::new();
        steps.try_reserve(self.shards.len()).map_err(|error| {
            format!(
                "phase-2 GPU dispatch-step reserve failed for {} shard(s): {error}. Fix: reduce the compiled detector set.",
                self.shards.len()
            )
        })?;
        reads.try_reserve(self.shards.len()).map_err(|error| {
            format!(
                "phase-2 GPU read-range reserve failed for {} shard(s): {error}. Fix: reduce the compiled detector set.",
                self.shards.len()
            )
        })?;
        for ((shard, shard_bindings), &byte_len) in
            self.shards.iter().zip(&bindings).zip(&reset_lengths)
        {
            steps.push(shard.dispatch_step(shard_bindings, haystack_len));
            reads.push(shard.read_range(byte_len)?);
        }

        if scratch.outputs.len() < self.shards.len() {
            scratch.outputs.resize_with(self.shards.len(), Vec::new);
        } else {
            scratch.outputs.truncate(self.shards.len());
        }
        let mut output_refs = Vec::new();
        output_refs
            .try_reserve(scratch.outputs.len())
            .map_err(|error| {
                format!(
                    "phase-2 GPU output-reference reserve failed for {} shard(s): {error}. Fix: reduce the compiled detector set.",
                    scratch.outputs.len()
                )
            })?;
        output_refs.extend(scratch.outputs.iter_mut());
        self.backend
            .dispatch_resident_sequence_read_ranges_into(&steps, &reads, &mut output_refs)
            .map_err(|error| error.to_string())?;
        drop(output_refs);

        let mut evidence_bits = 0usize;
        for ((shard, output), &byte_len) in
            self.shards.iter().zip(&scratch.outputs).zip(&reset_lengths)
        {
            evidence_bits =
                evidence_bits.saturating_add(shard.decode_into(output, byte_len, admitted)?);
        }
        Ok(evidence_bits)
    }

    fn validate_scan(
        &self,
        scratch: &Phase2GpuDfaScratch,
        haystack_len: u32,
        admitted: &[bool],
    ) -> Result<(), String> {
        if self.shared.len() != SHARED_BINDINGS {
            return Err(format!(
                "phase-2 GPU resident catalog has {} shared binding(s), need {SHARED_BINDINGS}. Fix: restart the scanner and inspect resident preparation.",
                self.shared.len()
            ));
        }
        if admitted.len() != scratch.region_starts.len() {
            return Err(format!(
                "phase-2 GPU resident admission has {} output row(s), need {}",
                admitted.len(),
                scratch.region_starts.len()
            ));
        }
        if scratch.region_starts.first().copied() != Some(0) {
            return Err(
                "phase-2 GPU resident admission requires the first region to begin at byte 0. Fix: rebuild the packed batch."
                    .to_string(),
            );
        }
        if haystack_len as usize > scratch.dispatch.haystack_bytes.len() {
            return Err(format!(
                "phase-2 GPU resident logical haystack length is {haystack_len}, but the packed input has {} byte(s). Fix: rebuild the packed batch.",
                scratch.dispatch.haystack_bytes.len()
            ));
        }
        if scratch
            .region_starts
            .iter()
            .any(|&start| start > haystack_len)
            || scratch
                .region_starts
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(
                "phase-2 GPU resident region starts are not strictly ordered within the logical haystack. Fix: rebuild the packed batch."
                    .to_string(),
            );
        }
        if scratch.dispatch.haystack_bytes.len() > self.haystack_capacity
            || scratch.region_starts.len() > self.region_capacity as usize
        {
            return Err(
                "phase-2 GPU resident scan exceeds its prepared capacity. Fix: rebuild the resident catalog at the required capacity."
                    .to_string(),
            );
        }
        Ok(())
    }

    fn stage_region_starts(&self, scratch: &mut Phase2GpuDfaScratch) -> Result<(), String> {
        let region_capacity = self.region_capacity as usize;
        let region_byte_len = region_capacity.checked_mul(U32_BYTES).ok_or_else(|| {
            "phase-2 GPU resident region staging size overflows host usize. Fix: reduce the batch size."
                .to_string()
        })?;
        scratch.region_bytes.clear();
        scratch
            .region_bytes
            .try_reserve(region_byte_len)
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
        Ok(())
    }

    fn free(mut self) -> Result<(), String> {
        let shared = std::mem::take(&mut self.shared);
        let shards = std::mem::take(&mut self.shards);
        cleanup_resources(self.backend.as_ref(), shared, shards)
    }
}

impl Drop for ResidentState {
    fn drop(&mut self) {
        let shared = std::mem::take(&mut self.shared);
        let shards = std::mem::take(&mut self.shards);
        if shared.is_empty() && shards.is_empty() {
            return;
        }
        if let Err(error) = cleanup_resources(self.backend.as_ref(), shared, shards) {
            tracing::warn!(
                target: "keyhog::gpu",
                %error,
                "phase-2 GPU catalog-resident cleanup failed during scanner drop"
            );
        }
    }
}

fn cleanup_resources(
    backend: &dyn VyreBackend,
    shared: Vec<Resource>,
    shards: Vec<ShardResident>,
) -> Result<(), String> {
    let mut first_error = free_resources(backend, shared).err();
    for shard in shards {
        if let Err(error) = shard.free(backend) {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn cleanup_after_prepare_error<T>(
    backend: &dyn VyreBackend,
    shared: Vec<Resource>,
    shards: Vec<ShardResident>,
    error: String,
) -> Result<T, String> {
    match cleanup_resources(backend, shared, shards) {
        Ok(()) => Err(error),
        Err(cleanup) => Err(format!(
            "{error}; partial preparation cleanup failed: {cleanup}"
        )),
    }
}

fn rebuild_state(
    slot: &mut ResidentSlot,
    shards: &[Phase2GpuDfaShard],
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
    match ResidentState::prepare(shards, backend, capacity) {
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
