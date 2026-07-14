//! Scanner-owned VYRE resident region-presence pipeline.
//!
//! The pipeline keeps immutable literal matcher tables on the selected GPU.
//! Capacity grows geometrically from the real batch instead of reserving the
//! scanner's full input budget at startup.

use super::CompiledScanner;
use zeroize::Zeroize;

pub(super) struct GpuResidentPresenceState {
    pipeline: vyre_libs::scan::ResidentPresencePipeline,
    backend: std::sync::Arc<dyn vyre::VyreBackend>,
    output: Vec<u32>,
    scratch: Vec<u8>,
}

pub(super) enum GpuResidentPresenceSlot {
    Empty,
    Ready(GpuResidentPresenceState),
    Failed(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResidentPresenceCapacity {
    required_haystack_bytes: usize,
    haystack_bytes: usize,
    regions: u32,
}

impl ResidentPresenceCapacity {
    fn for_batch(haystack_bytes: usize, region_count: usize) -> Result<Self, String> {
        if haystack_bytes > vyre_libs::scan::dispatch_io::DEFAULT_MAX_SCAN_BYTES as usize {
            return Err(format!(
                "GPU resident region-presence batch is {haystack_bytes} byte(s), above VYRE's \
                 {}-byte scan ceiling. Fix: lower the GPU batch cap or split the request at \
                 chunk boundaries before dispatch.",
                vyre_libs::scan::dispatch_io::DEFAULT_MAX_SCAN_BYTES
            ));
        }
        let required_haystack_bytes = haystack_bytes.max(4);
        let max_haystack_bytes = vyre_libs::scan::dispatch_io::DEFAULT_MAX_SCAN_BYTES as usize;
        let growth_headroom = required_haystack_bytes / 4;
        // The ceiling check above bounds this sum to 1.25 GiB, below usize::MAX
        // even on supported 32-bit targets.
        let haystack_bytes = (required_haystack_bytes + growth_headroom).min(max_haystack_bytes);
        let region_count = u32::try_from(region_count).map_err(|_| {
            format!(
                "GPU resident region-presence batch has {region_count} regions, exceeding the \
                 u32 GPU ABI. Fix: lower the GPU batch region cap."
            )
        })?;
        if region_count == 0 {
            return Err(
                "GPU resident region-presence requires at least one region. Fix: do not dispatch an empty batch."
                    .to_string(),
            );
        }
        let regions = region_count.checked_next_power_of_two().ok_or_else(|| {
            format!(
                "GPU resident region-presence region capacity overflows u32 for a \
                 {region_count}-region batch. Fix: lower the GPU batch region cap."
            )
        })?;
        Ok(Self {
            required_haystack_bytes,
            haystack_bytes,
            regions,
        })
    }

    fn fits(self, state: &GpuResidentPresenceState) -> bool {
        state.pipeline.haystack_capacity() >= self.required_haystack_bytes
            && state.pipeline.max_regions() >= self.regions
    }

    fn preserving(self, state: Option<&GpuResidentPresenceState>) -> Self {
        let Some(state) = state else {
            return self;
        };
        Self {
            required_haystack_bytes: self.required_haystack_bytes,
            haystack_bytes: self.haystack_bytes.max(state.pipeline.haystack_capacity()),
            regions: self.regions.max(state.pipeline.max_regions()),
        }
    }
}

fn zero_scratch_allocation(buffer: &mut Vec<u8>) {
    buffer.zeroize();
}

fn zero_output_contents(buffer: &mut Vec<u32>) {
    buffer.as_mut_slice().zeroize();
    buffer.clear();
}

struct ZeroResidentHostBuffers<'a> {
    output: &'a mut Vec<u32>,
    scratch: &'a mut Vec<u8>,
}

impl Drop for ZeroResidentHostBuffers<'_> {
    fn drop(&mut self) {
        zero_output_contents(self.output);
        zero_scratch_allocation(self.scratch);
    }
}

impl GpuResidentPresenceState {
    fn clear_host_buffers(&mut self) {
        zero_output_contents(&mut self.output);
        zero_scratch_allocation(&mut self.scratch);
    }

    fn free(mut self) -> Result<(), String> {
        self.clear_host_buffers();
        self.pipeline
            .free(self.backend.as_ref())
            .map_err(|error| format!("failed to free GPU resident presence pipeline: {error}"))
    }
}

pub(super) fn scan_gpu_literal_presence_by_region_resident(
    slot: &std::sync::Mutex<GpuResidentPresenceSlot>,
    matcher: &vyre_libs::scan::GpuLiteralSet,
    backend: &std::sync::Arc<dyn vyre::VyreBackend>,
    haystack: &[u8],
    region_starts: &[u32],
) -> Result<Vec<u32>, String> {
    let needed = ResidentPresenceCapacity::for_batch(haystack.len(), region_starts.len())?;
    let mut slot = slot.lock().map_err(|_| {
        "GPU resident presence pipeline lock is poisoned after an earlier scan panic. Fix: restart the scanner process and inspect the preceding GPU fault."
            .to_string()
    })?;

    if let GpuResidentPresenceSlot::Failed(reason) = &*slot {
        return Err(format!(
            "GPU resident presence pipeline is unhealthy after an earlier preparation or cleanup failure: {reason}. Fix: restart the scanner process after correcting the reported GPU fault."
        ));
    }

    let must_rebuild = match &*slot {
        GpuResidentPresenceSlot::Empty => true,
        GpuResidentPresenceSlot::Ready(state) => {
            state.backend.id() != backend.id()
                || state.backend.version() != backend.version()
                || !needed.fits(state)
        }
        GpuResidentPresenceSlot::Failed(_) => false,
    };
    if must_rebuild {
        let capacity = needed.preserving(match &*slot {
            GpuResidentPresenceSlot::Ready(state) => Some(state),
            GpuResidentPresenceSlot::Empty | GpuResidentPresenceSlot::Failed(_) => None,
        });
        let prior = std::mem::replace(&mut *slot, GpuResidentPresenceSlot::Empty);
        if let GpuResidentPresenceSlot::Ready(prior) = prior {
            if let Err(error) = prior.free() {
                *slot = GpuResidentPresenceSlot::Failed(error.clone());
                return Err(error);
            }
        }
        let pipeline = match matcher
            .prepare_resident_presence(backend.as_ref(), capacity.haystack_bytes, capacity.regions)
            .map_err(|error| {
                format!(
                    "failed to prepare the selected GPU resident region-presence pipeline \
                     ({}-byte haystack, {} regions): {error}",
                    capacity.haystack_bytes, capacity.regions
                )
            }) {
            Ok(pipeline) => pipeline,
            Err(error) => {
                *slot = GpuResidentPresenceSlot::Failed(error.clone());
                return Err(error);
            }
        };
        *slot = GpuResidentPresenceSlot::Ready(GpuResidentPresenceState {
            pipeline,
            backend: std::sync::Arc::clone(backend),
            output: Vec::new(),
            scratch: Vec::new(),
        });
    }

    let GpuResidentPresenceSlot::Ready(state) = &mut *slot else {
        return Err(
            "GPU resident presence pipeline was not installed after successful preparation"
                .to_string(),
        );
    };
    if super::profile::perf_trace_enabled() {
        eprintln!(
            "perf-trace gpu-resident-presence: action={} backend={} haystack_capacity={} region_capacity={}",
            if must_rebuild { "prepare" } else { "reuse" },
            backend.id(),
            state.pipeline.haystack_capacity(),
            state.pipeline.max_regions(),
        );
    }
    let guard = ZeroResidentHostBuffers {
        output: &mut state.output,
        scratch: &mut state.scratch,
    };
    state
        .pipeline
        .scan_into(
            backend.as_ref(),
            haystack,
            region_starts,
            0,
            guard.output,
            guard.scratch,
        )
        .map_err(|error| format!("resident region-presence dispatch error: {error}"))?;
    Ok(guard.output.clone())
}

impl CompiledScanner {
    pub(super) fn gpu_resident_presence_slot(
        &self,
        backend: crate::hw_probe::ScanBackend,
    ) -> Option<&std::sync::Mutex<GpuResidentPresenceSlot>> {
        match backend {
            crate::hw_probe::ScanBackend::GpuCuda => Some(&self.gpu_resident_presence_cuda),
            crate::hw_probe::ScanBackend::GpuWgpu => Some(&self.gpu_resident_presence_wgpu),
            _ => None,
        }
    }
}

impl Drop for CompiledScanner {
    fn drop(&mut self) {
        for slot in [
            &mut self.gpu_resident_presence_cuda,
            &mut self.gpu_resident_presence_wgpu,
        ] {
            let state = match slot.get_mut() {
                Ok(slot) => std::mem::replace(slot, GpuResidentPresenceSlot::Empty),
                Err(poisoned) => {
                    std::mem::replace(poisoned.into_inner(), GpuResidentPresenceSlot::Empty)
                }
            };
            let GpuResidentPresenceSlot::Ready(state) = state else {
                continue;
            };
            if let Err(error) = state.free() {
                eprintln!("keyhog: GPU resident presence cleanup failed: {error}");
                tracing::warn!(target: "keyhog::gpu", %error, "GPU resident presence cleanup failed");
            }
        }
    }
}
