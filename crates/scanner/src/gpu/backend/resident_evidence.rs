//! Scanner-owned VYRE resident fused presence-and-position pipeline.
//!
//! The pipeline keeps immutable literal matcher tables on the selected GPU and
//! produces both trigger presence and phase-two literal positions in one dispatch.
//! Capacity grows geometrically from the real batch instead of reserving the
//! scanner's full input budget at startup.

use crate::engine::CompiledScanner;
use crate::gpu::evidence;
use zeroize::Zeroize;

#[cfg(test)]
thread_local! {
    static TEST_FAIL_AFTER_DISPATCHES: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn with_test_resident_dispatch_failure<R>(
    successful_dispatches_before_failure: usize,
    run: impl FnOnce() -> R,
) -> R {
    struct Reset(Option<usize>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_FAIL_AFTER_DISPATCHES.with(|slot| slot.set(self.0));
        }
    }
    let prior = TEST_FAIL_AFTER_DISPATCHES
        .with(|slot| slot.replace(Some(successful_dispatches_before_failure)));
    let _reset = Reset(prior);
    run()
}

#[cfg(test)]
fn injected_dispatch_failure() -> bool {
    TEST_FAIL_AFTER_DISPATCHES.with(|slot| match slot.get() {
        Some(0) => {
            slot.set(None);
            true
        }
        Some(remaining) => {
            slot.set(Some(remaining - 1));
            false
        }
        None => false,
    })
}

/// VYRE's fused output is a resident array of three-u32 match records. The
/// common path starts at 2^16 records (768 KiB); a denser stable batch is counted
/// exactly, rebuilt at that count, and replayed once without exposing a partial
/// position set.
const GPU_FUSED_MATCH_CAP: u32 = 1 << 16;
/// Bound the rare dense replay to a 24 MiB resident/readback match buffer.
/// Inputs above it stay on the existing exact CPU recovery path instead of
/// turning hostile literal density into an unbounded device allocation.
const GPU_FUSED_MATCH_REPLAY_CAP: u32 = 1 << 21;

pub(crate) struct GpuResidentLiteralState {
    pipeline: vyre_libs::scan::ResidentFusedRegionScan,
    backend: std::sync::Arc<dyn vyre::VyreBackend>,
    output: Vec<u32>,
    matches: Vec<vyre_libs::scan::LiteralMatch>,
    scratch: Vec<u8>,
    /// Lower-bound device bytes held by the resident pipeline (haystack +
    /// region controls + match buffer); transition/bloom tables are not
    /// exposed through the vyre API and stay uncounted.
    device_bytes: u64,
}

pub(crate) struct GpuBorrowedLiteralState {
    output: Vec<u32>,
    matches: Vec<vyre_libs::scan::LiteralMatch>,
    scratch: vyre_libs::scan::dispatch_io::ScanDispatchScratch,
    max_matches: u32,
}

impl GpuBorrowedLiteralState {
    fn new() -> Self {
        Self {
            output: Vec::new(),
            matches: Vec::new(),
            scratch: vyre_libs::scan::dispatch_io::ScanDispatchScratch::default(),
            max_matches: GPU_FUSED_MATCH_CAP,
        }
    }

    fn clear_host_buffers(&mut self) {
        self.output.as_mut_slice().zeroize();
        self.output.clear();
        self.matches.clear();
        self.scratch.haystack_bytes.zeroize();
        self.scratch.hit_bytes.zeroize();
    }
}

pub(crate) enum GpuResidentLiteralSlot {
    Empty,
    Ready(GpuResidentLiteralState),
    Borrowed(GpuBorrowedLiteralState),
    Failed(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResidentLiteralCapacity {
    required_haystack_bytes: usize,
    haystack_bytes: usize,
    regions: u32,
    max_matches: u32,
}

impl ResidentLiteralCapacity {
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
            max_matches: GPU_FUSED_MATCH_CAP,
        })
    }

    fn fits(self, state: &GpuResidentLiteralState) -> bool {
        state.pipeline.haystack_capacity() >= self.required_haystack_bytes
            && state.pipeline.max_regions() >= self.regions
            && state.pipeline.max_matches() >= self.max_matches
    }

    fn preserving(self, state: Option<&GpuResidentLiteralState>) -> Self {
        let Some(state) = state else {
            return self;
        };
        Self {
            required_haystack_bytes: self.required_haystack_bytes,
            haystack_bytes: self.haystack_bytes.max(state.pipeline.haystack_capacity()),
            regions: self.regions.max(state.pipeline.max_regions()),
            max_matches: self.max_matches.max(state.pipeline.max_matches()),
        }
    }

    fn with_max_matches(self, max_matches: u32) -> Self {
        Self {
            max_matches: self.max_matches.max(max_matches),
            ..self
        }
    }
}

struct ZeroResidentHostBuffers<'a> {
    output: &'a mut Vec<u32>,
    matches: &'a mut Vec<vyre_libs::scan::LiteralMatch>,
    scratch: &'a mut Vec<u8>,
}

impl Drop for ZeroResidentHostBuffers<'_> {
    fn drop(&mut self) {
        GpuResidentLiteralState::zero_output_contents(self.output);
        self.matches.clear();
        GpuResidentLiteralState::zero_scratch_allocation(self.scratch);
    }
}

impl GpuResidentLiteralState {
    fn zero_scratch_allocation(buffer: &mut Vec<u8>) {
        buffer.zeroize();
    }

    fn zero_output_contents(buffer: &mut Vec<u32>) {
        buffer.as_mut_slice().zeroize();
        buffer.clear();
    }

    fn clear_host_buffers(&mut self) {
        Self::zero_output_contents(&mut self.output);
        self.matches.clear();
        Self::zero_scratch_allocation(&mut self.scratch);
    }

    fn free(mut self) -> Result<(), String> {
        self.clear_host_buffers();
        let freed = self
            .pipeline
            .free(self.backend.as_ref())
            .map_err(|error| format!("failed to free GPU resident literal pipeline: {error}"));
        if freed.is_ok() {
            evidence::note_device_free(self.device_bytes);
        }
        freed
    }
}

fn prepare_borrowed_literal_state(slot: &mut GpuResidentLiteralSlot) -> Result<(), String> {
    let prior = std::mem::replace(slot, GpuResidentLiteralSlot::Empty);
    match prior {
        GpuResidentLiteralSlot::Empty => {
            *slot = GpuResidentLiteralSlot::Borrowed(GpuBorrowedLiteralState::new());
            Ok(())
        }
        GpuResidentLiteralSlot::Borrowed(state) => {
            *slot = GpuResidentLiteralSlot::Borrowed(state);
            Ok(())
        }
        GpuResidentLiteralSlot::Ready(state) => match state.free() {
            Ok(()) => {
                *slot = GpuResidentLiteralSlot::Borrowed(GpuBorrowedLiteralState::new());
                Ok(())
            }
            Err(error) => {
                *slot = GpuResidentLiteralSlot::Failed(error.clone());
                Err(error)
            }
        },
        GpuResidentLiteralSlot::Failed(error) => {
            *slot = GpuResidentLiteralSlot::Failed(error.clone());
            Err(format!(
                "GPU literal pipeline is unhealthy after an earlier failure: {error}"
            ))
        }
    }
}

fn scan_gpu_literal_evidence_by_region_borrowed<R>(
    slot: &mut GpuResidentLiteralSlot,
    matcher: &vyre_libs::scan::GpuLiteralSet,
    backend: &std::sync::Arc<dyn vyre::VyreBackend>,
    haystack: &[u8],
    region_starts: &[u32],
    consume: impl FnOnce(&[u32], &[vyre_libs::scan::LiteralMatch]) -> Result<R, String>,
) -> Result<R, String> {
    prepare_borrowed_literal_state(slot)?;
    let backend_code = evidence::backend_code(backend.id());
    let upload_bytes = (haystack.len() + region_starts.len() * 4) as u64;
    // The borrowed path exists because the backend lacks timestamp features;
    // say so once per profile runtime instead of leaving kernel time absent.
    evidence::report_capability_unsupported(backend_code, evidence::capability::KERNEL_TIMESTAMPS);
    let mut consume = Some(consume);
    for attempt in 0..2 {
        let (scan_error, current_capacity) = {
            let GpuResidentLiteralSlot::Borrowed(state) = slot else {
                return Err(
                    "GPU borrowed literal pipeline was not installed after successful preparation"
                        .to_string(),
                );
            };
            let dispatch_wall = keyhog_profile::enabled().then(std::time::Instant::now);
            let dispatch = matcher
                .scan_presence_and_positions_by_region_with_scratch(
                    backend.as_ref(),
                    haystack,
                    region_starts,
                    0,
                    state.max_matches,
                    &mut state.matches,
                    &mut state.scratch,
                )
                .map_err(|error| error.to_string());
            match dispatch {
                Ok(output) => {
                    evidence::record_dispatch_submitted();
                    evidence::record_upload(upload_bytes, None);
                    if let Some(start) = dispatch_wall {
                        evidence::record_submit_to_complete(start.elapsed().as_nanos() as u64);
                    }
                    evidence::record_readback(
                        (output.len() * 4 + state.matches.len() * 12) as u64,
                        None,
                    );
                    state.output = output;
                    let consume = consume.take().ok_or_else(|| {
                        "GPU borrowed literal output consumer was already invoked".to_string()
                    })?;
                    let result = consume(state.output.as_slice(), state.matches.as_slice());
                    state.clear_host_buffers();
                    return result;
                }
                Err(error) => {
                    evidence::record_fault(backend_code, evidence::fault::DISPATCH);
                    let current_capacity = state.max_matches;
                    state.clear_host_buffers();
                    (
                        format!("borrowed fused literal dispatch error: {error}"),
                        current_capacity,
                    )
                }
            }
        };
        if attempt == 1 {
            return Err(scan_error);
        }
        let exact_count = matcher.count(backend.as_ref(), haystack).map_err(|error| {
            format!("{scan_error}; exact GPU match-count diagnosis also failed: {error}")
        })?;
        if exact_count <= current_capacity {
            return Err(scan_error);
        }
        if exact_count > GPU_FUSED_MATCH_REPLAY_CAP {
            return Err(format!(
                "{scan_error}; exact GPU match count {exact_count} exceeds the bounded dense-replay cap {GPU_FUSED_MATCH_REPLAY_CAP}. Fix: split the GPU batch or allow automatic stable-byte recovery."
            ));
        }
        let GpuResidentLiteralSlot::Borrowed(state) = slot else {
            return Err("GPU borrowed literal pipeline disappeared before replay".to_string());
        };
        state.max_matches = exact_count;
        evidence::record_retry(1);
    }
    Err("GPU borrowed literal scan exhausted its bounded replay".to_string())
}

/// Dispatch into scanner-owned readback allocations and expose presence plus
/// positioned matches only for the duration of `consume`. The callback runs
/// while the resident slot is locked so no later dispatch can overwrite them.
pub(crate) fn scan_gpu_literal_evidence_by_region_resident<R>(
    slot: &std::sync::Mutex<GpuResidentLiteralSlot>,
    matcher: &vyre_libs::scan::GpuLiteralSet,
    backend: &std::sync::Arc<dyn vyre::VyreBackend>,
    resident_timed_dispatch_supported: bool,
    haystack: &[u8],
    region_starts: &[u32],
    consume: impl FnOnce(&[u32], &[vyre_libs::scan::LiteralMatch]) -> Result<R, String>,
) -> Result<R, String> {
    let needed = ResidentLiteralCapacity::for_batch(haystack.len(), region_starts.len())?;
    let mut slot = slot.lock().map_err(|_| {
        "GPU resident literal pipeline lock is poisoned after an earlier scan panic. Fix: restart the scanner process and inspect the preceding GPU fault."
            .to_string()
    })?;

    if let GpuResidentLiteralSlot::Failed(reason) = &*slot {
        return Err(format!(
            "GPU resident literal pipeline is unhealthy after an earlier preparation or cleanup failure: {reason}. Fix: restart the scanner process after correcting the reported GPU fault."
        ));
    }
    if !resident_timed_dispatch_supported {
        #[cfg(test)]
        if injected_dispatch_failure() {
            evidence::record_fault(
                evidence::backend_code(backend.id()),
                evidence::fault::DISPATCH,
            );
            return Err("injected borrowed fused literal dispatch fault".to_string());
        }
        return scan_gpu_literal_evidence_by_region_borrowed(
            &mut slot,
            matcher,
            backend,
            haystack,
            region_starts,
            consume,
        );
    }
    let backend_code = evidence::backend_code(backend.id());
    let upload_bytes = (haystack.len() + region_starts.len() * 4) as u64;
    let mut consume = Some(consume);

    let must_rebuild = match &*slot {
        GpuResidentLiteralSlot::Empty => true,
        GpuResidentLiteralSlot::Ready(state) => {
            state.backend.id() != backend.id()
                || state.backend.version() != backend.version()
                || !needed.fits(state)
        }
        GpuResidentLiteralSlot::Borrowed(_) => true,
        GpuResidentLiteralSlot::Failed(_) => false,
    };
    if must_rebuild {
        let capacity = needed.preserving(match &*slot {
            GpuResidentLiteralSlot::Ready(state) => Some(state),
            GpuResidentLiteralSlot::Empty
            | GpuResidentLiteralSlot::Borrowed(_)
            | GpuResidentLiteralSlot::Failed(_) => None,
        });
        rebuild_resident_literal_state(&mut slot, matcher, backend, capacity)?;
    }

    for attempt in 0..2 {
        let scan_error = {
            let GpuResidentLiteralSlot::Ready(state) = &mut *slot else {
                return Err(
                    "GPU resident literal pipeline was not installed after successful preparation"
                        .to_string(),
                );
            };
            if crate::engine::profile::perf_trace_enabled() {
                eprintln!(
                    "perf-trace gpu-resident-fused: action={} backend={} haystack_capacity={} region_capacity={} match_capacity={} host_output_capacity={} host_match_capacity={} host_scratch_capacity={}",
                    if must_rebuild || attempt > 0 { "prepare" } else { "reuse" },
                    backend.id(),
                    state.pipeline.haystack_capacity(),
                    state.pipeline.max_regions(),
                    state.pipeline.max_matches(),
                    state.output.capacity(),
                    state.matches.capacity(),
                    state.scratch.capacity(),
                );
            }
            let guard = ZeroResidentHostBuffers {
                output: &mut state.output,
                matches: &mut state.matches,
                scratch: &mut state.scratch,
            };
            let dispatch = {
                #[cfg(test)]
                if injected_dispatch_failure() {
                    Err("injected resident fused literal dispatch fault".to_string())
                } else {
                    state
                        .pipeline
                        .scan_into_timed(
                            backend.as_ref(),
                            haystack,
                            region_starts,
                            0,
                            guard.output,
                            guard.matches,
                            guard.scratch,
                        )
                        .map_err(|error| error.to_string())
                }
                #[cfg(not(test))]
                {
                    state
                        .pipeline
                        .scan_into_timed(
                            backend.as_ref(),
                            haystack,
                            region_starts,
                            0,
                            guard.output,
                            guard.matches,
                            guard.scratch,
                        )
                        .map_err(|error| error.to_string())
                }
            };
            match dispatch {
                Ok(timed) => {
                    evidence::record_dispatch_submitted();
                    evidence::record_upload(upload_bytes, None);
                    evidence::record_submit_to_complete(timed.wall_ns);
                    match timed.device_ns {
                        Some(device_ns) => {
                            evidence::record_kernel(device_ns);
                            evidence::record_queue_wait(
                                timed.wall_ns.saturating_sub(device_ns),
                            );
                        }
                        None => {
                            evidence::report_capability_unsupported(
                                backend_code,
                                evidence::capability::KERNEL_TIMESTAMPS,
                            );
                        }
                    }
                    evidence::record_readback(
                        (guard.output.len() * 4 + guard.matches.len() * 12) as u64,
                        None,
                    );
                    let consume = consume.take().ok_or_else(|| {
                        "GPU resident literal output consumer was already invoked".to_string()
                    })?;
                    return consume(guard.output.as_slice(), guard.matches.as_slice());
                }
                Err(error) => {
                    evidence::record_fault(backend_code, evidence::fault::DISPATCH);
                    format!("resident fused literal dispatch error: {error}")
                }
            }
        };
        if attempt == 1 {
            return Err(scan_error);
        }

        // VYRE's resident fused API reports overflow through its closed error
        // contract but does not expose the count separately. Diagnose any first
        // dispatch failure with VYRE's exact count-only primitive. A count above
        // the resident capacity proves overflow without parsing error strings;
        // rebuild once at the exact device count and replay the stable bytes.
        let exact_count = match matcher.count(backend.as_ref(), haystack) {
            Ok(count) => count,
            Err(count_error) => {
                return Err(format!(
                    "{scan_error}; exact GPU match-count diagnosis also failed: {count_error}"
                ));
            }
        };
        let current_capacity = match &*slot {
            GpuResidentLiteralSlot::Ready(state) => state.pipeline.max_matches(),
            GpuResidentLiteralSlot::Empty
            | GpuResidentLiteralSlot::Borrowed(_)
            | GpuResidentLiteralSlot::Failed(_) => 0,
        };
        if exact_count <= current_capacity {
            return Err(scan_error);
        }
        if exact_count > GPU_FUSED_MATCH_REPLAY_CAP {
            return Err(format!(
                "{scan_error}; exact GPU match count {exact_count} exceeds the bounded dense-replay cap {GPU_FUSED_MATCH_REPLAY_CAP}. Fix: split the GPU batch or allow automatic stable-byte recovery."
            ));
        }
        let capacity = needed
            .with_max_matches(exact_count)
            .preserving(match &*slot {
                GpuResidentLiteralSlot::Ready(state) => Some(state),
                GpuResidentLiteralSlot::Empty
                | GpuResidentLiteralSlot::Borrowed(_)
                | GpuResidentLiteralSlot::Failed(_) => None,
            });
        evidence::record_retry(1);
        rebuild_resident_literal_state(&mut slot, matcher, backend, capacity)?;
    }
    Err("GPU resident literal scan exhausted its bounded replay".to_string())
}

fn rebuild_resident_literal_state(
    slot: &mut GpuResidentLiteralSlot,
    matcher: &vyre_libs::scan::GpuLiteralSet,
    backend: &std::sync::Arc<dyn vyre::VyreBackend>,
    capacity: ResidentLiteralCapacity,
) -> Result<(), String> {
    let prior = std::mem::replace(slot, GpuResidentLiteralSlot::Empty);
    match prior {
        GpuResidentLiteralSlot::Ready(prior) => {
            if let Err(error) = prior.free() {
                *slot = GpuResidentLiteralSlot::Failed(error.clone());
                return Err(error);
            }
        }
        GpuResidentLiteralSlot::Borrowed(mut prior) => prior.clear_host_buffers(),
        GpuResidentLiteralSlot::Empty => {}
        GpuResidentLiteralSlot::Failed(error) => {
            *slot = GpuResidentLiteralSlot::Failed(error.clone());
            return Err(format!(
                "GPU literal pipeline is unhealthy after an earlier failure: {error}"
            ));
        }
    }
    let pipeline = match matcher
        .prepare_resident_fused_scan(
            backend.as_ref(),
            capacity.haystack_bytes,
            capacity.regions,
            capacity.max_matches,
        )
        .map_err(|error| {
            format!(
                "failed to prepare the selected GPU resident fused literal pipeline \
                 ({}-byte haystack, {} regions, {} positioned matches): {error}",
                capacity.haystack_bytes, capacity.regions, capacity.max_matches
            )
        }) {
        Ok(pipeline) => pipeline,
        Err(error) => {
            *slot = GpuResidentLiteralSlot::Failed(error.clone());
            return Err(error);
        }
    };
    let device_bytes = capacity.haystack_bytes as u64
        + u64::from(capacity.regions) * 4
        + 8
        + u64::from(capacity.max_matches) * 12;
    *slot = GpuResidentLiteralSlot::Ready(GpuResidentLiteralState {
        pipeline,
        backend: std::sync::Arc::clone(backend),
        output: Vec::new(),
        matches: Vec::new(),
        scratch: Vec::new(),
        device_bytes,
    });
    evidence::note_device_alloc(device_bytes);
    Ok(())
}

impl CompiledScanner {
    pub(crate) fn reset_gpu_resident_literal_for_calibration(
        &self,
    ) -> std::result::Result<(), String> {
        let mut failures = Vec::new();
        for (backend, slot) in [
            ("cuda", &self.gpu_resident_literal_cuda),
            ("wgpu", &self.gpu_resident_literal_wgpu),
        ] {
            if let Err(error) = reset_resident_literal_slot(slot) {
                failures.push(format!("{backend}: {error}"));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "failed to reset GPU resident calibration state for {}",
                failures.join("; ")
            ))
        }
    }

    pub(crate) fn gpu_resident_literal_slot(
        &self,
        backend: crate::hw_probe::ScanBackend,
    ) -> Option<&std::sync::Mutex<GpuResidentLiteralSlot>> {
        match backend {
            crate::hw_probe::ScanBackend::GpuCuda => Some(&self.gpu_resident_literal_cuda),
            crate::hw_probe::ScanBackend::GpuMetal => Some(&self.gpu_resident_literal_metal),
            crate::hw_probe::ScanBackend::GpuWgpu => Some(&self.gpu_resident_literal_wgpu),
            _ => None,
        }
    }
}

fn reset_resident_literal_slot(
    slot: &std::sync::Mutex<GpuResidentLiteralSlot>,
) -> std::result::Result<(), String> {
    let mut slot = slot.lock().map_err(|_| {
        "GPU resident literal calibration state lock is poisoned after an earlier scan panic"
            .to_string()
    })?;
    let state = std::mem::replace(&mut *slot, GpuResidentLiteralSlot::Empty);
    match state {
        GpuResidentLiteralSlot::Empty => Ok(()),
        GpuResidentLiteralSlot::Failed(error) => {
            *slot = GpuResidentLiteralSlot::Failed(error.clone());
            Err(format!(
                "resident literal pipeline was already unhealthy: {error}"
            ))
        }
        GpuResidentLiteralSlot::Borrowed(mut state) => {
            state.clear_host_buffers();
            Ok(())
        }
        GpuResidentLiteralSlot::Ready(state) => {
            if let Err(error) = state.free() {
                *slot = GpuResidentLiteralSlot::Failed(error.clone());
                return Err(error);
            }
            Ok(())
        }
    }
}

impl Drop for CompiledScanner {
    fn drop(&mut self) {
        for slot in [
            &mut self.gpu_resident_literal_cuda,
            &mut self.gpu_resident_literal_wgpu,
        ] {
            let state = match slot.get_mut() {
                Ok(slot) => std::mem::replace(slot, GpuResidentLiteralSlot::Empty),
                Err(poisoned) => {
                    std::mem::replace(poisoned.into_inner(), GpuResidentLiteralSlot::Empty)
                }
            };
            match state {
                GpuResidentLiteralSlot::Ready(state) => {
                    if let Err(error) = state.free() {
                        eprintln!("keyhog: GPU resident literal cleanup failed: {error}");
                        tracing::warn!(target: "keyhog::gpu", %error, "GPU resident literal cleanup failed");
                    }
                }
                GpuResidentLiteralSlot::Borrowed(mut state) => state.clear_host_buffers(),
                GpuResidentLiteralSlot::Empty | GpuResidentLiteralSlot::Failed(_) => {}
            }
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/gpu_resident_evidence.rs"]
mod tests;
