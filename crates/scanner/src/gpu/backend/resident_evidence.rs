//! Scanner-owned VYRE resident fused presence-and-position pipeline.
//!
//! The pipeline keeps immutable literal matcher tables on the selected GPU and
//! produces both trigger presence and phase-two literal positions in one dispatch.
//! Capacity grows geometrically from the real batch instead of reserving the
//! scanner's full input budget at startup.

use crate::engine::{CompiledScanner, ScannerBackendState};
use crate::gpu::evidence;
use zeroize::Zeroize;

#[cfg(test)]
thread_local! {
    static TEST_FAIL_AFTER_DISPATCHES: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static TEST_MAX_IN_FLIGHT_SLOTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
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

#[cfg(test)]
pub(crate) fn reset_test_max_in_flight_slots() {
    TEST_MAX_IN_FLIGHT_SLOTS.with(|maximum| maximum.set(0));
}

#[cfg(test)]
pub(crate) fn test_max_in_flight_slots() -> usize {
    TEST_MAX_IN_FLIGHT_SLOTS.with(std::cell::Cell::get)
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

struct GpuResidentLiteralSession {
    pipeline: vyre::scan::ResidentFusedRegionScan,
    output: Vec<u32>,
    matches: Vec<vyre::scan::LiteralMatch>,
    scratch: Vec<u8>,
    in_flight: bool,
    device_bytes: u64,
}

pub(crate) struct GpuResidentLiteralState {
    sessions: [GpuResidentLiteralSession; 2],
    backend: std::sync::Arc<dyn vyre::VyreBackend>,
}

pub(crate) struct GpuBorrowedLiteralState {
    output: Vec<u32>,
    matches: Vec<vyre::scan::LiteralMatch>,
    scratch: vyre::scan::dispatch_io::ScanDispatchScratch,
    max_matches: u32,
}

impl GpuBorrowedLiteralState {
    fn new() -> Self {
        Self {
            output: Vec::new(),
            matches: Vec::new(),
            scratch: vyre::scan::dispatch_io::ScanDispatchScratch::default(),
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
        if haystack_bytes > vyre::scan::dispatch_io::DEFAULT_MAX_SCAN_BYTES as usize {
            return Err(format!(
                "GPU resident region-presence batch is {haystack_bytes} byte(s), above VYRE's \
                 {}-byte scan ceiling. Fix: lower the GPU batch cap or split the request at \
                 chunk boundaries before dispatch.",
                vyre::scan::dispatch_io::DEFAULT_MAX_SCAN_BYTES
            ));
        }
        let required_haystack_bytes = haystack_bytes.max(4);
        let max_haystack_bytes = vyre::scan::dispatch_io::DEFAULT_MAX_SCAN_BYTES as usize;
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
        let pipeline = &state.sessions[0].pipeline;
        pipeline.haystack_capacity() >= self.required_haystack_bytes
            && pipeline.max_regions() >= self.regions
            && pipeline.max_matches() >= self.max_matches
    }

    fn preserving(self, state: Option<&GpuResidentLiteralState>) -> Self {
        let Some(state) = state else {
            return self;
        };
        let pipeline = &state.sessions[0].pipeline;
        Self {
            required_haystack_bytes: self.required_haystack_bytes,
            haystack_bytes: self.haystack_bytes.max(pipeline.haystack_capacity()),
            regions: self.regions.max(pipeline.max_regions()),
            max_matches: self.max_matches.max(pipeline.max_matches()),
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
    matches: &'a mut Vec<vyre::scan::LiteralMatch>,
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
        for session in &mut self.sessions {
            Self::zero_output_contents(&mut session.output);
            session.matches.clear();
            Self::zero_scratch_allocation(&mut session.scratch);
        }
    }

    fn free(mut self) -> Result<(), String> {
        self.clear_host_buffers();
        let mut first_error = None;
        for session in self.sessions {
            let device_bytes = session.device_bytes;
            match session
                .pipeline
                .free(self.backend.as_ref())
                .map_err(|error| format!("failed to free GPU resident literal pipeline: {error}"))
            {
                Ok(()) => evidence::note_device_free(device_bytes),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
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
    matcher: &vyre::scan::GpuLiteralSet,
    backend: &std::sync::Arc<dyn vyre::VyreBackend>,
    haystack: &[u8],
    region_starts: &[u32],
    consume: impl FnOnce(&[u32], &[vyre::scan::LiteralMatch]) -> Result<R, String>,
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
    matcher: &vyre::scan::GpuLiteralSet,
    backend: &std::sync::Arc<dyn vyre::VyreBackend>,
    resident_timed_dispatch_supported: bool,
    haystack: &[u8],
    region_starts: &[u32],
    consume: impl FnOnce(&[u32], &[vyre::scan::LiteralMatch]) -> Result<R, String>,
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
            let session = &mut state.sessions[0];
            if crate::engine::profile::diagnostic() {
                eprintln!(
                    "perf-trace gpu-resident-fused: action={} backend={} haystack_capacity={} region_capacity={} match_capacity={} host_output_capacity={} host_match_capacity={} host_scratch_capacity={}",
                    if must_rebuild || attempt > 0 { "prepare" } else { "reuse" },
                    backend.id(),
                    session.pipeline.haystack_capacity(),
                    session.pipeline.max_regions(),
                    session.pipeline.max_matches(),
                    session.output.capacity(),
                    session.matches.capacity(),
                    session.scratch.capacity(),
                );
            }
            let guard = ZeroResidentHostBuffers {
                output: &mut session.output,
                matches: &mut session.matches,
                scratch: &mut session.scratch,
            };
            let dispatch = {
                #[cfg(test)]
                if injected_dispatch_failure() {
                    Err("injected resident fused literal dispatch fault".to_string())
                } else {
                    session
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
                    session
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
                            evidence::record_queue_wait(timed.wall_ns.saturating_sub(device_ns));
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
            GpuResidentLiteralSlot::Ready(state) => state.sessions[0].pipeline.max_matches(),
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
#[must_use = "pending GPU resident evidence must be retired before its IO slot can be reused"]
pub(crate) struct PendingGpuResidentLiteralEvidence<'a> {
    slot: &'a std::sync::Mutex<GpuResidentLiteralSlot>,
    session_index: usize,
    backend_code: u64,
    pending: Option<vyre::scan::PendingResidentFusedRegion>,
    submitted_at: std::time::Instant,
}

impl Drop for PendingGpuResidentLiteralEvidence<'_> {
    fn drop(&mut self) {
        let Some(dispatch) = self.pending.take() else {
            return;
        };
        let mut output = Vec::new();
        let mut matches = Vec::new();
        let retirement = dispatch.await_into(&mut output, &mut matches);
        GpuResidentLiteralState::zero_output_contents(&mut output);
        matches.clear();
        match self.slot.lock() {
            Ok(mut slot) => {
                if let GpuResidentLiteralSlot::Ready(state) = &mut *slot {
                    if let Some(session) = state.sessions.get_mut(self.session_index) {
                        session.in_flight = false;
                        GpuResidentLiteralState::zero_output_contents(&mut session.output);
                        session.matches.clear();
                    }
                }
            }
            // LAW10: lock poison is surfaced here through a fault receipt and unconditional stderr.
            Err(_) => {
                evidence::record_fault(self.backend_code, evidence::fault::DISPATCH);
                eprintln!(
                    "keyhog: GPU resident pipeline lock was poisoned while abandoning pending work. Restart the scanner before reusing the selected GPU route."
                );
            }
        }
        if let Err(error) = retirement {
            evidence::record_fault(self.backend_code, evidence::fault::DISPATCH);
            eprintln!(
                "keyhog: abandoned GPU resident dispatch retirement failed: {error}. Restart the scanner before reusing the selected GPU route."
            );
            tracing::error!(
                target: "keyhog::gpu",
                %error,
                "abandoned GPU resident dispatch retirement failed"
            );
        }
    }
}

pub(crate) struct GpuResidentLiteralOverlap<'a, M> {
    pending: Option<(PendingGpuResidentLiteralEvidence<'a>, M)>,
}

impl<M> GpuResidentLiteralOverlap<'_, M> {
    pub(crate) const fn new() -> Self {
        Self { pending: None }
    }
}

impl<'a, M: Clone> GpuResidentLiteralOverlap<'a, M> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch(
        &mut self,
        slot: &'a std::sync::Mutex<GpuResidentLiteralSlot>,
        matcher: &vyre::scan::GpuLiteralSet,
        backend: &std::sync::Arc<dyn vyre::VyreBackend>,
        haystack: &[u8],
        region_starts: &[u32],
        metadata: M,
        flush: bool,
        mut consume: impl FnMut(M, &[u32], &[vyre::scan::LiteralMatch]) -> Result<(), String>,
        mut recover: impl FnMut(&M, String) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut finish = |pending: PendingGpuResidentLiteralEvidence<'a>, metadata: M| {
            match finish_gpu_literal_evidence_by_region_resident(
                pending,
                backend,
                |presence, matches| consume(metadata.clone(), presence, matches),
            ) {
                Ok(()) => Ok(()),
                Err(error) => recover(&metadata, error),
            }
        };

        if self.pending.is_some()
            && !gpu_resident_literal_capacity_fits(
                slot,
                backend,
                haystack.len(),
                region_starts.len(),
            )?
        {
            let (pending, metadata) = self.pending.take().ok_or_else(|| {
                "GPU resident overlap lost its pending capacity-growth dispatch".to_string()
            })?;
            finish(pending, metadata)?;
        }

        let current = match submit_gpu_literal_evidence_by_region_resident(
            slot,
            matcher,
            backend,
            haystack,
            region_starts,
        ) {
            Ok(pending) => pending,
            Err(error) => {
                if let Some((pending, prior_metadata)) = self.pending.take() {
                    finish(pending, prior_metadata)?;
                }
                return recover(&metadata, error);
            }
        };
        if let Some((pending, prior_metadata)) = self.pending.replace((current, metadata)) {
            finish(pending, prior_metadata)?;
        }
        if flush {
            let (pending, metadata) = self
                .pending
                .take()
                .ok_or_else(|| "GPU resident overlap flush has no pending dispatch".to_string())?;
            finish(pending, metadata)?;
        }
        Ok(())
    }
}
pub(crate) fn gpu_resident_literal_capacity_fits(
    slot: &std::sync::Mutex<GpuResidentLiteralSlot>,
    backend: &std::sync::Arc<dyn vyre::VyreBackend>,
    haystack_bytes: usize,
    region_count: usize,
) -> Result<bool, String> {
    let needed = ResidentLiteralCapacity::for_batch(haystack_bytes, region_count)?;
    let slot = slot.lock().map_err(|_| {
        "GPU resident literal pipeline lock is poisoned after an earlier scan panic. Fix: restart the scanner process and inspect the preceding GPU fault."
            .to_string()
    })?;
    match &*slot {
        GpuResidentLiteralSlot::Ready(state) => Ok(
            state.backend.id() == backend.id()
                && state.backend.version() == backend.version()
                && needed.fits(state),
        ),
        GpuResidentLiteralSlot::Empty | GpuResidentLiteralSlot::Borrowed(_) => Ok(false),
        GpuResidentLiteralSlot::Failed(reason) => Err(format!(
            "GPU resident literal pipeline is unhealthy after an earlier preparation or cleanup failure: {reason}. Fix: restart the scanner process after correcting the reported GPU fault."
        )),
    }
}

pub(crate) fn submit_gpu_literal_evidence_by_region_resident<'a>(
    slot: &'a std::sync::Mutex<GpuResidentLiteralSlot>,
    matcher: &vyre::scan::GpuLiteralSet,
    backend: &std::sync::Arc<dyn vyre::VyreBackend>,
    haystack: &[u8],
    region_starts: &[u32],
) -> Result<PendingGpuResidentLiteralEvidence<'a>, String> {
    let needed = ResidentLiteralCapacity::for_batch(haystack.len(), region_starts.len())?;
    let mut slot_guard = slot.lock().map_err(|_| {
        "GPU resident literal pipeline lock is poisoned after an earlier scan panic. Fix: restart the scanner process and inspect the preceding GPU fault."
            .to_string()
    })?;
    if let GpuResidentLiteralSlot::Failed(reason) = &*slot_guard {
        return Err(format!(
            "GPU resident literal pipeline is unhealthy after an earlier preparation or cleanup failure: {reason}. Fix: restart the scanner process after correcting the reported GPU fault."
        ));
    }
    let must_rebuild = match &*slot_guard {
        GpuResidentLiteralSlot::Empty | GpuResidentLiteralSlot::Borrowed(_) => true,
        GpuResidentLiteralSlot::Ready(state) => {
            state.backend.id() != backend.id()
                || state.backend.version() != backend.version()
                || !needed.fits(state)
        }
        GpuResidentLiteralSlot::Failed(_) => false,
    };
    if must_rebuild {
        if matches!(
            &*slot_guard,
            GpuResidentLiteralSlot::Ready(state)
                if state.sessions.iter().any(|session| session.in_flight)
        ) {
            return Err(
                "GPU resident literal capacity cannot grow while an earlier dispatch is in flight. Fix: retire the pending batch before submitting the larger batch."
                    .to_string(),
            );
        }
        let capacity = needed.preserving(match &*slot_guard {
            GpuResidentLiteralSlot::Ready(state) => Some(state),
            GpuResidentLiteralSlot::Empty
            | GpuResidentLiteralSlot::Borrowed(_)
            | GpuResidentLiteralSlot::Failed(_) => None,
        });
        rebuild_resident_literal_state(&mut slot_guard, matcher, backend, capacity)?;
    }
    let GpuResidentLiteralSlot::Ready(state) = &mut *slot_guard else {
        return Err(
            "GPU resident literal pipeline was not installed after successful preparation"
                .to_string(),
        );
    };
    let session_index = state
        .sessions
        .iter()
        .position(|session| !session.in_flight)
        .ok_or_else(|| {
            "both GPU resident literal IO slots are in flight. Fix: retire the oldest pending batch before submitting another."
                .to_string()
        })?;
    let session = &mut state.sessions[session_index];
    GpuResidentLiteralState::zero_output_contents(&mut session.output);
    session.matches.clear();
    GpuResidentLiteralState::zero_scratch_allocation(&mut session.scratch);
    #[cfg(test)]
    if injected_dispatch_failure() {
        evidence::record_fault(
            evidence::backend_code(backend.id()),
            evidence::fault::DISPATCH,
        );
        return Err("injected resident fused literal dispatch fault".to_string());
    }
    let haystack_bytes = u64::try_from(haystack.len())
        .map_err(|_| "GPU resident haystack byte accounting exceeds u64".to_string())?;
    // LAW10: conversion failure remains an error through the final ok_or_else; no accounting value is substituted.
    let region_bytes = u64::try_from(region_starts.len())
        // LAW10: conversion failure is propagated by the final ok_or_else.
        .ok()
        .and_then(|regions| regions.checked_mul(4))
        .ok_or_else(|| "GPU resident region-control byte accounting exceeds u64".to_string())?;
    let upload_bytes = haystack_bytes
        .checked_add(region_bytes)
        .ok_or_else(|| "GPU resident upload byte accounting exceeds u64".to_string())?;
    let submitted_at = std::time::Instant::now();
    let pending = session
        .pipeline
        .scan_async(
            backend.as_ref(),
            haystack,
            region_starts,
            0,
            &mut session.scratch,
        )
        .map_err(|error| {
            evidence::record_fault(
                evidence::backend_code(backend.id()),
                evidence::fault::DISPATCH,
            );
            format!("resident fused literal submission error: {error}")
        })?;
    GpuResidentLiteralState::zero_scratch_allocation(&mut session.scratch);
    session.in_flight = true;
    #[cfg(test)]
    {
        let in_flight = state
            .sessions
            .iter()
            .filter(|session| session.in_flight)
            .count();
        TEST_MAX_IN_FLIGHT_SLOTS.with(|maximum| {
            if in_flight > maximum.get() {
                maximum.set(in_flight);
            }
        });
    }
    evidence::record_dispatch_submitted();
    evidence::record_upload(upload_bytes, None);
    Ok(PendingGpuResidentLiteralEvidence {
        backend_code: evidence::backend_code(backend.id()),
        slot,
        session_index,
        pending: Some(pending),
        submitted_at,
    })
}

pub(crate) fn finish_gpu_literal_evidence_by_region_resident<R>(
    mut pending: PendingGpuResidentLiteralEvidence<'_>,
    backend: &std::sync::Arc<dyn vyre::VyreBackend>,
    consume: impl FnOnce(&[u32], &[vyre::scan::LiteralMatch]) -> Result<R, String>,
) -> Result<R, String> {
    let mut slot = pending.slot.lock().map_err(|_| {
        "GPU resident literal pipeline lock is poisoned while retiring pending work. Fix: restart the scanner process and inspect the preceding GPU fault."
            .to_string()
    })?;
    let GpuResidentLiteralSlot::Ready(state) = &mut *slot else {
        return Err(
            "GPU resident literal pipeline disappeared before pending work was retired".to_string(),
        );
    };
    let session = state
        .sessions
        .get_mut(pending.session_index)
        .ok_or_else(|| "GPU resident pending IO slot index is out of range".to_string())?;
    if !session.in_flight {
        return Err("GPU resident pending IO slot was already retired".to_string());
    }
    let dispatch = pending
        .pending
        .take()
        .ok_or_else(|| "GPU resident pending dispatch was already consumed".to_string())?;
    let timing = dispatch
        .await_into_timed(&mut session.output, &mut session.matches)
        .map_err(|error| format!("resident fused literal dispatch error: {error}"));
    session.in_flight = false;
    let complete_ns = u64::try_from(pending.submitted_at.elapsed().as_nanos())
        .map_err(|_| "GPU resident dispatch duration exceeds u64 nanoseconds".to_string())?;
    match timing {
        Ok(timing) => {
            evidence::record_submit_to_complete(complete_ns);
            match timing.device_ns {
                Some(device_ns) => {
                    evidence::record_kernel(device_ns);
                    evidence::record_queue_wait(complete_ns.saturating_sub(device_ns));
                }
                None => evidence::report_capability_unsupported(
                    evidence::backend_code(backend.id()),
                    evidence::capability::KERNEL_TIMESTAMPS,
                ),
            }
            // LAW10: every conversion or arithmetic failure reaches the final ok_or_else and aborts readback accounting.
            let output_bytes = u64::try_from(session.output.len())
                // LAW10: conversion failure is propagated by the final ok_or_else.
                .ok()
                .and_then(|words| words.checked_mul(4))
                .and_then(|bytes| {
                    u64::try_from(session.matches.len())
                        // LAW10: conversion failure is propagated by the final ok_or_else.
                        .ok()
                        .and_then(|matches| matches.checked_mul(12))
                        .and_then(|match_bytes| bytes.checked_add(match_bytes))
                })
                .ok_or_else(|| "GPU resident readback byte accounting exceeds u64".to_string())?;
            evidence::record_readback(output_bytes, None);
            let result = consume(session.output.as_slice(), session.matches.as_slice());
            GpuResidentLiteralState::zero_output_contents(&mut session.output);
            session.matches.clear();
            result
        }
        Err(error) => {
            evidence::record_fault(
                evidence::backend_code(backend.id()),
                evidence::fault::DISPATCH,
            );
            GpuResidentLiteralState::zero_output_contents(&mut session.output);
            session.matches.clear();
            Err(error)
        }
    }
}

fn rebuild_resident_literal_state(
    slot: &mut GpuResidentLiteralSlot,
    matcher: &vyre::scan::GpuLiteralSet,
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
    let second_pipeline = match pipeline.fork_independent(backend.as_ref()) {
        Ok(pipeline) => pipeline,
        Err(error) => {
            let preparation_error =
                format!("failed to prepare the second GPU resident literal IO slot: {error}");
            let cleanup_error = pipeline.free(backend.as_ref()).err();
            let error = cleanup_error.map_or(preparation_error.clone(), |cleanup_error| {
                format!("{preparation_error}; primary slot cleanup also failed: {cleanup_error}")
            });
            *slot = GpuResidentLiteralSlot::Failed(error.clone());
            return Err(error);
        }
    };
    let new_session = |pipeline| GpuResidentLiteralSession {
        pipeline,
        output: Vec::new(),
        matches: Vec::new(),
        scratch: Vec::new(),
        in_flight: false,
        device_bytes,
    };
    *slot = GpuResidentLiteralSlot::Ready(GpuResidentLiteralState {
        sessions: [new_session(pipeline), new_session(second_pipeline)],
        backend: std::sync::Arc::clone(backend),
    });
    evidence::note_device_alloc(device_bytes * 2);
    Ok(())
}

impl CompiledScanner {
    pub(crate) fn reset_gpu_resident_literal_for_calibration(
        &self,
    ) -> std::result::Result<(), String> {
        let slots: &[(&str, &std::sync::Mutex<GpuResidentLiteralSlot>)] = match &self.backend_state
        {
            ScannerBackendState::Census {
                resident_literal_cuda,
                resident_literal_wgpu,
                ..
            } => &[
                ("cuda", resident_literal_cuda),
                ("wgpu", resident_literal_wgpu),
            ],
            ScannerBackendState::SelectedGpu {
                peer,
                resident_literal,
            } => &[(peer.backend().label(), resident_literal)],
            ScannerBackendState::SelectedHost(_) | ScannerBackendState::Disabled => &[],
        };
        let mut failures = Vec::new();
        for (backend, slot) in slots {
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
        match &self.backend_state {
            ScannerBackendState::Census {
                resident_literal_cuda,
                resident_literal_metal,
                resident_literal_wgpu,
                ..
            } => match backend {
                crate::hw_probe::ScanBackend::GpuCuda => Some(resident_literal_cuda),
                crate::hw_probe::ScanBackend::GpuMetal => Some(resident_literal_metal),
                crate::hw_probe::ScanBackend::GpuWgpu => Some(resident_literal_wgpu),
                _ => None,
            },
            ScannerBackendState::SelectedGpu {
                peer,
                resident_literal,
            } if peer.backend() == backend => Some(resident_literal),
            ScannerBackendState::SelectedGpu { .. }
            | ScannerBackendState::SelectedHost(_)
            | ScannerBackendState::Disabled => None,
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

fn release_resident_literal_slot(slot: &mut std::sync::Mutex<GpuResidentLiteralSlot>) {
    let state = match slot.get_mut() {
        Ok(slot) => std::mem::replace(slot, GpuResidentLiteralSlot::Empty),
        Err(poisoned) => std::mem::replace(poisoned.into_inner(), GpuResidentLiteralSlot::Empty),
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

impl Drop for CompiledScanner {
    fn drop(&mut self) {
        match &mut self.backend_state {
            ScannerBackendState::Census {
                resident_literal_cuda,
                resident_literal_wgpu,
                ..
            } => {
                release_resident_literal_slot(resident_literal_cuda);
                release_resident_literal_slot(resident_literal_wgpu);
            }
            ScannerBackendState::SelectedGpu {
                resident_literal, ..
            } => release_resident_literal_slot(resident_literal),
            ScannerBackendState::SelectedHost(_) | ScannerBackendState::Disabled => {}
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/gpu_resident_evidence.rs"]
mod tests;
