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
/// Aggregate resident/readback match capacity across every in-flight slot.
/// Pipeline depth divides this ceiling instead of multiplying it.
const GPU_FUSED_MATCH_REPLAY_CAP: u32 = 1 << 21;
pub(crate) const GPU_RESIDENT_PIPELINE_MIN_DEPTH: u8 = 1;
pub(crate) const GPU_RESIDENT_PIPELINE_MAX_DEPTH: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GpuResidentDispatchCapability {
    Synchronous,
    TimedResident,
    AsyncSubmitRetire,
}

impl GpuResidentDispatchCapability {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Synchronous => "synchronous",
            Self::TimedResident => "timed-resident",
            Self::AsyncSubmitRetire => "async-submit-retire",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GpuResidentPipelineConfig {
    pub(crate) depth: u8,
    pub(crate) slot_input_capacity_bytes: usize,
    pub(crate) slot_match_capacity: u32,
}

impl GpuResidentPipelineConfig {
    pub(crate) fn for_depth(depth: u8) -> Result<Self, String> {
        if !(GPU_RESIDENT_PIPELINE_MIN_DEPTH..=GPU_RESIDENT_PIPELINE_MAX_DEPTH).contains(&depth) {
            return Err(format!(
                "GPU resident pipeline depth {depth} is outside the supported {GPU_RESIDENT_PIPELINE_MIN_DEPTH}..={GPU_RESIDENT_PIPELINE_MAX_DEPTH} range. Fix: recalibrate autoroute with this build."
            ));
        }
        let divisor = usize::from(depth);
        let slot_input_capacity_bytes = crate::gpu_input_budget::gpu_batch_input_limit()
            .checked_div(divisor)
            .filter(|capacity| *capacity > 0)
            .ok_or_else(|| "GPU resident per-slot input capacity is zero".to_string())?;
        let slot_match_capacity = GPU_FUSED_MATCH_REPLAY_CAP
            .checked_div(u32::from(depth))
            .filter(|capacity| *capacity >= GPU_FUSED_MATCH_CAP)
            .ok_or_else(|| {
                "GPU resident per-slot replay capacity is below the initial match capacity"
                    .to_string()
            })?;
        Ok(Self {
            depth,
            slot_input_capacity_bytes,
            slot_match_capacity,
        })
    }
}

struct GpuResidentLiteralSession {
    pipeline: Option<vyre::scan::ResidentFusedRegionScan>,
    input: Vec<u8>,
    region_starts: Vec<u32>,
    output: Vec<u32>,
    matches: Vec<vyre::scan::LiteralMatch>,
    scratch: Vec<u8>,
    in_flight: bool,
    device_bytes: u64,
}
impl GpuResidentLiteralSession {
    fn clear_host_buffers(&mut self) {
        self.input.zeroize();
        self.input.clear();
        self.region_starts.as_mut_slice().zeroize();
        self.region_starts.clear();
        GpuResidentLiteralState::zero_output_contents(&mut self.output);
        self.matches.clear();
        GpuResidentLiteralState::zero_scratch_allocation(&mut self.scratch);
    }
}

struct ZeroResidentSessionHostBuffers<'a>(&'a mut GpuResidentLiteralSession);

impl std::ops::Deref for ZeroResidentSessionHostBuffers<'_> {
    type Target = GpuResidentLiteralSession;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl std::ops::DerefMut for ZeroResidentSessionHostBuffers<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

impl Drop for ZeroResidentSessionHostBuffers<'_> {
    fn drop(&mut self) {
        self.0.clear_host_buffers();
    }
}

pub(crate) struct GpuResidentLiteralState {
    sessions: Vec<GpuResidentLiteralSession>,
    config: GpuResidentPipelineConfig,
    presence_words: usize,
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
    presence_words: usize,
    pipeline: GpuResidentPipelineConfig,
}

impl ResidentLiteralCapacity {
    fn for_batch(
        haystack_bytes: usize,
        region_count: usize,
        presence_words: usize,
        depth: u8,
    ) -> Result<Self, String> {
        if presence_words == 0 {
            return Err("GPU resident presence row must contain at least one word".to_string());
        }
        let pipeline = GpuResidentPipelineConfig::for_depth(depth)?;
        if haystack_bytes > pipeline.slot_input_capacity_bytes {
            return Err(format!(
                "GPU resident region-presence batch is {haystack_bytes} byte(s), above the depth-{depth} per-slot input ceiling of {} byte(s). Fix: split the request using the calibrated pipeline capacity.",
                pipeline.slot_input_capacity_bytes
            ));
        }
        if haystack_bytes > vyre::scan::dispatch_io::DEFAULT_MAX_SCAN_BYTES as usize {
            return Err(format!(
                "GPU resident region-presence batch is {haystack_bytes} byte(s), above VYRE's \
                 {}-byte scan ceiling. Fix: lower the GPU batch cap or split the request at \
                 chunk boundaries before dispatch.",
                vyre::scan::dispatch_io::DEFAULT_MAX_SCAN_BYTES
            ));
        }
        let required_haystack_bytes = haystack_bytes.max(4);
        let max_haystack_bytes = pipeline
            .slot_input_capacity_bytes
            .min(vyre::scan::dispatch_io::DEFAULT_MAX_SCAN_BYTES as usize);
        let growth_headroom = required_haystack_bytes / 4;
        let haystack_bytes = required_haystack_bytes
            .saturating_add(growth_headroom)
            .min(max_haystack_bytes);
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
        Self {
            required_haystack_bytes,
            haystack_bytes,
            regions,
            max_matches: GPU_FUSED_MATCH_CAP.min(pipeline.slot_match_capacity),
            presence_words,
            pipeline,
        }
        .validate_mutable_budget()
    }

    fn fits(self, state: &GpuResidentLiteralState) -> bool {
        let Some(pipeline) = state
            .sessions
            .first()
            .and_then(|session| session.pipeline.as_ref())
        else {
            return false;
        };
        state.config == self.pipeline
            && state.presence_words == self.presence_words
            && pipeline.haystack_capacity() >= self.required_haystack_bytes
            && pipeline.max_regions() >= self.regions
            && pipeline.max_matches() >= self.max_matches
    }

    fn preserving(self, state: Option<&GpuResidentLiteralState>) -> Result<Self, String> {
        let Some(pipeline) = state
            .filter(|state| {
                state.config == self.pipeline && state.presence_words == self.presence_words
            })
            .and_then(|state| state.sessions.first())
            .and_then(|session| session.pipeline.as_ref())
        else {
            return Ok(self);
        };
        Self {
            required_haystack_bytes: self.required_haystack_bytes,
            haystack_bytes: self.haystack_bytes.max(pipeline.haystack_capacity()),
            regions: self.regions.max(pipeline.max_regions()),
            max_matches: self.max_matches.max(pipeline.max_matches()),
            presence_words: self.presence_words,
            pipeline: self.pipeline,
        }
        .validate_mutable_budget()
    }

    fn with_max_matches(self, max_matches: u32) -> Result<Self, String> {
        if max_matches > self.pipeline.slot_match_capacity {
            return Err(format!(
                "exact GPU match count {max_matches} exceeds the depth-{} per-slot replay ceiling {}. Fix: split the GPU batch using the calibrated pipeline capacity.",
                self.pipeline.depth, self.pipeline.slot_match_capacity
            ));
        }
        Self {
            max_matches: self.max_matches.max(max_matches),
            ..self
        }
        .validate_mutable_budget()
    }

    fn mutable_device_bytes(self) -> Result<u64, String> {
        let haystack_bytes = self
            .haystack_bytes
            .checked_add(3)
            .map(|bytes| bytes & !3)
            .ok_or_else(|| "GPU resident padded haystack byte count overflowed".to_string())?;
        let presence_bytes = usize::try_from(self.regions)
            .ok()
            .and_then(|regions| regions.checked_mul(self.presence_words))
            .and_then(|words| words.checked_mul(std::mem::size_of::<u32>()))
            .ok_or_else(|| "GPU resident presence-buffer byte count overflowed".to_string())?;
        let region_bytes = usize::try_from(self.regions)
            .ok()
            .and_then(|regions| regions.checked_mul(std::mem::size_of::<u32>()))
            .ok_or_else(|| "GPU resident region-control byte count overflowed".to_string())?;
        let match_bytes = usize::try_from(self.max_matches)
            .ok()
            .and_then(|matches| matches.checked_mul(3 * std::mem::size_of::<u32>()))
            .ok_or_else(|| "GPU resident match-output byte count overflowed".to_string())?;
        haystack_bytes
            .checked_add(presence_bytes)
            .and_then(|bytes| bytes.checked_add(region_bytes))
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<u32>()))
            .and_then(|bytes| bytes.checked_add(match_bytes))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| "GPU resident mutable device byte count overflowed".to_string())
    }

    fn validate_mutable_budget(self) -> Result<Self, String> {
        let aggregate = self
            .mutable_device_bytes()?
            .checked_mul(u64::from(self.pipeline.depth))
            .ok_or_else(|| "GPU resident aggregate mutable byte count overflowed".to_string())?;
        let input_budget = u64::try_from(crate::gpu_input_budget::gpu_batch_input_limit())
            .map_err(|_| "GPU input budget exceeds u64".to_string())?;
        let replay_budget = u64::from(GPU_FUSED_MATCH_REPLAY_CAP)
            .checked_mul(3 * std::mem::size_of::<u32>() as u64)
            .ok_or_else(|| "GPU replay byte budget overflowed".to_string())?;
        // One input budget owns all slot haystacks. A second bounds presence
        // and region-control buffers; positioned output has its own fixed cap.
        let aggregate_ceiling = input_budget
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(replay_budget))
            .ok_or_else(|| "GPU resident aggregate mutable byte ceiling overflowed".to_string())?;
        if aggregate > aggregate_ceiling {
            return Err(format!(
                "GPU resident depth-{} mutable allocation is {aggregate} byte(s), above the {aggregate_ceiling}-byte aggregate ceiling. Fix: reduce the batch region count or recalibrate a shallower pipeline.",
                self.pipeline.depth
            ));
        }
        Ok(self)
    }
}

pub(crate) fn gpu_resident_literal_required_device_bytes(
    haystack_bytes: usize,
    region_count: usize,
    presence_words: usize,
    depth: u8,
) -> Result<u64, String> {
    ResidentLiteralCapacity::for_batch(haystack_bytes, region_count, presence_words, depth)?
        .mutable_device_bytes()?
        .checked_mul(u64::from(depth))
        .ok_or_else(|| "GPU resident per-device allocation overflows u64".to_string())
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
            session.clear_host_buffers();
        }
    }

    fn free(mut self) -> Result<(), String> {
        self.clear_host_buffers();
        let mut first_error = None;
        for mut session in self.sessions {
            let Some(pipeline) = session.pipeline.take() else {
                first_error.get_or_insert_with(|| {
                    "GPU resident literal session lost its pipeline before cleanup".to_string()
                });
                continue;
            };
            let device_bytes = session.device_bytes;
            match pipeline
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
    presence_words: usize,
    consume: impl FnOnce(&[u32], &[vyre::scan::LiteralMatch]) -> Result<R, String>,
) -> Result<R, String> {
    let needed = ResidentLiteralCapacity::for_batch(
        haystack.len(),
        region_starts.len(),
        presence_words,
        GPU_RESIDENT_PIPELINE_MIN_DEPTH,
    )?;
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
        })?;
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
            let pipeline = session.pipeline.as_mut().ok_or_else(|| {
                "GPU resident literal session lost its pipeline before dispatch".to_string()
            })?;
            if crate::engine::profile::diagnostic() {
                eprintln!(
                    "perf-trace gpu-resident-fused: action={} backend={} haystack_capacity={} region_capacity={} match_capacity={} host_output_capacity={} host_match_capacity={} host_scratch_capacity={}",
                    if must_rebuild || attempt > 0 { "prepare" } else { "reuse" },
                    backend.id(),
                    pipeline.haystack_capacity(),
                    pipeline.max_regions(),
                    pipeline.max_matches(),
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
                    pipeline
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
                    pipeline
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
            GpuResidentLiteralSlot::Ready(state) => state.sessions[0]
                .pipeline
                .as_ref()
                .map_or(0, vyre::scan::ResidentFusedRegionScan::max_matches),
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
            .with_max_matches(exact_count)?
            .preserving(match &*slot {
                GpuResidentLiteralSlot::Ready(state) => Some(state),
                GpuResidentLiteralSlot::Empty
                | GpuResidentLiteralSlot::Borrowed(_)
                | GpuResidentLiteralSlot::Failed(_) => None,
            })?;
        evidence::record_retry(1);
        rebuild_resident_literal_state(&mut slot, matcher, backend, capacity)?;
    }
    Err("GPU resident literal scan exhausted its bounded replay".to_string())
}
#[must_use = "pending GPU resident evidence must be retired before its IO slot can be reused"]
pub(crate) struct PendingGpuResidentLiteralEvidence<'a> {
    slot: &'a std::sync::Mutex<GpuResidentLiteralSlot>,
    matcher: &'a vyre::scan::GpuLiteralSet,
    session_index: usize,
    backend_code: u64,
    pending: Option<vyre::scan::PendingResidentFusedRegion>,
    submitted_at: std::time::Instant,
}

impl PendingGpuResidentLiteralEvidence<'_> {
    fn is_ready(&self) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|pending| pending.is_ready())
    }
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
                        session.clear_host_buffers();
                    }
                }
            }
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

/// Bounded resident dispatch ring. Ready fences may retire out of submission
/// order; metadata identifies the logical source rows consumed by each result.
pub(crate) struct GpuResidentLiteralOverlap<'a, M> {
    pending: Vec<(PendingGpuResidentLiteralEvidence<'a>, M)>,
    depth: u8,
    presence_words: usize,
}

impl<M> GpuResidentLiteralOverlap<'_, M> {
    pub(crate) fn new(depth: u8, presence_words: usize) -> Result<Self, String> {
        GpuResidentPipelineConfig::for_depth(depth)?;
        if presence_words == 0 {
            return Err("GPU resident presence row must contain at least one word".to_string());
        }
        Ok(Self {
            pending: Vec::with_capacity(usize::from(depth)),
            depth,
            presence_words,
        })
    }
}

impl<'a, M: Clone> GpuResidentLiteralOverlap<'a, M> {
    fn retire_one(
        &mut self,
        backend: &std::sync::Arc<dyn vyre::VyreBackend>,
        consume: &mut impl FnMut(M, &[u32], &[vyre::scan::LiteralMatch]) -> Result<(), String>,
        recover: &mut impl FnMut(&M, String) -> Result<(), String>,
    ) -> Result<(), String> {
        let index = self
            .pending
            .iter()
            .position(|(pending, _)| pending.is_ready())
            .unwrap_or(0);
        let (pending, metadata) = self.pending.swap_remove(index);
        match finish_gpu_literal_evidence_by_region_resident(
            pending,
            backend,
            |presence, matches| consume(metadata.clone(), presence, matches),
        ) {
            Ok(()) => Ok(()),
            Err(error) => recover(&metadata, error),
        }
    }

    fn retire_all(
        &mut self,
        backend: &std::sync::Arc<dyn vyre::VyreBackend>,
        consume: &mut impl FnMut(M, &[u32], &[vyre::scan::LiteralMatch]) -> Result<(), String>,
        recover: &mut impl FnMut(&M, String) -> Result<(), String>,
    ) -> Result<(), String> {
        while !self.pending.is_empty() {
            self.retire_one(backend, consume, recover)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch(
        &mut self,
        slot: &'a std::sync::Mutex<GpuResidentLiteralSlot>,
        matcher: &'a vyre::scan::GpuLiteralSet,
        backend: &std::sync::Arc<dyn vyre::VyreBackend>,
        haystack: &[u8],
        region_starts: &[u32],
        metadata: M,
        flush: bool,
        mut consume: impl FnMut(M, &[u32], &[vyre::scan::LiteralMatch]) -> Result<(), String>,
        mut recover: impl FnMut(&M, String) -> Result<(), String>,
    ) -> Result<(), String> {
        if !self.pending.is_empty()
            && !gpu_resident_literal_capacity_fits(
                slot,
                backend,
                haystack.len(),
                region_starts.len(),
                self.presence_words,
                self.depth,
            )?
        {
            self.retire_all(backend, &mut consume, &mut recover)?;
        }

        let current = match submit_gpu_literal_evidence_by_region_resident(
            slot,
            matcher,
            backend,
            haystack,
            region_starts,
            self.presence_words,
            self.depth,
        ) {
            Ok(pending) => pending,
            Err(error) => {
                self.retire_all(backend, &mut consume, &mut recover)?;
                return recover(&metadata, error);
            }
        };
        if self.pending.len() >= usize::from(self.depth) {
            return Err(
                "GPU resident dispatch ring exceeded its calibrated slot bound".to_string(),
            );
        }
        self.pending.push((current, metadata));
        if self.pending.len() == usize::from(self.depth) {
            self.retire_one(backend, &mut consume, &mut recover)?;
        }
        if flush {
            self.retire_all(backend, &mut consume, &mut recover)?;
        }
        Ok(())
    }
}
pub(crate) fn gpu_resident_literal_capacity_fits(
    slot: &std::sync::Mutex<GpuResidentLiteralSlot>,
    backend: &std::sync::Arc<dyn vyre::VyreBackend>,
    haystack_bytes: usize,
    region_count: usize,
    presence_words: usize,
    depth: u8,
) -> Result<bool, String> {
    let needed =
        ResidentLiteralCapacity::for_batch(haystack_bytes, region_count, presence_words, depth)?;
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
    matcher: &'a vyre::scan::GpuLiteralSet,
    backend: &std::sync::Arc<dyn vyre::VyreBackend>,
    haystack: &[u8],
    region_starts: &[u32],
    presence_words: usize,
    depth: u8,
) -> Result<PendingGpuResidentLiteralEvidence<'a>, String> {
    let needed = ResidentLiteralCapacity::for_batch(
        haystack.len(),
        region_starts.len(),
        presence_words,
        depth,
    )?;
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
        })?;
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
            format!(
                "all {} GPU resident literal IO slots are in flight. Fix: retire a pending batch before submitting another.",
                state.config.depth
            )
        })?;
    let session = &mut state.sessions[session_index];
    GpuResidentLiteralState::zero_output_contents(&mut session.output);
    session.matches.clear();
    GpuResidentLiteralState::zero_scratch_allocation(&mut session.scratch);
    session.input.zeroize();
    session.input.clear();
    session.region_starts.as_mut_slice().zeroize();
    session.region_starts.clear();
    session
        .input
        .try_reserve_exact(haystack.len())
        .map_err(|error| format!("GPU resident slot input reserve failed: {error}"))?;
    session
        .region_starts
        .try_reserve_exact(region_starts.len())
        .map_err(|error| format!("GPU resident slot region-start reserve failed: {error}"))?;
    session.input.extend_from_slice(haystack);
    session.region_starts.extend_from_slice(region_starts);
    #[cfg(test)]
    if injected_dispatch_failure() {
        evidence::record_fault(
            evidence::backend_code(backend.id()),
            evidence::fault::DISPATCH,
        );
        session.clear_host_buffers();
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
    let pipeline = match session.pipeline.as_mut() {
        Some(pipeline) => pipeline,
        None => {
            session.clear_host_buffers();
            return Err(
                "GPU resident literal session lost its pipeline before submission".to_string(),
            );
        }
    };
    let submission = pipeline.scan_async(
        backend.as_ref(),
        session.input.as_slice(),
        session.region_starts.as_slice(),
        0,
        &mut session.scratch,
    );
    GpuResidentLiteralState::zero_scratch_allocation(&mut session.scratch);
    let pending = match submission {
        Ok(pending) => pending,
        Err(error) => {
            evidence::record_fault(
                evidence::backend_code(backend.id()),
                evidence::fault::DISPATCH,
            );
            session.clear_host_buffers();
            return Err(format!("resident fused literal submission error: {error}"));
        }
    };
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
        matcher,
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
    let slot_match_capacity = state.config.slot_match_capacity;
    let session = state
        .sessions
        .get_mut(pending.session_index)
        .ok_or_else(|| "GPU resident pending IO slot index is out of range".to_string())?;
    let mut session_guard = ZeroResidentSessionHostBuffers(session);
    let session = &mut *session_guard;
    if !session.in_flight {
        return Err("GPU resident pending IO slot was already retired".to_string());
    }
    let mut dispatch = pending
        .pending
        .take()
        .ok_or_else(|| "GPU resident pending dispatch was already consumed".to_string())?;
    let mut submitted_at = pending.submitted_at;
    let mut consume = Some(consume);

    for attempt in 0..2 {
        let timing = dispatch
            .await_into_timed(&mut session.output, &mut session.matches)
            .map_err(|error| format!("resident fused literal dispatch error: {error}"));
        session.in_flight = false;
        let complete_ns = u64::try_from(submitted_at.elapsed().as_nanos())
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
                let output_bytes = u64::try_from(session.output.len())
                    .ok()
                    .and_then(|words| words.checked_mul(4))
                    .and_then(|bytes| {
                        u64::try_from(session.matches.len())
                            .ok()
                            .and_then(|matches| matches.checked_mul(12))
                            .and_then(|match_bytes| bytes.checked_add(match_bytes))
                    })
                    .ok_or_else(|| {
                        "GPU resident readback byte accounting exceeds u64".to_string()
                    })?;
                evidence::record_readback(output_bytes, None);
                let consumer = consume.take().ok_or_else(|| {
                    "GPU resident literal output consumer was already invoked".to_string()
                })?;
                let result = consumer(session.output.as_slice(), session.matches.as_slice());
                session.input.zeroize();
                session.input.clear();
                session.region_starts.as_mut_slice().zeroize();
                session.region_starts.clear();
                GpuResidentLiteralState::zero_output_contents(&mut session.output);
                session.matches.clear();
                GpuResidentLiteralState::zero_scratch_allocation(&mut session.scratch);
                return result;
            }
            Err(scan_error) => {
                evidence::record_fault(
                    evidence::backend_code(backend.id()),
                    evidence::fault::DISPATCH,
                );
                GpuResidentLiteralState::zero_output_contents(&mut session.output);
                session.matches.clear();
                if attempt == 1 {
                    session.input.zeroize();
                    session.input.clear();
                    session.region_starts.as_mut_slice().zeroize();
                    session.region_starts.clear();
                    GpuResidentLiteralState::zero_scratch_allocation(&mut session.scratch);
                    return Err(scan_error);
                }

                let exact_count = pending
                    .matcher
                    .count(backend.as_ref(), session.input.as_slice())
                    .map_err(|count_error| {
                        format!(
                            "{scan_error}; exact GPU match-count diagnosis also failed: {count_error}"
                        )
                    })?;
                let pipeline = session.pipeline.as_ref().ok_or_else(|| {
                    "GPU resident literal session lost its pipeline during retirement".to_string()
                })?;
                let current_capacity = pipeline.max_matches();
                if exact_count <= current_capacity {
                    session.input.zeroize();
                    session.input.clear();
                    session.region_starts.as_mut_slice().zeroize();
                    session.region_starts.clear();
                    return Err(scan_error);
                }
                if exact_count > slot_match_capacity {
                    session.input.zeroize();
                    session.input.clear();
                    session.region_starts.as_mut_slice().zeroize();
                    session.region_starts.clear();
                    return Err(format!(
                        "{scan_error}; exact GPU match count {exact_count} exceeds the calibrated per-slot replay ceiling {slot_match_capacity}"
                    ));
                }
                let haystack_capacity = pipeline.haystack_capacity();
                let max_regions = pipeline.max_regions();
                let old_pipeline = session.pipeline.take().ok_or_else(|| {
                    "GPU resident literal session lost its pipeline before dense replay".to_string()
                })?;
                old_pipeline.free(backend.as_ref()).map_err(|error| {
                    format!(
                        "{scan_error}; failed to free the overflowed resident slot before replay: {error}"
                    )
                })?;
                evidence::note_device_free(session.device_bytes);
                let replay_pipeline = pending
                    .matcher
                    .prepare_resident_fused_scan(
                        backend.as_ref(),
                        haystack_capacity,
                        max_regions,
                        exact_count,
                    )
                    .map_err(|error| {
                        session.input.zeroize();
                        session.input.clear();
                        session.region_starts.as_mut_slice().zeroize();
                        session.region_starts.clear();
                        format!(
                            "{scan_error}; failed to rebuild the resident slot for exact dense replay at {exact_count} matches: {error}"
                        )
                    })?;
                let added_match_bytes = u64::from(exact_count - current_capacity)
                    .checked_mul(12)
                    .ok_or_else(|| {
                    "GPU resident replay device byte accounting overflowed".to_string()
                })?;
                session.device_bytes = session
                    .device_bytes
                    .checked_add(added_match_bytes)
                    .ok_or_else(|| {
                        "GPU resident replay aggregate byte accounting overflowed".to_string()
                    })?;
                evidence::note_device_alloc(session.device_bytes);
                session.pipeline = Some(replay_pipeline);
                let GpuResidentLiteralSession {
                    pipeline,
                    input,
                    region_starts,
                    scratch,
                    ..
                } = session;
                let replay = pipeline
                    .as_mut()
                    .ok_or_else(|| {
                        "GPU resident replay pipeline disappeared before submission".to_string()
                    })?
                    .scan_async(
                        backend.as_ref(),
                        input.as_slice(),
                        region_starts.as_slice(),
                        0,
                        scratch,
                    );
                GpuResidentLiteralState::zero_scratch_allocation(scratch);
                dispatch = replay.map_err(|error| {
                    format!("resident fused literal dense-replay submission error: {error}")
                })?;
                session.in_flight = true;
                submitted_at = std::time::Instant::now();
                evidence::record_retry(1);
                evidence::record_dispatch_submitted();
            }
        }
    }
    unreachable!("bounded resident dense replay loop returns from both attempts")
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

    let mut sessions = Vec::new();
    sessions
        .try_reserve_exact(usize::from(capacity.pipeline.depth))
        .map_err(|error| format!("failed to reserve bounded GPU resident slot ring: {error}"))?;
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
    let device_bytes = capacity.mutable_device_bytes()?;
    let new_session = |pipeline| GpuResidentLiteralSession {
        pipeline: Some(pipeline),
        input: Vec::new(),
        region_starts: Vec::new(),
        output: Vec::new(),
        matches: Vec::new(),
        scratch: Vec::new(),
        in_flight: false,
        device_bytes,
    };
    sessions.push(new_session(pipeline));
    while sessions.len() < usize::from(capacity.pipeline.depth) {
        let fork = sessions[0]
            .pipeline
            .as_ref()
            .ok_or_else(|| "prepared GPU resident primary slot lost its pipeline".to_string())?
            .fork_independent(backend.as_ref())
            .map_err(|error| {
                format!(
                    "failed to prepare GPU resident literal IO slot {} of {}: {error}",
                    sessions.len() + 1,
                    capacity.pipeline.depth
                )
            });
        match fork {
            Ok(pipeline) => sessions.push(new_session(pipeline)),
            Err(preparation_error) => {
                let mut cleanup_errors = Vec::new();
                for mut session in sessions {
                    if let Some(pipeline) = session.pipeline.take() {
                        if let Err(error) = pipeline.free(backend.as_ref()) {
                            cleanup_errors.push(error.to_string());
                        }
                    }
                }
                let error = if cleanup_errors.is_empty() {
                    preparation_error
                } else {
                    format!(
                        "{preparation_error}; prepared slot cleanup failed: {}",
                        cleanup_errors.join("; ")
                    )
                };
                *slot = GpuResidentLiteralSlot::Failed(error.clone());
                return Err(error);
            }
        }
    }
    let aggregate_device_bytes = device_bytes
        .checked_mul(u64::from(capacity.pipeline.depth))
        .ok_or_else(|| "GPU resident aggregate device byte accounting overflowed".to_string())?;
    *slot = GpuResidentLiteralSlot::Ready(GpuResidentLiteralState {
        sessions,
        config: capacity.pipeline,
        presence_words: capacity.presence_words,
        backend: std::sync::Arc::clone(backend),
    });
    evidence::note_device_alloc(aggregate_device_bytes);
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
                resident_literal_metal,
                resident_literal_wgpu,
                ..
            } => &[
                ("cuda", resident_literal_cuda),
                ("metal", resident_literal_metal),
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

    /// Report the real selected VYRE submit/retire capability. Deeper routes
    /// are eligible only when the backend advertises asynchronous compute.
    pub fn gpu_resident_dispatch_capability(
        &self,
        backend: crate::hw_probe::ScanBackend,
    ) -> std::result::Result<&'static str, String> {
        let selected = self
            .gpu_backend(backend)
            .ok_or_else(|| self.gpu_backend_unavailable_reason(backend))?;
        let capability = if selected.supports_async_compute() {
            GpuResidentDispatchCapability::AsyncSubmitRetire
        } else if self
            .backend_state
            .gpu_resident_timed_dispatch_supported(backend)
        {
            GpuResidentDispatchCapability::TimedResident
        } else {
            GpuResidentDispatchCapability::Synchronous
        };
        Ok(capability.label())
    }

    pub fn eligible_gpu_resident_pipeline_depths(
        &self,
        backend: crate::hw_probe::ScanBackend,
    ) -> std::result::Result<Vec<u8>, String> {
        match self.gpu_resident_dispatch_capability(backend)? {
            "async-submit-retire" => {
                Ok((GPU_RESIDENT_PIPELINE_MIN_DEPTH..=GPU_RESIDENT_PIPELINE_MAX_DEPTH).collect())
            }
            "synchronous" | "timed-resident" => Ok(vec![GPU_RESIDENT_PIPELINE_MIN_DEPTH]),
            capability => Err(format!(
                "selected GPU backend reported unknown resident dispatch capability {capability:?}"
            )),
        }
    }

    pub fn gpu_resident_pipeline_slot_capacities(
        &self,
        depth: u8,
    ) -> std::result::Result<(usize, u32), String> {
        let config = GpuResidentPipelineConfig::for_depth(depth)?;
        Ok((config.slot_input_capacity_bytes, config.slot_match_capacity))
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
