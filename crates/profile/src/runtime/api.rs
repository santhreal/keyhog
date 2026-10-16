//! Thread-local runtime context guards, span guards, and public profiling entry points.

use std::future::{poll_fn, Future};
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use crate::schema::Stage;
use crate::schema_v2::{Evidence, EvidenceGap, MetricDistributionV2, TypedMetricRecordV2, WorkOrigin};
use super::shard::{SpanOutcome, SpanTrace, WorkerShard};
use super::{
    ACTIVE_CONTEXTS, ASYNC_PARENT_SPANS, CURRENT, LEGACY, NUMERIC_THREAD_ID,
    PROCESS_ACTIVE_COMPILE_PHASE, SPAN_DEPTH, TASK_ID, WORK_ORIGIN,
    CausalParent, Runtime, SamplingPolicy,
};

pub struct ContextGuard {
    pub(super) runtime: Runtime,
    pub(super) not_send: PhantomData<Rc<()>>,
}

impl Drop for ContextGuard {
    fn drop(&mut self) {
        CURRENT.with(|stack| {
            let mut stack = stack.borrow_mut();
            if stack
                .last()
                .is_some_and(|runtime| Arc::ptr_eq(&runtime.inner, &self.runtime.inner))
            {
                stack.pop();
            } else if let Some(position) = stack
                .iter()
                .rposition(|runtime| Arc::ptr_eq(&runtime.inner, &self.runtime.inner))
            {
                stack.remove(position);
            }
        });
        ACTIVE_CONTEXTS.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(super) struct AsyncParentGuard {
    pub(super) runtime_key: usize,
    pub(super) span_id: u64,
    pub(super) stack_slot: usize,
    pub(super) not_send: PhantomData<Rc<()>>,
}

impl Drop for AsyncParentGuard {
    fn drop(&mut self) {
        ASYNC_PARENT_SPANS.with(|stack| {
            let mut stack = stack.borrow_mut();
            if stack[self.stack_slot].is_some_and(|active| {
                active.runtime_key == self.runtime_key && active.span_id == self.span_id
            }) {
                stack[self.stack_slot] = None;
            }
        });
    }
}

struct WorkOriginGuard {
    previous: WorkOrigin,
}

impl WorkOriginGuard {
    fn enter(origin: WorkOrigin) -> Self {
        Self {
            previous: WORK_ORIGIN.with(|slot| slot.replace(origin)),
        }
    }
}

impl Drop for WorkOriginGuard {
    fn drop(&mut self) {
        WORK_ORIGIN.with(|slot| slot.set(self.previous));
    }
}

struct TaskGuard {
    previous: u64,
}

impl TaskGuard {
    fn enter(task_id: u64) -> Self {
        Self {
            previous: TASK_ID.with(|slot| slot.replace(task_id)),
        }
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        TASK_ID.with(|slot| slot.set(self.previous));
    }
}

pub(super) struct LegacyRuntime {
    pub(super) runtime: Runtime,
    pub(super) enabled: bool,
}

impl LegacyRuntime {
    pub(super) fn new() -> Self {
        Self {
            runtime: Runtime::legacy(),
            enabled: false,
        }
    }
}

/// Optional attribution for work performed inside a derived input.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum Attribution {
    #[default]
    Root = 0,
    Decoded = 1,
}

impl From<Attribution> for WorkOrigin {
    fn from(attribution: Attribution) -> Self {
        match attribution {
            Attribution::Root => Self::Root,
            Attribution::Decoded => Self::Decoded,
        }
    }
}

pub(super) fn numeric_thread_id() -> u64 {
    NUMERIC_THREAD_ID.with(|thread_id| *thread_id)
}

/// Return a clone of the runtime current on this thread.
pub fn current_runtime() -> Option<Runtime> {
    if ACTIVE_CONTEXTS.load(Ordering::Relaxed) == 0 {
        return None;
    }
    CURRENT
        .with(|stack| stack.borrow().last().cloned())
        .or_else(|| {
            LEGACY.with(|legacy| {
                let legacy = legacy.borrow();
                legacy.enabled.then(|| legacy.runtime.clone())
            })
        })
}

pub(crate) fn runtime_for_drain() -> Runtime {
    CURRENT
        .with(|stack| stack.borrow().last().cloned())
        .unwrap_or_else(|| LEGACY.with(|legacy| legacy.borrow().runtime.clone()))
}

/// Replace this thread's attribution and return its previous value.
///
/// Legacy projection of [`set_work_origin`]: the returned value is `Decoded`
/// whenever the previous origin was any attributed (non-root) work.
pub fn set_attribution(attribution: Attribution) -> Attribution {
    let previous = set_work_origin(attribution.into());
    if previous.is_attributed_work() {
        Attribution::Decoded
    } else {
        Attribution::Root
    }
}

/// Replace this thread's causal work origin and return its previous value.
pub fn set_work_origin(origin: WorkOrigin) -> WorkOrigin {
    WORK_ORIGIN.with(|slot| slot.replace(origin))
}

/// Current thread's causal work origin.
pub fn current_work_origin() -> WorkOrigin {
    WORK_ORIGIN.with(|slot| slot.get())
}

/// Replace this thread's caller-assigned task identity and return the previous.
///
/// Zero clears the identity. The value is a caller-managed task or name index;
/// [`instrument_future`] propagates it across polls and worker threads.
pub fn set_task_id(task_id: u64) -> u64 {
    TASK_ID.with(|slot| slot.replace(task_id))
}

/// Current thread's caller-assigned task identity, or zero when unset.
pub fn current_task_id() -> u64 {
    TASK_ID.with(|slot| slot.get())
}

pub(super) fn evidence_or_unavailable(value: u64) -> Evidence<u64> {
    if value == 0 {
        Evidence::unavailable(EvidenceGap::Unavailable)
    } else {
        Evidence::recorded(value)
    }
}

/// Capture a portable token naming the current runtime's causal parent.
///
/// Returns `None` when no runtime is current on this thread.
pub fn current_causal_parent() -> Option<CausalParent> {
    current_runtime().map(|runtime| runtime.causal_parent())
}

/// Return whether fixed-stage profiling is active on the calling thread.
#[inline]
pub fn enabled() -> bool {
    if ACTIVE_CONTEXTS.load(Ordering::Relaxed) == 0 {
        return false;
    }
    CURRENT.with(|stack| !stack.borrow().is_empty())
        || LEGACY.with(|legacy| legacy.borrow().enabled)
}

/// Enable or disable the calling thread's standalone profiling runtime.
///
/// Prefer [`crate::Session::start`] for operator runs because it also captures
/// identity, resources, and state transitions. This switch remains available
/// to libraries and microbenchmarks that only need stage counters.
pub fn set_enabled(enabled: bool) {
    LEGACY.with(|legacy| {
        let mut legacy = legacy.borrow_mut();
        if legacy.enabled == enabled {
            return;
        }
        legacy.enabled = enabled;
        if enabled {
            ACTIVE_CONTEXTS.fetch_add(1, Ordering::Relaxed);
        } else {
            ACTIVE_CONTEXTS.fetch_sub(1, Ordering::Relaxed);
        }
    });
}

struct AsyncSpan {
    runtime: Option<Runtime>,
    shard: Option<Arc<WorkerShard>>,
    stage: Stage,
    started: Option<Instant>,
    trace: Option<SpanTrace>,
}

impl Drop for AsyncSpan {
    fn drop(&mut self) {
        let (Some(runtime), Some(started)) = (&self.runtime, self.started) else {
            return;
        };
        let elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        runtime.record(
            self.shard.as_deref(),
            self.stage,
            SpanOutcome {
                start_offset_ns: runtime.offset_ns(started),
                elapsed_ns,
                self_ns: 0,
                blocked: false,
                serial: false,
                // An async span can be polled on any thread, so it never
                // owns a worker's outermost interval.
                outermost: false,
            },
        );
        if let Some(trace) = self.trace {
            runtime.finish_span(trace, elapsed_ns);
        }
    }
}

fn instrument_impl<F>(
    stage: Stage,
    future: F,
    parent_override: Option<CausalParent>,
) -> impl Future<Output = F::Output>
where
    F: Future,
{
    let runtime = current_runtime();
    let shard = runtime.as_ref().and_then(Runtime::worker_shard);
    let worker_id = shard.as_ref().map_or(0, |shard| shard.sequence);
    let started = runtime.as_ref().map(|_| Instant::now());
    let parent_span_id = match (runtime.as_ref(), parent_override) {
        (Some(runtime), Some(parent)) if runtime.context_id() == parent.context_id() => {
            parent.span_id()
        }
        (Some(_), Some(_)) => 0,
        (Some(runtime), None) => runtime.current_parent_span_id(),
        (None, _) => 0,
    };
    let trace = runtime
        .as_ref()
        .zip(started)
        .and_then(|(runtime, started)| {
            runtime.begin_async_span(stage, started, parent_span_id, worker_id)
        });
    let span_id = trace.map(|trace| trace.span_id);
    let origin = current_work_origin();
    let task_id = current_task_id();
    let poll_runtime = runtime.clone();

    async move {
        let _span = AsyncSpan {
            runtime,
            shard,
            stage,
            started,
            trace,
        };
        let mut future = std::pin::pin!(future);
        poll_fn(|context| {
            let _context_guard = poll_runtime.as_ref().map(Runtime::enter);
            let _parent_guard = poll_runtime
                .as_ref()
                .zip(span_id)
                .and_then(|(runtime, span_id)| runtime.enter_async_parent(span_id));
            let _origin_guard = WorkOriginGuard::enter(origin);
            let _task_guard = TaskGuard::enter(task_id);
            if span_id.is_some() {
                crate::allocation::stage_context_push(stage);
            }
            let result = future.as_mut().poll(context);
            if span_id.is_some() {
                crate::allocation::stage_context_pop();
            }
            result
        })
        .await
    }
}

/// Propagate the current runtime and causal parent while polling one future.
///
/// The returned future records one wall-time span from wrapper construction
/// through completion or cancellation. Runtime and parent guards exist only
/// during each poll, so the returned future remains `Send` when `F` is `Send`.
pub fn instrument_future<F>(stage: Stage, future: F) -> impl Future<Output = F::Output>
where
    F: Future,
{
    instrument_impl(stage, future, None)
}

/// Propagate the current runtime with an explicit portable causal parent.
///
/// Use this when the future crosses a spawn boundary where thread-local
/// parentage cannot reach. A token captured from another runtime records the
/// future's span as a root of the current runtime instead.
pub fn instrument_future_with_parent<F>(
    parent: CausalParent,
    stage: Stage,
    future: F,
) -> impl Future<Output = F::Output>
where
    F: Future,
{
    instrument_impl(stage, future, Some(parent))
}

/// Allocation-free stage guard. It contains no start timestamp while disabled.
#[must_use]
pub struct Span {
    runtime: Option<Runtime>,
    shard: Option<Arc<WorkerShard>>,
    stage: Stage,
    started: Option<Instant>,
    trace: Option<SpanTrace>,
    stack_slot: Option<usize>,
    span_id: u64,
    blocked: bool,
    serial: bool,
}

impl Span {
    /// Whether this span reads and will record a clock measurement.
    pub fn is_recording(&self) -> bool {
        self.started.is_some()
    }
}

fn span_impl(
    stage: Stage,
    parent_override: Option<CausalParent>,
    blocked: bool,
    serial: bool,
) -> Span {
    if ACTIVE_CONTEXTS.load(Ordering::Relaxed) == 0 {
        return Span {
            runtime: None,
            shard: None,
            stage,
            started: None,
            trace: None,
            stack_slot: None,
            span_id: 0,
            blocked: false,
            serial: false,
        };
    }
    let runtime = current_runtime();
    let shard = runtime.as_ref().and_then(Runtime::worker_shard);
    let worker_id = shard.as_ref().map_or(0, |shard| shard.sequence);
    let started = runtime.as_ref().map(|_| Instant::now());
    if started.is_some() {
        SPAN_DEPTH.with(|depth| depth.set(depth.get() + 1));
    }
    let (trace, stack_slot, span_id) = match (runtime.as_ref(), started) {
        (Some(runtime), Some(started)) => {
            let (parent_slot, current_parent_id) = runtime.current_parent();
            let parent_span_id = match parent_override {
                Some(parent) if runtime.context_id() == parent.context_id() => parent.span_id(),
                _ => current_parent_id,
            };
            runtime.begin_span_with(stage, started, parent_span_id, parent_slot, worker_id)
        }
        _ => (None, None, 0),
    };
    if trace.is_some() {
        crate::allocation::stage_context_push(stage);
    }
    Span {
        runtime,
        shard,
        stage,
        started,
        trace,
        stack_slot,
        span_id,
        blocked,
        serial,
    }
}

/// Start one fixed-stage measurement.
#[inline]
pub fn span(stage: Stage) -> Span {
    span_impl(stage, None, false, false)
}

/// Start one fixed-stage measurement with an explicit portable causal parent.
///
/// The token replaces thread-local parent lookup, so the caller can carry
/// parentage across crate, thread, or spawn boundaries. A token captured from
/// another runtime records this span as a root of the current runtime.
pub fn span_with_parent(parent: CausalParent, stage: Stage) -> Span {
    span_impl(stage, Some(parent), false, false)
}

/// Declare that this region runs with the worker pool idle.
///
/// Use it for barriers such as enumeration, plan compilation, or final merge,
/// where no other worker can make progress. The guard measures wall time like
/// [`span`] and additionally accumulates declared-serial time, which the
/// profiler reports as the Amdahl floor on any speedup from more threads.
/// The profiler also derives serial phases from observed concurrency, so a
/// region left undeclared is still detected; declaring it makes the report
/// state the intent rather than infer it.
pub fn serial_span(stage: Stage) -> Span {
    span_impl(stage, None, false, true)
}

/// Record one blocked wait interval separately from runnable execution.
///
/// The guard measures wall time like [`span`] but additionally accumulates
/// per-stage blocked time drained by `Runtime::take_session_blocked_waits`,
/// and it never counts as attributed (decoded or derived) execution. Reuse
/// wait stages such as [`Stage::SourceQueueWait`] and [`Stage::ScannerQueueWait`].
pub fn blocked(stage: Stage) -> Span {
    span_impl(stage, None, true, false)
}

/// Time a region whose measurement drives a decision, profiled or not.
///
/// [`span`] deliberately measures nothing while profiling is off, which is
/// right for reporting and wrong for a measurement the product acts on. A
/// timer whose value picks a backend must produce the same value whether or
/// not an operator passed `--profile`, or the flag would change routing.
///
/// This guard therefore reads the clock unconditionally, returns the elapsed
/// duration to the caller, and additionally records it as a [`span`] would
/// when a runtime is current. The name says "decision" so a reader knows at
/// the call site that it costs a clock read even when profiling is off. On a
/// hot path where nothing acts on the value, use [`span`].
#[must_use = "a decision timer only measures when finished"]
pub struct DecisionTimer {
    stage: Stage,
    started: Instant,
}

/// Start a decision-driving measurement of one micro-function.
pub fn decision_timer(stage: Stage) -> DecisionTimer {
    DecisionTimer {
        stage,
        started: Instant::now(),
    }
}

impl DecisionTimer {
    /// Stop the timer, record it when profiling is on, and return the elapsed time.
    pub fn finish(self) -> std::time::Duration {
        let elapsed = self.started.elapsed();
        if ACTIVE_CONTEXTS.load(Ordering::Relaxed) != 0 {
            if let Some(runtime) = current_runtime() {
                let shard = runtime.worker_shard();
                runtime.record(
                    shard.as_deref(),
                    self.stage,
                    SpanOutcome {
                        start_offset_ns: runtime.offset_ns(self.started),
                        elapsed_ns: u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
                        self_ns: 0,
                        blocked: false,
                        serial: false,
                        // The caller owns the enclosing span, if any; a decision
                        // timer never claims a worker's outermost interval.
                        outermost: false,
                    },
                );
            }
        }
        elapsed
    }
}

impl Drop for Span {
    #[inline]
    fn drop(&mut self) {
        let (Some(runtime), Some(started)) = (&self.runtime, self.started) else {
            return;
        };
        let outermost = SPAN_DEPTH.with(|depth| {
            let next = depth.get().saturating_sub(1);
            depth.set(next);
            next == 0
        });
        let elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let self_ns = runtime.pop_active_span(self.stack_slot, self.span_id, elapsed_ns);
        runtime.record(
            self.shard.as_deref(),
            self.stage,
            SpanOutcome {
                start_offset_ns: runtime.offset_ns(started),
                elapsed_ns,
                self_ns,
                blocked: self.blocked,
                serial: self.serial,
                outermost,
            },
        );
        if let Some(trace) = self.trace {
            runtime.finish_span(trace, elapsed_ns);
            crate::allocation::stage_context_pop();
        }
    }
}

/// Time a sub-stage region into a [`crate::CounterId`] instead of a stage.
///
/// Some measurements sit strictly inside a stage leaf. Recording them as
/// spans would add their time to that leaf's inclusive total a second time,
/// so they belong in a counter. This guard is [`span`] with a counter sink:
/// same enabled gate, same clock, no allocation on drop.
#[must_use = "a counter span measures nothing until it is dropped"]
pub struct CounterSpan {
    counter: crate::CounterId,
    started: Option<Instant>,
}

/// Start a sub-stage measurement that accumulates into one counter.
#[inline]
pub fn counter_span(counter: crate::CounterId) -> CounterSpan {
    CounterSpan {
        counter,
        started: (ACTIVE_CONTEXTS.load(Ordering::Relaxed) != 0).then(Instant::now),
    }
}

impl Drop for CounterSpan {
    #[inline]
    fn drop(&mut self) {
        let Some(started) = self.started else {
            return;
        };
        add_counter(
            self.counter,
            u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
        );
    }
}

/// Count one retry attempt, whether or not the retry eventually succeeded.
///
/// Count every attempt, not every operation: a path that retries a thousand
/// times must read as a thousand. The profiler reports retries as a finding
/// because a retry that fires means a failure the product did not design out.
#[inline]
pub fn record_retry(cause: crate::RetryCause) {
    if let Some(runtime) = current_runtime() {
        runtime.record_retry(cause);
    }
}

/// Add to one slot of an indexed counter family.
///
/// A slot at or beyond [`crate::INDEXED_COUNTER_SLOTS`] is counted as dropped
/// on the drained record rather than folded into another slot.
#[inline]
pub fn add_indexed_counter(counter: crate::IndexedCounterId, slot: u16, delta: u64) {
    if let Some(runtime) = current_runtime() {
        runtime.add_indexed_counter(counter, slot, delta);
    }
}

/// Attribute bytes to one micro-function so its throughput can be reported.
///
/// Record the bytes the named stage actually moved or examined, not the run's
/// input size. A stage that sees each byte twice reports twice the bytes, and
/// that is the honest number for its own throughput.
#[inline]
pub fn add_stage_bytes(stage: crate::Stage, bytes: u64) {
    if let Some(runtime) = current_runtime() {
        runtime.add_stage_bytes(stage, bytes);
    }
}

/// Count one consultation of a reuse cache that was served from the cache.
#[inline]
pub fn record_cache_hit(cache: crate::CacheId) {
    if let Some(runtime) = current_runtime() {
        runtime.record_cache_outcome(cache, true);
    }
}

/// Count one consultation of a reuse cache that had to recompute or refetch.
#[inline]
pub fn record_cache_miss(cache: crate::CacheId) {
    if let Some(runtime) = current_runtime() {
        runtime.record_cache_outcome(cache, false);
    }
}

/// Set the current compile phase (Install, Update, Scan, Developer) on the active runtime.
#[inline]
pub fn set_compile_phase(phase: crate::CompilePhase) {
    PROCESS_ACTIVE_COMPILE_PHASE.store(phase as u8, Ordering::Relaxed);
    if let Some(runtime) = current_runtime() {
        runtime.set_compile_phase(phase);
    }
}

/// Retrieve the active compile phase from the active runtime (defaults to Scan).
#[inline]
pub fn active_compile_phase() -> crate::CompilePhase {
    if let Some(runtime) = current_runtime() {
        runtime.active_compile_phase()
    } else {
        match PROCESS_ACTIVE_COMPILE_PHASE.load(Ordering::Relaxed) {
            0 => crate::CompilePhase::Install,
            1 => crate::CompilePhase::Update,
            2 => crate::CompilePhase::Scan,
            3 => crate::CompilePhase::Developer,
            _ => crate::CompilePhase::Scan,
        }
    }
}

/// Record one invocation of a compiler surface in the active compile phase.
#[inline]
pub fn record_compile_surface_invocation(surface: crate::CompileSurfaceId) {
    if let Some(runtime) = current_runtime() {
        runtime.record_compile_surface_invocation(surface);
    }
}

/// Record one invocation of a compiler surface in an explicit compile phase.
#[inline]
pub fn record_compile_surface_invocation_with_phase(
    surface: crate::CompileSurfaceId,
    phase: crate::CompilePhase,
) {
    if let Some(runtime) = current_runtime() {
        runtime.record_compile_surface_invocation_with_phase(surface, phase);
    }
}

/// Record one load of a prepared/installed artifact for a compile surface class.
#[inline]
pub fn record_compile_surface_load(surface: crate::CompileSurfaceId) {
    if let Some(runtime) = current_runtime() {
        runtime.record_compile_surface_load(surface);
    }
}

/// Sum total runtime compilations across all surfaces in Scan and Developer phases.
#[inline]
pub fn total_runtime_compiles() -> u64 {
    if let Some(runtime) = current_runtime() {
        runtime.total_runtime_compiles()
    } else {
        0
    }
}

/// Derive compile surface reports for all 13 compile surface classes.
#[inline]
pub fn compile_surface_reports() -> Vec<crate::schema_v2::CompileSurfaceRecordV2> {
    if let Some(runtime) = current_runtime() {
        runtime.compile_surface_reports()
    } else {
        crate::CompileSurfaceId::ALL
            .iter()
            .map(|&surface| crate::schema_v2::CompileSurfaceRecordV2 {
                version: crate::schema_v2::COMPILE_SURFACE_RECORD_V2_VERSION,
                surface,
                name: surface.as_str().to_string(),
                runtime_compiles: 0,
                loads: 0,
                install_compiles: 0,
                update_compiles: 0,
                developer_compiles: 0,
            })
            .collect()
    }
}

/// Read total cache hits recorded in the active profile for `cache`.
#[inline]
#[must_use]
pub fn cache_hits(cache: crate::CacheId) -> u64 {
    current_runtime().map_or(0, |runtime| runtime.cache_hits(cache))
}

/// Read total cache misses recorded in the active profile for `cache`.
#[inline]
#[must_use]
pub fn cache_misses(cache: crate::CacheId) -> u64 {
    current_runtime().map_or(0, |runtime| runtime.cache_misses(cache))
}

/// Add source bytes processed by the current profile.
#[inline]
pub fn add_input_bytes(bytes: u64) {
    if let Some(runtime) = current_runtime() {
        runtime.add_input_bytes(bytes);
    }
}

/// Add source units such as files, objects, responses, or chunks.
#[inline]
pub fn add_input_units(units: u64) {
    if let Some(runtime) = current_runtime() {
        runtime.add_input_units(units);
    }
}

/// Record one expensive detail event under a deterministic bounded sampling policy.
#[inline]
pub fn record_sampled_event(event: crate::EventId, value: u64, policy: SamplingPolicy) -> bool {
    current_runtime().is_some_and(|runtime| runtime.record_sampled_event(event, value, policy))
}
/// Add bytes produced by accepted decode-through work in the current profile.
#[inline]
pub fn add_derived_decoder_bytes(bytes: u64) {
    if let Some(runtime) = current_runtime() {
        runtime.add_derived_decoder_bytes(bytes);
    }
}

/// Add bytes submitted once to the completed backend route in the current profile.
#[inline]
pub fn add_backend_dispatched_bytes(bytes: u64) {
    if let Some(runtime) = current_runtime() {
        runtime.add_backend_dispatched_bytes(bytes);
    }
}

/// Increment one typed monotonic counter in the current profiling runtime.
#[inline]
pub fn add_counter(counter: crate::CounterId, delta: u64) {
    if let Some(runtime) = current_runtime() {
        runtime.add_counter(counter, delta);
    }
}

/// Replace one typed latest-value gauge in the current profiling runtime.
#[inline]
pub fn set_gauge(gauge: crate::GaugeId, value: u64) {
    if let Some(runtime) = current_runtime() {
        runtime.set_gauge(gauge, value);
    }
}

/// Record one typed instantaneous event with a numeric payload.
#[inline]
pub fn record_event(event: crate::EventId, value: u64) {
    if let Some(runtime) = current_runtime() {
        runtime.record_event(event, value);
    }
}

/// Record one producer enqueue for later matching by [`record_queue_dequeue`].
///
/// The `(queue, sequence)` pair must be unique per in-flight item. Retention
/// is bounded by [`MAX_QUEUE_LINKS`]; loss is counted explicitly.
pub fn record_queue_enqueue(queue: crate::QueueId, sequence: u64) {
    if let Some(runtime) = current_runtime() {
        runtime.record_queue_enqueue(queue, sequence);
    }
}

/// Record the consumer dequeue matching one earlier [`record_queue_enqueue`].
///
/// A dequeue with no recorded pending enqueue increments the unmatched count.
pub fn record_queue_dequeue(queue: crate::QueueId, sequence: u64) {
    if let Some(runtime) = current_runtime() {
        runtime.record_queue_dequeue(queue, sequence);
    }
}

/// Increment one queue's depth gauge and refresh its high-water mark.
pub fn record_queue_depth_enqueue(queue: crate::QueueId) {
    if let Some(runtime) = current_runtime() {
        runtime.queue_depth_enqueue(queue);
    }
}

/// Decrement one queue's depth gauge, saturating at zero.
pub fn record_queue_depth_dequeue(queue: crate::QueueId) {
    if let Some(runtime) = current_runtime() {
        runtime.queue_depth_dequeue(queue);
    }
}

/// Replace one queue's depth gauge and refresh its high-water mark.
pub fn set_queue_depth(queue: crate::QueueId, depth: u64) {
    if let Some(runtime) = current_runtime() {
        runtime.set_queue_depth(queue, depth);
    }
}

/// Record one observed value into a metric's bounded logarithmic distribution.
#[inline]
pub fn record_distribution(metric: crate::MetricId, value: u64) {
    if let Some(runtime) = current_runtime() {
        runtime.record_distribution(metric, value);
    }
}

/// Record one filesystem open latency inside a [`Stage::SourceWalk`] or
/// [`Stage::SourceRead`] instrumented path.
#[inline]
pub fn record_fs_open_latency_ns(elapsed_ns: u64) {
    record_distribution(crate::MetricId::FsOpenLatencyNs, elapsed_ns);
}

/// Record one filesystem read latency inside a [`Stage::SourceRead`]
/// instrumented path.
#[inline]
pub fn record_fs_read_latency_ns(elapsed_ns: u64) {
    record_distribution(crate::MetricId::FsReadLatencyNs, elapsed_ns);
}

/// Record one filesystem metadata (stat/readdir) latency inside a
/// [`Stage::SourceWalk`] instrumented path.
#[inline]
pub fn record_fs_metadata_latency_ns(elapsed_ns: u64) {
    record_distribution(crate::MetricId::FsMetadataLatencyNs, elapsed_ns);
}

/// Record one network request latency observed by a caller.
#[inline]
pub fn record_network_latency_ns(elapsed_ns: u64) {
    record_distribution(crate::MetricId::NetworkLatencyNs, elapsed_ns);
}

/// Add network bytes a caller read and wrote; process-level counters are not
/// visible to the profiler on every host, so callers report their own IO.
#[inline]
pub fn record_network_bytes(read_bytes: u64, written_bytes: u64) {
    if read_bytes > 0 {
        add_counter(crate::CounterId::NetworkBytesRead, read_bytes);
    }
    if written_bytes > 0 {
        add_counter(crate::CounterId::NetworkBytesWritten, written_bytes);
    }
}

/// Count one completed network request.
#[inline]
pub fn record_network_request() {
    add_counter(crate::CounterId::NetworkRequests, 1);
}

/// Record one explicitly observed page-cache state for IO work.
///
/// The observation becomes one [`crate::AnnotationId::IoCacheState`] timeline
/// record and increments the matching observation counter. The profiler
/// never infers cache state from latency; only caller knowledge is recorded.
#[inline]
pub fn record_io_cache_state(state: crate::IoCacheStateV2) {
    record_annotation(crate::AnnotationId::IoCacheState, state.as_value());
    let counter = match state {
        crate::IoCacheStateV2::Cold => crate::CounterId::PageCacheColdObservations,
        crate::IoCacheStateV2::Warm => crate::CounterId::PageCacheWarmObservations,
        crate::IoCacheStateV2::Direct => crate::CounterId::PageCacheDirectObservations,
    };
    add_counter(counter, 1);
}

/// Record the current retained-buffer level in bytes; the runtime keeps the
/// running high water alongside the latest value.
#[inline]
pub fn record_retained_buffer_bytes(bytes: u64) {
    if let Some(runtime) = current_runtime() {
        runtime.record_retained_buffer_bytes(bytes);
    }
}

/// Drain typed counters from the current session or standalone runtime.
///
/// Under a [`Session`] this equals `Runtime::take_session_typed_metrics`;
/// under the standalone `set_enabled` runtime it drains the legacy store.
pub fn take_typed_metrics() -> Vec<TypedMetricRecordV2> {
    runtime_for_drain().take_legacy_typed_metrics()
}

/// Drain caller-recorded value distributions from the current runtime.
///
/// Works under both a [`Session`] and the standalone `set_enabled` runtime.
pub fn take_metric_distributions() -> Vec<MetricDistributionV2> {
    runtime_for_drain().take_metric_distributions()
}

/// Record one typed numeric annotation on the current run timeline.
#[inline]
pub fn record_annotation(annotation: crate::AnnotationId, value: u64) {
    if let Some(runtime) = current_runtime() {
        runtime.record_annotation(annotation, value);
    }
}

/// Record the requested, selected, and completed route for one completed batch.
///
/// A recovered batch records the failed selected backend in
/// `recovered_from_backend` and the replay backend in `completed_backend`.
pub fn record_batch_route(
    workload_key_digest: &str,
    requested_backend: &str,
    selected_backend: &str,
    completed_backend: &str,
    recovered_from_backend: Option<&str>,
) {
    if let Some(runtime) = current_runtime() {
        runtime.record_batch_route(
            workload_key_digest,
            requested_backend,
            selected_backend,
            completed_backend,
            recovered_from_backend,
        );
    }
}

/// Atomically read and clear aggregate input bytes and units.
pub fn take_input_totals() -> (u64, u64) {
    runtime_for_drain().take_input_totals()
}

/// Discard fixed-stage counters and input totals in the current runtime.
pub fn reset() {
    runtime_for_drain().reset();
}
