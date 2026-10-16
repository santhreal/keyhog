mod api;
mod session_drain;
mod shard;

pub use api::*;
pub(crate) use shard::RawStageCounters;

use shard::{
    latency_bucket_bounds, latency_bucket_index, max_counters, percentile_upper_bound,
    zero_cache_counters, zero_compile_surface_invocations, zero_compile_surface_loads,
    zero_counters, zero_event_values, zero_indexed_counters, zero_latency_buckets,
    zero_metric_values, ActiveSpan, PendingQueueEnqueue, RawSpanHardware, RawSpanRecord,
    SpanOutcome, SpanTrace, WorkerShard, GAUGE_PRESENT_WORDS,
};
use crate::schema::Stage;
use crate::schema_v2::{
    AnnotationV2, BatchRouteV2, BlockedWaitRecordV2, CacheEffectivenessV2, DistributionBucketV2,
    Evidence, EvidenceGap, IndexedCounterRecordV2, LatencyBucketV2, LatencyDistributionV2,
    MetricDistributionV2, PointEventV2, QueueDepthV2, QueueLinkV2, RetryRecordV2, SpanRecordV2,
    StageConcurrencyV2, TypedMetricRecordV2, WorkOrigin, WorkerImbalanceV2, WorkerLoadV2,
    WorkerOccupancyRowV2, WorkerOccupancyV2,
};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::future::{poll_fn, Future};
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

pub(crate) const STAGE_COUNT: usize = Stage::ALL.len();

/// Maximum number of causal span records retained by one profiling runtime.
pub const MAX_RECORDED_SPANS: usize = 65_536;
const MAX_NESTED_SPANS: usize = 64;
const LATENCY_BUCKET_COUNT: usize = 65;
pub const MAX_POINT_EVENTS: usize = 16_384;
pub const MAX_ANNOTATIONS: usize = 16_384;
/// Maximum pending enqueues and completed links retained per runtime.
pub const MAX_QUEUE_LINKS: usize = 16_384;
/// Hard cap on retained batch-route records; further routes count as drops.
pub const MAX_BATCH_ROUTES: usize = 16_384;

/// Exact reasons queue causality records were not retained.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QueueLinkLossCounts {
    /// Pending enqueues dropped at capacity or displaced by a duplicate sequence.
    pub dropped_enqueues: u64,
    /// Completed links dropped at capacity.
    pub dropped_links: u64,
    /// Dequeues with no recorded matching enqueue.
    pub unmatched_dequeues: u64,
    /// Pending enqueues never matched by a dequeue before the drain.
    pub unconsumed_enqueues: u64,
}

/// Portable causal parent captured from a runtime's current span context.
///
/// The token is plain data: pass it across crate, thread, or spawn boundaries
/// and attach it with [`span_with_parent`] or [`instrument_future_with_parent`]
/// where thread-local propagation cannot reach. A token only applies inside
/// the runtime it was captured from; elsewhere the span records as a root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CausalParent {
    context_id: u64,
    span_id: u64,
}

impl CausalParent {
    /// Process-local identity of the runtime this token was captured from.
    pub const fn context_id(self) -> u64 {
        self.context_id
    }

    /// Parent span identifier, or zero when captured outside any span.
    pub const fn span_id(self) -> u64 {
        self.span_id
    }

    /// Whether this token names the runtime root instead of a live span.
    pub const fn is_root(self) -> bool {
        self.span_id == 0
    }
}

/// Deterministic bounded policy for retaining expensive detail events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SamplingPolicy {
    initial_events: u64,
    every_nth_after_initial: u64,
    maximum_retained: u64,
}

impl SamplingPolicy {
    /// Retain `initial_events`, then every Nth observation, up to an absolute bound.
    pub const fn bounded(
        initial_events: u64,
        every_nth_after_initial: u64,
        maximum_retained: u64,
    ) -> Self {
        Self {
            initial_events,
            every_nth_after_initial: if every_nth_after_initial == 0 {
                1
            } else {
                every_nth_after_initial
            },
            maximum_retained,
        }
    }

    fn selects(self, observation: u64) -> bool {
        observation < self.initial_events
            || (observation - self.initial_events).is_multiple_of(self.every_nth_after_initial)
    }
}

/// Exact reasons typed timeline records were not retained.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EventLossCounts {
    pub point_events: u64,
    pub annotations: u64,
    pub sampled_out_events: u64,
}

impl EventLossCounts {
    /// Total capacity loss. Policy sampling is reported separately.
    pub const fn capacity_drops(self) -> u64 {
        self.point_events.saturating_add(self.annotations)
    }
}


static ACTIVE_CONTEXTS: AtomicUsize = AtomicUsize::new(0);
static NEXT_THREAD_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_CONTEXT_ID: AtomicU64 = AtomicU64::new(1);
static PROCESS_ACTIVE_COMPILE_PHASE: AtomicU8 = AtomicU8::new(crate::CompilePhase::Scan as u8);

thread_local! {
    pub(super) static CURRENT: RefCell<Vec<Runtime>> = const { RefCell::new(Vec::new()) };
    pub(super) static WORK_ORIGIN: Cell<WorkOrigin> = const { Cell::new(WorkOrigin::Root) };
    pub(super) static TASK_ID: Cell<u64> = const { Cell::new(0) };
    pub(super) static SPAN_DEPTH: Cell<u32> = const { Cell::new(0) };
    pub(super) static LEGACY: RefCell<LegacyRuntime> = RefCell::new(LegacyRuntime::new());
    pub(super) static ACTIVE_SPANS: RefCell<[Option<ActiveSpan>; MAX_NESTED_SPANS]> =
        const { RefCell::new([None; MAX_NESTED_SPANS]) };
    pub(super) static ASYNC_PARENT_SPANS: RefCell<[Option<ActiveSpan>; MAX_NESTED_SPANS]> =
        const { RefCell::new([None; MAX_NESTED_SPANS]) };
    pub(super) static NUMERIC_THREAD_ID: u64 = NEXT_THREAD_ID.fetch_add(1, Ordering::Relaxed);
    pub(super) static THREAD_SHARDS: RefCell<Vec<ThreadShardAssignment>> = const { RefCell::new(Vec::new()) };
}

struct RuntimeInner {
    context_id: u64,
    next_shard_sequence: AtomicU64,
    elapsed_ns: [AtomicU64; STAGE_COUNT],
    calls: [AtomicU64; STAGE_COUNT],
    attributed_ns: [AtomicU64; STAGE_COUNT],
    session_shards: Mutex<Vec<Arc<WorkerShard>>>,
    session_gauge_values: [AtomicU64; crate::MetricId::COUNT],
    session_gauge_present: [AtomicU64; GAUGE_PRESENT_WORDS],
    input_bytes: AtomicU64,
    input_units: AtomicU64,
    session_recording: bool,
    session_route_sequence: AtomicU64,
    session_batch_routes: Mutex<Vec<BatchRouteV2>>,
    session_dropped_batch_routes: AtomicU64,
    started: Instant,
    session_span_sequence: AtomicU64,
    session_span_reservations: AtomicUsize,
    session_spans: Mutex<Vec<RawSpanRecord>>,
    session_dropped_spans: AtomicU64,
    session_event_sequence: AtomicU64,
    session_point_events: Mutex<Vec<PointEventV2>>,
    session_annotations: Mutex<Vec<AnnotationV2>>,
    session_dropped_point_events: AtomicU64,
    session_dropped_annotations: AtomicU64,
    session_sample_observations: [AtomicU64; crate::EventId::COUNT],
    session_sample_retained: [AtomicU64; crate::EventId::COUNT],
    session_sampled_out_events: AtomicU64,
    queue_pending: Mutex<HashMap<(u8, u64), PendingQueueEnqueue>>,
    queue_links: Mutex<Vec<QueueLinkV2>>,
    queue_dropped_enqueues: AtomicU64,
    queue_dropped_links: AtomicU64,
    queue_unmatched_dequeues: AtomicU64,
    queue_depth_current: [AtomicU64; crate::QueueId::COUNT],
    queue_depth_high_water: [AtomicU64; crate::QueueId::COUNT],
    queue_depth_enqueues: [AtomicU64; crate::QueueId::COUNT],
    queue_depth_dequeues: [AtomicU64; crate::QueueId::COUNT],
    legacy_typed_counters: [AtomicU64; crate::MetricId::COUNT],
    distribution_buckets: [[AtomicU64; LATENCY_BUCKET_COUNT]; crate::MetricId::COUNT],
    distribution_min: [AtomicU64; crate::MetricId::COUNT],
    distribution_max: [AtomicU64; crate::MetricId::COUNT],
    active_compile_phase: AtomicU8,
    legacy_compile_surface_invocations:
        [[AtomicU64; crate::CompilePhase::COUNT]; crate::CompileSurfaceId::COUNT],
    legacy_compile_surface_loads: [AtomicU64; crate::CompileSurfaceId::COUNT],
}

const fn zero_queue_depths() -> [AtomicU64; crate::QueueId::COUNT] {
    [const { AtomicU64::new(0) }; crate::QueueId::COUNT]
}

const fn zero_distribution_buckets() -> [[AtomicU64; LATENCY_BUCKET_COUNT]; crate::MetricId::COUNT]
{
    [const { [const { AtomicU64::new(0) }; LATENCY_BUCKET_COUNT] }; crate::MetricId::COUNT]
}

const fn zero_distribution_mins() -> [AtomicU64; crate::MetricId::COUNT] {
    [const { AtomicU64::new(u64::MAX) }; crate::MetricId::COUNT]
}

const fn zero_distribution_maxes() -> [AtomicU64; crate::MetricId::COUNT] {
    [const { AtomicU64::new(0) }; crate::MetricId::COUNT]
}

impl RuntimeInner {
    fn new(session_recording: bool, started: Instant) -> Self {
        Self {
            context_id: NEXT_CONTEXT_ID.fetch_add(1, Ordering::Relaxed),
            next_shard_sequence: AtomicU64::new(1),
            elapsed_ns: zero_counters(),
            calls: zero_counters(),
            attributed_ns: zero_counters(),
            session_shards: Mutex::new(Vec::new()),
            session_gauge_values: zero_metric_values(),
            session_gauge_present: [const { AtomicU64::new(0) }; GAUGE_PRESENT_WORDS],
            input_bytes: AtomicU64::new(0),
            input_units: AtomicU64::new(0),
            session_recording,
            session_route_sequence: AtomicU64::new(0),
            session_batch_routes: Mutex::new(Vec::new()),
            session_dropped_batch_routes: AtomicU64::new(0),
            started,
            session_span_sequence: AtomicU64::new(0),
            session_span_reservations: AtomicUsize::new(0),
            session_spans: Mutex::new(Vec::new()),
            session_dropped_spans: AtomicU64::new(0),
            session_event_sequence: AtomicU64::new(0),
            session_point_events: Mutex::new(Vec::new()),
            session_annotations: Mutex::new(Vec::new()),
            session_dropped_point_events: AtomicU64::new(0),
            session_dropped_annotations: AtomicU64::new(0),
            session_sample_observations: zero_event_values(),
            session_sample_retained: zero_event_values(),
            session_sampled_out_events: AtomicU64::new(0),
            queue_pending: Mutex::new(HashMap::new()),
            queue_links: Mutex::new(Vec::new()),
            queue_dropped_enqueues: AtomicU64::new(0),
            queue_dropped_links: AtomicU64::new(0),
            queue_unmatched_dequeues: AtomicU64::new(0),
            queue_depth_current: zero_queue_depths(),
            queue_depth_high_water: zero_queue_depths(),
            queue_depth_enqueues: zero_queue_depths(),
            queue_depth_dequeues: zero_queue_depths(),
            legacy_typed_counters: zero_metric_values(),
            distribution_buckets: zero_distribution_buckets(),
            distribution_min: zero_distribution_mins(),
            distribution_max: zero_distribution_maxes(),
            active_compile_phase: AtomicU8::new(
                PROCESS_ACTIVE_COMPILE_PHASE.load(Ordering::Relaxed),
            ),
            legacy_compile_surface_invocations: zero_compile_surface_invocations(),
            legacy_compile_surface_loads: zero_compile_surface_loads(),
        }
    }

    fn sorted_shards(&self) -> Vec<Arc<WorkerShard>> {
        let shards = match self.session_shards.lock() {
            Ok(shards) => shards,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut sorted: Vec<Arc<WorkerShard>> = shards.to_vec();
        sorted.sort_by_key(|shard| shard.sequence);
        sorted
    }
}

struct ThreadShardAssignment {
    runtime: Weak<RuntimeInner>,
    shard: Arc<WorkerShard>,
}

/// Owned fixed-stage metric storage that can be propagated across worker boundaries.
#[derive(Clone)]
pub struct Runtime {
    inner: Arc<RuntimeInner>,
}

impl Runtime {
    /// Create an isolated runtime whose measurements can back one profiling session.
    pub fn new() -> Self {
        Self::new_at(Instant::now())
    }

    /// Process-local identity that distinguishes this runtime from every peer.
    pub fn context_id(&self) -> u64 {
        self.inner.context_id
    }

    pub(crate) fn new_at(started: Instant) -> Self {
        Self {
            inner: Arc::new(RuntimeInner::new(true, started)),
        }
    }

    pub(super) fn legacy() -> Self {
        Self {
            inner: Arc::new(RuntimeInner::new(false, Instant::now())),
        }
    }

    pub(super) fn worker_shard(&self) -> Option<Arc<WorkerShard>> {
        if !self.inner.session_recording {
            return None;
        }
        THREAD_SHARDS.with(|assignments| {
            let mut assignments = assignments.borrow_mut();
            assignments.retain(|assignment| assignment.runtime.strong_count() != 0);
            if let Some(assignment) = assignments.iter().find(|assignment| {
                std::ptr::eq(assignment.runtime.as_ptr(), Arc::as_ptr(&self.inner))
            }) {
                return Some(assignment.shard.clone());
            }
            let shard = Arc::new(WorkerShard::new(
                self.inner
                    .next_shard_sequence
                    .fetch_add(1, Ordering::Relaxed),
            ));
            match self.inner.session_shards.lock() {
                Ok(mut shards) => shards.push(shard.clone()),
                Err(poisoned) => poisoned.into_inner().push(shard.clone()),
            }
            assignments.push(ThreadShardAssignment {
                runtime: Arc::downgrade(&self.inner),
                shard: shard.clone(),
            });
            Some(shard)
        })
    }

    /// Number of isolated worker counter shards registered by this runtime.
    pub fn worker_shard_count(&self) -> usize {
        match self.inner.session_shards.lock() {
            Ok(shards) => shards.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// Shard sequence of the calling thread without registering a new shard.
    fn peek_worker_shard_sequence(&self) -> u64 {
        THREAD_SHARDS.with(|assignments| {
            assignments
                .borrow()
                .iter()
                .find(|assignment| {
                    std::ptr::eq(assignment.runtime.as_ptr(), Arc::as_ptr(&self.inner))
                })
                .map_or(0, |assignment| assignment.shard.sequence)
        })
    }

    /// Capture a portable token naming this runtime's current causal parent.
    pub fn causal_parent(&self) -> CausalParent {
        CausalParent {
            context_id: self.inner.context_id,
            span_id: self.current_parent_span_id(),
        }
    }

    /// Make this runtime current on the calling thread until the guard is dropped.
    pub fn enter(&self) -> ContextGuard {
        let _ = self.worker_shard();
        CURRENT.with(|stack| stack.borrow_mut().push(self.clone()));
        ACTIVE_CONTEXTS.fetch_add(1, Ordering::Relaxed);
        ContextGuard {
            runtime: self.clone(),
            not_send: PhantomData,
        }
    }

    pub(super) fn enter_async_parent(&self, span_id: u64) -> Option<AsyncParentGuard> {
        let stack_slot =
            ASYNC_PARENT_SPANS.with(|stack| stack.borrow().iter().position(Option::is_none))?;
        let runtime_key = Arc::as_ptr(&self.inner) as usize;
        ASYNC_PARENT_SPANS.with(|stack| {
            stack.borrow_mut()[stack_slot] = Some(ActiveSpan {
                runtime_key,
                span_id,
                child_elapsed_ns: 0,
                parent_slot: None,
            });
        });
        Some(AsyncParentGuard {
            runtime_key,
            span_id,
            stack_slot,
            not_send: PhantomData,
        })
    }

    /// Run one synchronous closure with this runtime as its current context.
    pub fn scope<T>(&self, operation: impl FnOnce() -> T) -> T {
        let _guard = self.enter();
        operation()
    }

    pub(super) fn elapsed_ns(&self) -> u64 {
        u64::try_from(self.inner.started.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    pub(crate) fn add_counter(&self, counter: crate::CounterId, delta: u64) {
        if let Some(shard) = self.worker_shard() {
            shard.counter_values[counter.metric_id() as usize].fetch_add(delta, Ordering::Relaxed);
        } else if !self.inner.session_recording {
            self.inner.legacy_typed_counters[counter.metric_id() as usize]
                .fetch_add(delta, Ordering::Relaxed);
        }
    }

    pub(super) fn record_distribution(&self, metric_id: crate::MetricId, value: u64) {
        let index = metric_id as usize;
        let bucket = latency_bucket_index(value);
        self.inner.distribution_buckets[index][bucket].fetch_add(1, Ordering::Relaxed);
        self.inner.distribution_min[index].fetch_min(value, Ordering::Relaxed);
        self.inner.distribution_max[index].fetch_max(value, Ordering::Relaxed);
    }

    /// Count retry annotations recorded so far without draining them.
    pub(crate) fn retry_annotation_count(&self) -> u64 {
        if !self.inner.session_recording {
            return 0;
        }
        let annotations = match self.inner.session_annotations.lock() {
            Ok(annotations) => annotations,
            Err(poisoned) => poisoned.into_inner(),
        };
        annotations
            .iter()
            .filter(|annotation| annotation.annotation_id == crate::AnnotationId::RetryAttempt)
            .count() as u64
    }

    /// Read one session gauge without clearing it; `None` when never set.
    pub(crate) fn session_gauge(&self, gauge: crate::GaugeId) -> Option<u64> {
        if !self.inner.session_recording {
            return None;
        }
        let index = gauge.metric_id() as usize;
        let present = self.inner.session_gauge_present[index / 64].load(Ordering::Relaxed);
        (present & (1_u64 << (index % 64)) != 0)
            .then(|| self.inner.session_gauge_values[index].load(Ordering::Relaxed))
    }

    /// Record the current retained-buffer level and its running high water.
    pub(crate) fn record_retained_buffer_bytes(&self, bytes: u64) {
        if !self.inner.session_recording {
            return;
        }
        self.set_gauge(crate::GaugeId::RetainedBufferBytes, bytes);
        let peak = crate::GaugeId::RetainedBufferPeakBytes.metric_id() as usize;
        self.inner.session_gauge_values[peak].fetch_max(bytes, Ordering::Relaxed);
        self.inner.session_gauge_present[peak / 64]
            .fetch_or(1_u64 << (peak % 64), Ordering::Relaxed);
    }

    /// Drain caller-recorded value distributions in stable metric order.
    pub fn take_metric_distributions(&self) -> Vec<MetricDistributionV2> {
        let mut records = Vec::new();
        for index in 0..crate::MetricId::COUNT {
            let mut call_count = 0_u64;
            let buckets: Vec<DistributionBucketV2> = (0..LATENCY_BUCKET_COUNT)
                .filter_map(|bucket| {
                    let count =
                        self.inner.distribution_buckets[index][bucket].swap(0, Ordering::Relaxed);
                    call_count = call_count.saturating_add(count);
                    if count == 0 {
                        return None;
                    }
                    let (lower_bound, upper_bound) = latency_bucket_bounds(bucket);
                    Some(DistributionBucketV2 {
                        version: 1,
                        lower_bound,
                        upper_bound,
                        count,
                    })
                })
                .collect();
            if call_count == 0 {
                continue;
            }
            let minimum = self.inner.distribution_min[index].swap(u64::MAX, Ordering::Relaxed);
            let maximum = self.inner.distribution_max[index].swap(0, Ordering::Relaxed);
            records.push(MetricDistributionV2 {
                version: 1,
                metric_id: crate::METRICS[index].id,
                call_count,
                minimum,
                maximum,
                buckets,
            });
        }
        records
    }

    /// Drain typed counters recorded by the standalone (non-session) runtime.
    pub fn take_legacy_typed_metrics(&self) -> Vec<TypedMetricRecordV2> {
        if self.inner.session_recording {
            return self.take_session_typed_metrics();
        }
        let mut records = Vec::new();
        for counter in crate::CounterId::ALL {
            let metric_id = counter.metric_id();
            let value =
                self.inner.legacy_typed_counters[metric_id as usize].swap(0, Ordering::Relaxed);
            if value != 0 {
                records.push(TypedMetricRecordV2 {
                    version: 1,
                    metric_id,
                    kind: crate::MetricKind::Counter,
                    value,
                });
            }
        }
        records
    }

    pub(crate) fn set_gauge(&self, gauge: crate::GaugeId, value: u64) {
        if !self.inner.session_recording {
            return;
        }
        let index = gauge.metric_id() as usize;
        self.inner.session_gauge_values[index].store(value, Ordering::Relaxed);
        self.inner.session_gauge_present[index / 64]
            .fetch_or(1_u64 << (index % 64), Ordering::Relaxed);
    }

    pub(super) fn record_event(&self, event_id: crate::EventId, value: u64) -> bool {
        if !self.inner.session_recording {
            return false;
        }
        let sequence = self
            .inner
            .session_event_sequence
            .fetch_add(1, Ordering::Relaxed);
        let event = PointEventV2 {
            version: 2,
            sequence,
            event_id,
            elapsed_ns: self.elapsed_ns(),
            thread_id: numeric_thread_id(),
            value,
            task_id: evidence_or_unavailable(current_task_id()),
            worker_id: evidence_or_unavailable(self.peek_worker_shard_sequence()),
        };
        let mut events = match self.inner.session_point_events.lock() {
            Ok(events) => events,
            Err(poisoned) => poisoned.into_inner(),
        };
        if events.len() == MAX_POINT_EVENTS {
            self.inner
                .session_dropped_point_events
                .fetch_add(1, Ordering::Relaxed);
            false
        } else {
            events.push(event);
            true
        }
    }

    pub(super) fn record_sampled_event(
        &self,
        event_id: crate::EventId,
        value: u64,
        policy: SamplingPolicy,
    ) -> bool {
        if !self.inner.session_recording {
            return false;
        }
        let index = event_id.index();
        let observation =
            self.inner.session_sample_observations[index].fetch_add(1, Ordering::Relaxed);
        let mut retained = false;
        if policy.selects(observation) {
            let counter = &self.inner.session_sample_retained[index];
            let mut current = counter.load(Ordering::Relaxed);
            loop {
                if current >= policy.maximum_retained {
                    break;
                }
                match counter.compare_exchange_weak(
                    current,
                    current + 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        retained = true;
                        break;
                    }
                    Err(observed) => current = observed,
                }
            }
        }
        if retained {
            self.record_event(event_id, value)
        } else {
            self.inner
                .session_sampled_out_events
                .fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    pub(super) fn record_annotation(&self, annotation_id: crate::AnnotationId, value: u64) {
        if !self.inner.session_recording {
            return;
        }
        let sequence = self
            .inner
            .session_event_sequence
            .fetch_add(1, Ordering::Relaxed);
        let annotation = AnnotationV2 {
            version: 2,
            sequence,
            annotation_id,
            elapsed_ns: self.elapsed_ns(),
            thread_id: numeric_thread_id(),
            value,
            task_id: evidence_or_unavailable(current_task_id()),
            worker_id: evidence_or_unavailable(self.peek_worker_shard_sequence()),
        };
        let mut annotations = match self.inner.session_annotations.lock() {
            Ok(annotations) => annotations,
            Err(poisoned) => poisoned.into_inner(),
        };
        if annotations.len() == MAX_ANNOTATIONS {
            self.inner
                .session_dropped_annotations
                .fetch_add(1, Ordering::Relaxed);
        } else {
            annotations.push(annotation);
        }
    }

    /// Drain typed counter and gauge records in stable metric order.
    pub fn take_session_typed_metrics(&self) -> Vec<TypedMetricRecordV2> {
        let mut records =
            Vec::with_capacity(crate::CounterId::ALL.len() + crate::GaugeId::ALL.len());
        let shards = self.inner.sorted_shards();
        for counter in crate::CounterId::ALL {
            let metric_id = counter.metric_id();
            let value = shards.iter().fold(0_u64, |total, shard| {
                total.saturating_add(
                    shard.counter_values[metric_id as usize].swap(0, Ordering::Relaxed),
                )
            });
            if value != 0 {
                records.push(TypedMetricRecordV2 {
                    version: 1,
                    metric_id,
                    kind: crate::MetricKind::Counter,
                    value,
                });
            }
        }
        drop(shards);
        let present: [u64; GAUGE_PRESENT_WORDS] =
            std::array::from_fn(|i| self.inner.session_gauge_present[i].swap(0, Ordering::Relaxed));
        for gauge in crate::GaugeId::ALL {
            let metric_id = gauge.metric_id();
            let index = metric_id as usize;
            if present[index / 64] & (1_u64 << (index % 64)) != 0 {
                records.push(TypedMetricRecordV2 {
                    version: 1,
                    metric_id,
                    kind: crate::MetricKind::Gauge,
                    value: self.inner.session_gauge_values[metric_id as usize]
                        .swap(0, Ordering::Relaxed),
                });
            }
        }
        records.sort_unstable_by_key(|record| record.metric_id);
        records
    }

    /// Drain typed timeline records and exact loss counts by cause.
    pub fn take_session_typed_events(
        &self,
    ) -> (Vec<PointEventV2>, Vec<AnnotationV2>, EventLossCounts) {
        let mut events = match self.inner.session_point_events.lock() {
            Ok(events) => events,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut events = std::mem::take(&mut *events);
        let mut annotations = match self.inner.session_annotations.lock() {
            Ok(annotations) => annotations,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut annotations = std::mem::take(&mut *annotations);
        events.sort_unstable_by_key(|event| event.sequence);
        annotations.sort_unstable_by_key(|annotation| annotation.sequence);
        let loss = EventLossCounts {
            point_events: self
                .inner
                .session_dropped_point_events
                .swap(0, Ordering::Relaxed),
            annotations: self
                .inner
                .session_dropped_annotations
                .swap(0, Ordering::Relaxed),
            sampled_out_events: self
                .inner
                .session_sampled_out_events
                .swap(0, Ordering::Relaxed),
        };
        (events, annotations, loss)
    }

    pub(super) fn current_parent(&self) -> (Option<usize>, u64) {
        let runtime_key = Arc::as_ptr(&self.inner) as usize;
        let active = ACTIVE_SPANS.with(|stack| {
            let stack = stack.borrow();
            stack.iter().enumerate().rev().find_map(|(slot, active)| {
                active
                    .and_then(|a| (a.runtime_key == runtime_key).then_some((Some(slot), a.span_id)))
            })
        });
        if let Some(pair) = active {
            return pair;
        }
        let async_span_id = ASYNC_PARENT_SPANS.with(|stack| {
            stack
                .borrow()
                .iter()
                .rev()
                .flatten()
                .find(|active| active.runtime_key == runtime_key)
                .map(|active| active.span_id)
        });
        (None, async_span_id.unwrap_or(0))
    }

    pub(super) fn current_parent_span_id(&self) -> u64 {
        self.current_parent().1
    }

    fn reserve_span_with_id(
        &self,
        span_id: u64,
        stage: Stage,
        started: Instant,
        parent_span_id: u64,
        _stack_slot: Option<usize>,
        worker_id: u64,
    ) -> Option<SpanTrace> {
        if !self.inner.session_recording {
            return None;
        }
        let reservation = self
            .inner
            .session_span_reservations
            .fetch_add(1, Ordering::Relaxed);
        if reservation >= MAX_RECORDED_SPANS {
            self.inner
                .session_dropped_spans
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let mut records = match self.inner.session_spans.lock() {
            Ok(records) => records,
            Err(poisoned) => poisoned.into_inner(),
        };
        let record_index = records.len();
        records.push(RawSpanRecord {
            span_id,
            parent_span_id,
            metric_id: stage.into(),
            start_ns: u64::try_from(
                started
                    .checked_duration_since(self.inner.started)
                    .unwrap_or_default()
                    .as_nanos(),
            )
            .unwrap_or(u64::MAX),
            inclusive_ns: 0,
            thread_id: numeric_thread_id(),
            worker_id,
            task_id: current_task_id(),
            work_origin: current_work_origin(),
            completed: false,
            hardware: RawSpanHardware::begin(),
        });
        Some(SpanTrace {
            record_index,
            span_id,
        })
    }

    fn reserve_span(
        &self,
        stage: Stage,
        started: Instant,
        parent_span_id: u64,
        stack_slot: Option<usize>,
        worker_id: u64,
    ) -> Option<SpanTrace> {
        let span_id = self
            .inner
            .session_span_sequence
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.reserve_span_with_id(
            span_id,
            stage,
            started,
            parent_span_id,
            stack_slot,
            worker_id,
        )
    }

    pub(super) fn begin_span_with(
        &self,
        stage: Stage,
        started: Instant,
        parent_span_id: u64,
        parent_slot: Option<usize>,
        worker_id: u64,
    ) -> (Option<SpanTrace>, Option<usize>, u64) {
        let span_id = self
            .inner
            .session_span_sequence
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let stack_slot = ACTIVE_SPANS.with(|stack| stack.borrow().iter().position(Option::is_none));
        let Some(stack_slot) = stack_slot else {
            self.inner
                .session_dropped_spans
                .fetch_add(1, Ordering::Relaxed);
            return (None, None, span_id);
        };
        let trace = if self.inner.session_recording {
            self.reserve_span_with_id(
                span_id,
                stage,
                started,
                parent_span_id,
                Some(stack_slot),
                worker_id,
            )
        } else {
            None
        };
        let runtime_key = Arc::as_ptr(&self.inner) as usize;
        ACTIVE_SPANS.with(|stack| {
            stack.borrow_mut()[stack_slot] = Some(ActiveSpan {
                runtime_key,
                span_id,
                child_elapsed_ns: 0,
                parent_slot,
            });
        });
        (trace, Some(stack_slot), span_id)
    }

    fn pop_active_span(
        &self,
        stack_slot: Option<usize>,
        expected_span_id: u64,
        elapsed_ns: u64,
    ) -> u64 {
        let Some(stack_slot) = stack_slot else {
            return elapsed_ns;
        };
        let runtime_key = Arc::as_ptr(&self.inner) as usize;
        let child_elapsed_ns = ACTIVE_SPANS.with(|stack| {
            let mut stack = stack.borrow_mut();
            if let Some(active) = &stack[stack_slot] {
                if active.runtime_key == runtime_key && active.span_id == expected_span_id {
                    let active = stack[stack_slot].take().unwrap();
                    if let Some(parent_slot) = active.parent_slot {
                        if let Some(parent) = stack[parent_slot].as_mut() {
                            if parent.runtime_key == runtime_key {
                                parent.child_elapsed_ns =
                                    parent.child_elapsed_ns.saturating_add(elapsed_ns);
                            }
                        }
                    }
                    return active.child_elapsed_ns;
                }
            }
            0
        });
        elapsed_ns.saturating_sub(child_elapsed_ns)
    }
    pub(super) fn begin_async_span(
        &self,
        stage: Stage,
        started: Instant,
        parent_span_id: u64,
        worker_id: u64,
    ) -> Option<SpanTrace> {
        if !self.inner.session_recording {
            return None;
        }
        self.reserve_span(stage, started, parent_span_id, None, worker_id)
    }

    fn finish_span(&self, trace: SpanTrace, inclusive_ns: u64) {
        let mut records = match self.inner.session_spans.lock() {
            Ok(records) => records,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(record) = records.get_mut(trace.record_index) {
            record.inclusive_ns = inclusive_ns;
            record.completed = true;
            record.hardware.finish();
        }
    }

    /// Drain bounded causal spans and the exact count omitted or unfinished.
    pub fn take_session_span_records(&self) -> (Vec<SpanRecordV2>, u64) {
        let mut records = match self.inner.session_spans.lock() {
            Ok(records) => records,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut raw = std::mem::take(&mut *records);
        drop(records);
        raw.sort_unstable_by_key(|record| record.span_id);
        let unfinished = raw.iter().filter(|record| !record.completed).count() as u64;
        raw.retain(|record| record.completed);
        let positions: HashMap<u64, usize> = raw
            .iter()
            .enumerate()
            .map(|(index, record)| (record.span_id, index))
            .collect();
        let mut exclusive: Vec<u64> = raw.iter().map(|record| record.inclusive_ns).collect();
        for record in &raw {
            if let Some(parent_index) = positions.get(&record.parent_span_id).copied() {
                exclusive[parent_index] =
                    exclusive[parent_index].saturating_sub(record.inclusive_ns);
            }
        }
        let spans = raw
            .into_iter()
            .enumerate()
            .map(|(index, record)| SpanRecordV2 {
                version: 3,
                span_id: record.span_id,
                parent_span_id: if positions.contains_key(&record.parent_span_id) {
                    Evidence::recorded(record.parent_span_id)
                } else {
                    Evidence::unavailable(EvidenceGap::Unavailable)
                },
                metric_id: record.metric_id,
                start_ns: record.start_ns,
                inclusive_ns: record.inclusive_ns,
                exclusive_ns: exclusive[index],
                thread_id: record.thread_id,
                task_id: evidence_or_unavailable(record.task_id),
                worker_id: evidence_or_unavailable(record.worker_id),
                work_origin: record.work_origin,
                hardware: record.hardware.into_evidence(),
            })
            .collect();
        let dropped = self
            .inner
            .session_dropped_spans
            .swap(0, Ordering::Relaxed)
            .saturating_add(unfinished);
        (spans, dropped)
    }

    /// Drain per-micro-function logarithmic latency distributions.
    pub fn take_session_latency_distributions(&self) -> Vec<LatencyDistributionV2> {
        let shards = self.inner.sorted_shards();
        Stage::ALL
            .into_iter()
            .filter_map(|stage| {
                let mut call_count = 0_u64;
                let buckets: Vec<LatencyBucketV2> = (0..LATENCY_BUCKET_COUNT)
                    .filter_map(|index| {
                        let count = shards.iter().fold(0_u64, |total, shard| {
                            total.saturating_add(
                                shard.latency_buckets[stage.index()][index]
                                    .swap(0, Ordering::Relaxed),
                            )
                        });
                        call_count = call_count.saturating_add(count);
                        (count != 0).then(|| {
                            let (lower_bound_ns, upper_bound_ns) = latency_bucket_bounds(index);
                            LatencyBucketV2 {
                                version: 1,
                                lower_bound_ns,
                                upper_bound_ns,
                                count,
                            }
                        })
                    })
                    .collect();
                if call_count == 0 {
                    return None;
                }
                let minimum_ns = shards.iter().fold(u64::MAX, |minimum, shard| {
                    minimum
                        .min(shard.latency_min_ns[stage.index()].swap(u64::MAX, Ordering::Relaxed))
                });
                let maximum_ns = shards.iter().fold(0_u64, |maximum, shard| {
                    maximum.max(shard.latency_max_ns[stage.index()].swap(0, Ordering::Relaxed))
                });
                Some(LatencyDistributionV2 {
                    version: 2,
                    metric_id: stage.metric_id(),
                    macro_stage_id: stage.macro_stage_id(),
                    call_count,
                    minimum_ns,
                    maximum_ns,
                    p50_ns: percentile_upper_bound(&buckets, call_count, 50, maximum_ns),
                    p90_ns: percentile_upper_bound(&buckets, call_count, 90, maximum_ns),
                    p95_ns: percentile_upper_bound(&buckets, call_count, 95, maximum_ns),
                    p99_ns: percentile_upper_bound(&buckets, call_count, 99, maximum_ns),
                    buckets,
                })
            })
            .collect()
    }

    pub(super) fn record(&self, shard: Option<&WorkerShard>, stage: Stage, outcome: SpanOutcome) {
        let index = stage.index();
        let elapsed_ns = outcome.elapsed_ns;
        let self_ns = outcome.self_ns;
        if self.inner.session_recording {
            let Some(shard) = shard else {
                return;
            };
            shard.elapsed_ns[index].fetch_add(elapsed_ns, Ordering::Relaxed);
            shard.calls[index].fetch_add(1, Ordering::Relaxed);
            shard.legacy_elapsed_ns[index].fetch_add(elapsed_ns, Ordering::Relaxed);
            shard.legacy_calls[index].fetch_add(1, Ordering::Relaxed);
            let bucket = latency_bucket_index(elapsed_ns);
            shard.latency_buckets[index][bucket].fetch_add(1, Ordering::Relaxed);
            shard.latency_min_ns[index].fetch_min(elapsed_ns, Ordering::Relaxed);
            shard.latency_max_ns[index].fetch_max(elapsed_ns, Ordering::Relaxed);
            shard.stage_first_start_ns[index].fetch_min(outcome.start_offset_ns, Ordering::Relaxed);
            shard.stage_last_end_ns[index].fetch_max(
                outcome.start_offset_ns.saturating_add(elapsed_ns),
                Ordering::Relaxed,
            );
            // Every non-blocked stage carries its self-time (exclusive elapsed time) in attributed_ns.
            // Blocked wait and container stages are never attributed execution.
            if !outcome.blocked && !stage.is_container() {
                shard.attributed_ns[index].fetch_add(self_ns, Ordering::Relaxed);
                shard.legacy_attributed_ns[index].fetch_add(self_ns, Ordering::Relaxed);
            }

            if outcome.blocked {
                shard.blocked_ns[index].fetch_add(elapsed_ns, Ordering::Relaxed);
                shard.blocked_calls[index].fetch_add(1, Ordering::Relaxed);
            }
            if outcome.serial {
                shard.serial_ns[index].fetch_add(elapsed_ns, Ordering::Relaxed);
                shard.serial_calls[index].fetch_add(1, Ordering::Relaxed);
            }
            // Worker occupancy is computed from self-time: a worker is credited once
            // for each nanosecond it actually spends executing or waiting in blocked state.
            // Container stages wrapping multi-threaded pipelines do not add to worker occupancy.
            if !stage.is_container() {
                if outcome.outermost {
                    shard.top_level_calls.fetch_add(1, Ordering::Relaxed);
                }
                if outcome.blocked {
                    shard
                        .top_level_blocked_ns
                        .fetch_add(self_ns, Ordering::Relaxed);
                } else {
                    shard
                        .top_level_busy_ns
                        .fetch_add(self_ns, Ordering::Relaxed);
                }
            }
            return;
        }
        self.inner.elapsed_ns[index].fetch_add(elapsed_ns, Ordering::Relaxed);
        self.inner.calls[index].fetch_add(1, Ordering::Relaxed);
        if !outcome.blocked && !stage.is_container() {
            self.inner.attributed_ns[index].fetch_add(self_ns, Ordering::Relaxed);
        }
    }

    pub(super) fn add_stage_bytes(&self, stage: Stage, bytes: u64) {
        if let Some(shard) = self.worker_shard() {
            shard.stage_bytes[stage.index()].fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub(super) fn record_cache_outcome(&self, cache: crate::CacheId, hit: bool) {
        let Some(shard) = self.worker_shard() else {
            return;
        };
        let slot = if hit {
            &shard.cache_hits[cache.index()]
        } else {
            &shard.cache_misses[cache.index()]
        };
        slot.fetch_add(1, Ordering::Relaxed);
    }

    /// Read total cache hits across all worker shards for `cache`.
    #[inline]
    #[must_use]
    pub fn cache_hits(&self, cache: crate::CacheId) -> u64 {
        let index = cache.index();
        let mut total = 0u64;
        for shard in self.inner.sorted_shards() {
            total = total.saturating_add(shard.cache_hits[index].load(Ordering::Relaxed));
        }
        total
    }

    /// Read total cache misses across all worker shards for `cache`.
    #[inline]
    #[must_use]
    pub fn cache_misses(&self, cache: crate::CacheId) -> u64 {
        let index = cache.index();
        let mut total = 0u64;
        for shard in self.inner.sorted_shards() {
            total = total.saturating_add(shard.cache_misses[index].load(Ordering::Relaxed));
        }
        total
    }

    pub(super) fn record_retry(&self, cause: crate::RetryCause) {
        if let Some(shard) = self.worker_shard() {
            shard.retries[cause.index()].fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn add_indexed_counter(&self, counter: crate::IndexedCounterId, slot: u16, delta: u64) {
        let Some(shard) = self.worker_shard() else {
            return;
        };
        // Folding an out-of-range slot into the last one would attribute one
        // caller's cost to another. Count it as dropped instead.
        match shard.indexed_counters[counter.index()].get(usize::from(slot)) {
            Some(cell) => {
                cell.fetch_add(delta, Ordering::Relaxed);
            }
            None => {
                shard
                    .indexed_counter_dropped
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub(super) fn add_input_bytes(&self, bytes: u64) {
        if let Some(shard) = self.worker_shard() {
            shard.input_bytes.fetch_add(bytes, Ordering::Relaxed);
            shard.legacy_input_bytes.fetch_add(bytes, Ordering::Relaxed);
            shard.counter_values[crate::MetricId::InputBytes as usize]
                .fetch_add(bytes, Ordering::Relaxed);
        } else {
            self.inner.input_bytes.fetch_add(bytes, Ordering::Relaxed);
            self.inner.legacy_typed_counters[crate::MetricId::InputBytes as usize]
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub(super) fn add_input_units(&self, units: u64) {
        if let Some(shard) = self.worker_shard() {
            shard.input_units.fetch_add(units, Ordering::Relaxed);
            shard.legacy_input_units.fetch_add(units, Ordering::Relaxed);
            shard.counter_values[crate::MetricId::InputUnits as usize]
                .fetch_add(units, Ordering::Relaxed);
        } else {
            self.inner.input_units.fetch_add(units, Ordering::Relaxed);
            self.inner.legacy_typed_counters[crate::MetricId::InputUnits as usize]
                .fetch_add(units, Ordering::Relaxed);
        }
    }

    pub(super) fn add_derived_decoder_bytes(&self, bytes: u64) {
        if let Some(shard) = self.worker_shard() {
            shard
                .derived_decoder_bytes
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub(super) fn add_backend_dispatched_bytes(&self, bytes: u64) {
        if let Some(shard) = self.worker_shard() {
            shard
                .backend_dispatched_bytes
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}

