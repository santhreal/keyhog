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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
            || (observation - self.initial_events) % self.every_nth_after_initial == 0
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

#[derive(Clone, Copy)]
struct ActiveSpan {
    runtime_key: usize,
    span_id: u64,
    child_elapsed_ns: u64,
    parent_slot: Option<usize>,
}

#[derive(Clone, Copy)]
struct SpanTrace {
    record_index: usize,
    span_id: u64,
}

/// One completed span's recording payload, assembled on the guard's drop path.
#[derive(Clone, Copy)]
struct SpanOutcome {
    start_offset_ns: u64,
    elapsed_ns: u64,
    self_ns: u64,
    blocked: bool,
    serial: bool,
    outermost: bool,
}

struct RawSpanRecord {
    span_id: u64,
    parent_span_id: u64,
    metric_id: crate::MetricId,
    start_ns: u64,
    inclusive_ns: u64,
    thread_id: u64,
    worker_id: u64,
    task_id: u64,
    work_origin: WorkOrigin,
    completed: bool,
    hardware: RawSpanHardware,
}

/// Raw counter readings captured at span edges; the cold path joins them.
#[derive(Clone, Copy, Default)]
struct RawSpanHardware {
    cycles_begin: u64,
    cycles_end: u64,
    instructions_begin: u64,
    instructions_end: u64,
    has_cycles: bool,
    has_instructions: bool,
    finished: bool,
}

impl RawSpanHardware {
    fn begin() -> Self {
        let mut hardware = Self::default();
        if let Some(reading) = crate::hardware::span_counter_reading() {
            if let Some(cycles) = reading.cycles {
                hardware.cycles_begin = cycles;
                hardware.has_cycles = true;
            }
            if let Some(instructions) = reading.instructions {
                hardware.instructions_begin = instructions;
                hardware.has_instructions = true;
            }
        }
        hardware
    }

    fn finish(&mut self) {
        if let Some(reading) = crate::hardware::span_counter_reading() {
            if self.has_cycles {
                if let Some(cycles) = reading.cycles {
                    self.cycles_end = cycles;
                }
            }
            if self.has_instructions {
                if let Some(instructions) = reading.instructions {
                    self.instructions_end = instructions;
                }
            }
        }
        self.finished = true;
    }

    fn into_evidence(self) -> Evidence<crate::hardware::SpanHardwareV2> {
        if !self.finished || (!self.has_cycles && !self.has_instructions) {
            return Evidence::unavailable(EvidenceGap::Unavailable);
        }
        let pair = |present: bool, begin: u64, end: u64| {
            if present {
                (Evidence::recorded(begin), Evidence::recorded(end))
            } else {
                (
                    Evidence::unavailable(EvidenceGap::Unsupported),
                    Evidence::unavailable(EvidenceGap::Unsupported),
                )
            }
        };
        let (cycles_begin, cycles_end) = pair(self.has_cycles, self.cycles_begin, self.cycles_end);
        let (instructions_begin, instructions_end) = pair(
            self.has_instructions,
            self.instructions_begin,
            self.instructions_end,
        );
        Evidence::recorded(crate::hardware::SpanHardwareV2 {
            version: crate::hardware::SPAN_HARDWARE_V2_VERSION,
            cycles_begin,
            cycles_end,
            instructions_begin,
            instructions_end,
        })
    }
}

struct PendingQueueEnqueue {
    thread_id: u64,
    elapsed_ns: u64,
}

struct WorkerShard {
    sequence: u64,
    elapsed_ns: [AtomicU64; STAGE_COUNT],
    calls: [AtomicU64; STAGE_COUNT],
    attributed_ns: [AtomicU64; STAGE_COUNT],
    blocked_ns: [AtomicU64; STAGE_COUNT],
    blocked_calls: [AtomicU64; STAGE_COUNT],
    legacy_elapsed_ns: [AtomicU64; STAGE_COUNT],
    legacy_calls: [AtomicU64; STAGE_COUNT],
    legacy_attributed_ns: [AtomicU64; STAGE_COUNT],
    latency_buckets: [[AtomicU64; LATENCY_BUCKET_COUNT]; STAGE_COUNT],
    latency_min_ns: [AtomicU64; STAGE_COUNT],
    latency_max_ns: [AtomicU64; STAGE_COUNT],
    counter_values: [AtomicU64; crate::MetricId::COUNT],
    input_bytes: AtomicU64,
    input_units: AtomicU64,
    legacy_input_bytes: AtomicU64,
    legacy_input_units: AtomicU64,
    derived_decoder_bytes: AtomicU64,
    backend_dispatched_bytes: AtomicU64,
    stage_first_start_ns: [AtomicU64; STAGE_COUNT],
    stage_last_end_ns: [AtomicU64; STAGE_COUNT],
    stage_bytes: [AtomicU64; STAGE_COUNT],
    serial_ns: [AtomicU64; STAGE_COUNT],
    serial_calls: [AtomicU64; STAGE_COUNT],
    top_level_busy_ns: AtomicU64,
    top_level_blocked_ns: AtomicU64,
    top_level_calls: AtomicU64,
    cache_hits: [AtomicU64; crate::CacheId::COUNT],
    cache_misses: [AtomicU64; crate::CacheId::COUNT],
    indexed_counters: [[AtomicU64; crate::INDEXED_COUNTER_SLOTS]; crate::IndexedCounterId::COUNT],
    indexed_counter_dropped: AtomicU64,
    retries: [AtomicU64; crate::RetryCause::COUNT],
}

const fn zero_counters() -> [AtomicU64; STAGE_COUNT] {
    [const { AtomicU64::new(0) }; STAGE_COUNT]
}

const fn zero_indexed_counters(
) -> [[AtomicU64; crate::INDEXED_COUNTER_SLOTS]; crate::IndexedCounterId::COUNT] {
    [const { [const { AtomicU64::new(0) }; crate::INDEXED_COUNTER_SLOTS] };
        crate::IndexedCounterId::COUNT]
}

const fn zero_event_values() -> [AtomicU64; crate::EventId::COUNT] {
    [const { AtomicU64::new(0) }; crate::EventId::COUNT]
}

const fn zero_metric_values() -> [AtomicU64; crate::MetricId::COUNT] {
    [const { AtomicU64::new(0) }; crate::MetricId::COUNT]
}

const GAUGE_PRESENT_WORDS: usize = (crate::MetricId::COUNT + 63) / 64;

const fn zero_latency_buckets() -> [[AtomicU64; LATENCY_BUCKET_COUNT]; STAGE_COUNT] {
    [const { [const { AtomicU64::new(0) }; LATENCY_BUCKET_COUNT] }; STAGE_COUNT]
}

const fn max_counters() -> [AtomicU64; STAGE_COUNT] {
    [const { AtomicU64::new(u64::MAX) }; STAGE_COUNT]
}

const fn zero_cache_counters() -> [AtomicU64; crate::CacheId::COUNT] {
    [const { AtomicU64::new(0) }; crate::CacheId::COUNT]
}

impl WorkerShard {
    fn new(sequence: u64) -> Self {
        Self {
            sequence,
            elapsed_ns: zero_counters(),
            calls: zero_counters(),
            attributed_ns: zero_counters(),
            blocked_ns: zero_counters(),
            blocked_calls: zero_counters(),
            legacy_elapsed_ns: zero_counters(),
            legacy_calls: zero_counters(),
            legacy_attributed_ns: zero_counters(),
            latency_buckets: zero_latency_buckets(),
            latency_min_ns: max_counters(),
            latency_max_ns: zero_counters(),
            counter_values: zero_metric_values(),
            input_bytes: AtomicU64::new(0),
            input_units: AtomicU64::new(0),
            legacy_input_bytes: AtomicU64::new(0),
            legacy_input_units: AtomicU64::new(0),
            derived_decoder_bytes: AtomicU64::new(0),
            backend_dispatched_bytes: AtomicU64::new(0),
            stage_first_start_ns: max_counters(),
            stage_last_end_ns: zero_counters(),
            stage_bytes: zero_counters(),
            serial_ns: zero_counters(),
            serial_calls: zero_counters(),
            top_level_busy_ns: AtomicU64::new(0),
            top_level_blocked_ns: AtomicU64::new(0),
            top_level_calls: AtomicU64::new(0),
            cache_hits: zero_cache_counters(),
            cache_misses: zero_cache_counters(),
            indexed_counters: zero_indexed_counters(),
            indexed_counter_dropped: AtomicU64::new(0),
            retries: [const { AtomicU64::new(0) }; crate::RetryCause::COUNT],
        }
    }
}

fn percentile_upper_bound(
    buckets: &[LatencyBucketV2],
    call_count: u64,
    percentile: u64,
    maximum_ns: u64,
) -> u64 {
    let rank = (u128::from(call_count) * u128::from(percentile)).div_ceil(100);
    let mut cumulative = 0_u128;
    for bucket in buckets {
        cumulative += u128::from(bucket.count);
        if cumulative >= rank {
            return bucket.upper_bound_ns.min(maximum_ns);
        }
    }
    maximum_ns
}

#[inline]
fn latency_bucket_index(elapsed_ns: u64) -> usize {
    if elapsed_ns == 0 {
        0
    } else {
        (u64::BITS - elapsed_ns.leading_zeros()) as usize
    }
}

fn latency_bucket_bounds(index: usize) -> (u64, u64) {
    match index {
        0 => (0, 0),
        64 => (1_u64 << 63, u64::MAX),
        _ => (1_u64 << (index - 1), (1_u64 << index) - 1),
    }
}

pub(crate) struct RawStageCounters {
    pub(crate) elapsed_ns: [u64; STAGE_COUNT],
    pub(crate) calls: [u64; STAGE_COUNT],
    pub(crate) attributed_ns: [u64; STAGE_COUNT],
}

static ACTIVE_CONTEXTS: AtomicUsize = AtomicUsize::new(0);
static NEXT_THREAD_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_CONTEXT_ID: AtomicU64 = AtomicU64::new(1);

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

    fn legacy() -> Self {
        Self {
            inner: Arc::new(RuntimeInner::new(false, Instant::now())),
        }
    }

    fn worker_shard(&self) -> Option<Arc<WorkerShard>> {
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

    fn enter_async_parent(&self, span_id: u64) -> Option<AsyncParentGuard> {
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

    fn elapsed_ns(&self) -> u64 {
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

    fn record_distribution(&self, metric_id: crate::MetricId, value: u64) {
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

    fn record_event(&self, event_id: crate::EventId, value: u64) -> bool {
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

    fn record_sampled_event(
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
        let retained = policy.selects(observation)
            && self.inner.session_sample_retained[index]
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |retained| {
                    (retained < policy.maximum_retained).then_some(retained + 1)
                })
                .is_ok();
        if retained {
            self.record_event(event_id, value)
        } else {
            self.inner
                .session_sampled_out_events
                .fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    fn record_annotation(&self, annotation_id: crate::AnnotationId, value: u64) {
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

    fn current_parent(&self) -> (Option<usize>, u64) {
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

    fn current_parent_span_id(&self) -> u64 {
        self.current_parent().1
    }

    fn reserve_span(
        &self,
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
        let span_id = self
            .inner
            .session_span_sequence
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
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

    fn begin_span_with(
        &self,
        stage: Stage,
        started: Instant,
        parent_span_id: u64,
        parent_slot: Option<usize>,
        worker_id: u64,
    ) -> (Option<SpanTrace>, Option<usize>) {
        let stack_slot = ACTIVE_SPANS.with(|stack| stack.borrow().iter().position(Option::is_none));
        let Some(stack_slot) = stack_slot else {
            self.inner
                .session_dropped_spans
                .fetch_add(1, Ordering::Relaxed);
            return (None, None);
        };
        let trace = self.reserve_span(stage, started, parent_span_id, Some(stack_slot), worker_id);
        let runtime_key = Arc::as_ptr(&self.inner) as usize;
        let span_id = trace.as_ref().map_or(0, |t| t.span_id);
        ACTIVE_SPANS.with(|stack| {
            stack.borrow_mut()[stack_slot] = Some(ActiveSpan {
                runtime_key,
                span_id,
                child_elapsed_ns: 0,
                parent_slot,
            });
        });
        (trace, Some(stack_slot))
    }

    fn pop_active_span(&self, stack_slot: Option<usize>, elapsed_ns: u64) -> u64 {
        let Some(stack_slot) = stack_slot else {
            return elapsed_ns;
        };
        let runtime_key = Arc::as_ptr(&self.inner) as usize;
        let child_elapsed_ns = ACTIVE_SPANS.with(|stack| {
            let mut stack = stack.borrow_mut();
            if let Some(active) = stack[stack_slot].take() {
                if active.runtime_key == runtime_key {
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
    fn begin_async_span(
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

    fn record(&self, shard: Option<&WorkerShard>, stage: Stage, outcome: SpanOutcome) {
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
            // Blocked wait is never attributed execution.
            if !outcome.blocked {
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
            return;
        }
        self.inner.elapsed_ns[index].fetch_add(elapsed_ns, Ordering::Relaxed);
        self.inner.calls[index].fetch_add(1, Ordering::Relaxed);
        if !outcome.blocked {
            self.inner.attributed_ns[index].fetch_add(self_ns, Ordering::Relaxed);
        }
    }

    fn add_stage_bytes(&self, stage: Stage, bytes: u64) {
        if let Some(shard) = self.worker_shard() {
            shard.stage_bytes[stage.index()].fetch_add(bytes, Ordering::Relaxed);
        }
    }

    fn record_cache_outcome(&self, cache: crate::CacheId, hit: bool) {
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

    fn record_retry(&self, cause: crate::RetryCause) {
        if let Some(shard) = self.worker_shard() {
            shard.retries[cause.index()].fetch_add(1, Ordering::Relaxed);
        }
    }

    fn add_indexed_counter(&self, counter: crate::IndexedCounterId, slot: u16, delta: u64) {
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

    fn add_input_bytes(&self, bytes: u64) {
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

    fn add_input_units(&self, units: u64) {
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

    fn add_derived_decoder_bytes(&self, bytes: u64) {
        if let Some(shard) = self.worker_shard() {
            shard
                .derived_decoder_bytes
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }

    fn add_backend_dispatched_bytes(&self, bytes: u64) {
        if let Some(shard) = self.worker_shard() {
            shard
                .backend_dispatched_bytes
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub(crate) fn drain_stage_counters(&self, session: bool) -> RawStageCounters {
        if !session && !self.inner.session_recording {
            return RawStageCounters {
                elapsed_ns: std::array::from_fn(|index| {
                    self.inner.elapsed_ns[index].swap(0, Ordering::Relaxed)
                }),
                calls: std::array::from_fn(|index| {
                    self.inner.calls[index].swap(0, Ordering::Relaxed)
                }),
                attributed_ns: std::array::from_fn(|index| {
                    self.inner.attributed_ns[index].swap(0, Ordering::Relaxed)
                }),
            };
        }
        let shards = self.inner.sorted_shards();
        if !session {
            return RawStageCounters {
                elapsed_ns: std::array::from_fn(|index| {
                    shards.iter().fold(0_u64, |total, shard| {
                        total.saturating_add(
                            shard.legacy_elapsed_ns[index].swap(0, Ordering::Relaxed),
                        )
                    })
                }),
                calls: std::array::from_fn(|index| {
                    shards.iter().fold(0_u64, |total, shard| {
                        total.saturating_add(shard.legacy_calls[index].swap(0, Ordering::Relaxed))
                    })
                }),
                attributed_ns: std::array::from_fn(|index| {
                    shards.iter().fold(0_u64, |total, shard| {
                        total.saturating_add(
                            shard.legacy_attributed_ns[index].swap(0, Ordering::Relaxed),
                        )
                    })
                }),
            };
        }
        RawStageCounters {
            elapsed_ns: std::array::from_fn(|index| {
                shards.iter().fold(0_u64, |total, shard| {
                    total.saturating_add(shard.elapsed_ns[index].swap(0, Ordering::Relaxed))
                })
            }),
            calls: std::array::from_fn(|index| {
                shards.iter().fold(0_u64, |total, shard| {
                    total.saturating_add(shard.calls[index].swap(0, Ordering::Relaxed))
                })
            }),
            attributed_ns: std::array::from_fn(|index| {
                shards.iter().fold(0_u64, |total, shard| {
                    total.saturating_add(shard.attributed_ns[index].swap(0, Ordering::Relaxed))
                })
            }),
        }
    }

    fn take_input_totals(&self) -> (u64, u64) {
        if !self.inner.session_recording {
            return (
                self.inner.input_bytes.swap(0, Ordering::Relaxed),
                self.inner.input_units.swap(0, Ordering::Relaxed),
            );
        }
        let shards = self.inner.sorted_shards();
        shards.iter().fold((0_u64, 0_u64), |totals, shard| {
            (
                totals
                    .0
                    .saturating_add(shard.legacy_input_bytes.swap(0, Ordering::Relaxed)),
                totals
                    .1
                    .saturating_add(shard.legacy_input_units.swap(0, Ordering::Relaxed)),
            )
        })
    }

    pub(crate) fn take_session_input_totals(&self) -> (u64, u64) {
        let shards = self.inner.sorted_shards();
        shards.iter().fold((0_u64, 0_u64), |totals, shard| {
            (
                totals
                    .0
                    .saturating_add(shard.input_bytes.swap(0, Ordering::Relaxed)),
                totals
                    .1
                    .saturating_add(shard.input_units.swap(0, Ordering::Relaxed)),
            )
        })
    }

    pub(crate) fn take_session_workload_totals(&self) -> (u64, u64) {
        let shards = self.inner.sorted_shards();
        shards.iter().fold((0_u64, 0_u64), |totals, shard| {
            (
                totals
                    .0
                    .saturating_add(shard.derived_decoder_bytes.swap(0, Ordering::Relaxed)),
                totals
                    .1
                    .saturating_add(shard.backend_dispatched_bytes.swap(0, Ordering::Relaxed)),
            )
        })
    }

    fn record_batch_route(
        &self,
        workload_key_digest: &str,
        requested_backend: &str,
        selected_backend: &str,
        completed_backend: &str,
        recovered_from_backend: Option<&str>,
    ) {
        if !self.inner.session_recording {
            return;
        }
        let batch_sequence = self
            .inner
            .session_route_sequence
            .fetch_add(1, Ordering::Relaxed);
        self.record_event(crate::EventId::BackendBatchCompleted, batch_sequence);
        if recovered_from_backend.is_some() {
            self.record_event(crate::EventId::BackendRecovered, batch_sequence);
        }
        let record = BatchRouteV2 {
            version: 1,
            batch_sequence,
            workload_key_digest: workload_key_digest.to_owned(),
            requested_backend: requested_backend.to_owned(),
            selected_backend: selected_backend.to_owned(),
            completed_backend: completed_backend.to_owned(),
            recovered_from_backend: recovered_from_backend.map_or_else(
                || Evidence::unavailable(crate::schema_v2::EvidenceGap::Unavailable),
                |backend| Evidence::recorded(backend.to_owned()),
            ),
        };
        let mut records = match self.inner.session_batch_routes.lock() {
            Ok(records) => records,
            Err(poisoned) => poisoned.into_inner(),
        };
        if records.len() >= MAX_BATCH_ROUTES {
            self.inner
                .session_dropped_batch_routes
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        records.push(record);
    }

    /// Drain completed batch-route records from this profiling runtime.
    pub fn take_session_batch_routes(&self) -> Vec<BatchRouteV2> {
        let mut records = match self.inner.session_batch_routes.lock() {
            Ok(records) => records,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut drained = std::mem::take(&mut *records);
        drained.sort_unstable_by_key(|record| record.batch_sequence);
        drained
    }

    /// Drain the count of batch routes dropped after [`MAX_BATCH_ROUTES`].
    pub fn take_session_dropped_batch_routes(&self) -> u64 {
        self.inner
            .session_dropped_batch_routes
            .swap(0, Ordering::Relaxed)
    }

    fn record_queue_enqueue(&self, queue: crate::QueueId, sequence: u64) {
        if !self.inner.session_recording {
            return;
        }
        let enqueue = PendingQueueEnqueue {
            thread_id: numeric_thread_id(),
            elapsed_ns: self.elapsed_ns(),
        };
        let mut pending = match self.inner.queue_pending.lock() {
            Ok(pending) => pending,
            Err(poisoned) => poisoned.into_inner(),
        };
        if pending.len() == MAX_QUEUE_LINKS && !pending.contains_key(&(queue as u8, sequence)) {
            self.inner
                .queue_dropped_enqueues
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        if pending.insert((queue as u8, sequence), enqueue).is_some() {
            // A duplicate (queue, sequence) enqueue displaces the earlier record.
            self.inner
                .queue_dropped_enqueues
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_queue_dequeue(&self, queue: crate::QueueId, sequence: u64) {
        if !self.inner.session_recording {
            return;
        }
        let enqueue = {
            let mut pending = match self.inner.queue_pending.lock() {
                Ok(pending) => pending,
                Err(poisoned) => poisoned.into_inner(),
            };
            pending.remove(&(queue as u8, sequence))
        };
        let Some(enqueue) = enqueue else {
            self.inner
                .queue_unmatched_dequeues
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        let link = QueueLinkV2 {
            version: 1,
            queue,
            sequence,
            producer_thread_id: enqueue.thread_id,
            producer_elapsed_ns: enqueue.elapsed_ns,
            consumer_thread_id: numeric_thread_id(),
            consumer_elapsed_ns: self.elapsed_ns(),
        };
        let mut links = match self.inner.queue_links.lock() {
            Ok(links) => links,
            Err(poisoned) => poisoned.into_inner(),
        };
        if links.len() == MAX_QUEUE_LINKS {
            self.inner
                .queue_dropped_links
                .fetch_add(1, Ordering::Relaxed);
        } else {
            links.push(link);
        }
    }

    /// Drain matched queue links in stable (queue, sequence) order with exact loss counts.
    pub fn take_session_queue_links(&self) -> (Vec<QueueLinkV2>, QueueLinkLossCounts) {
        let mut links = match self.inner.queue_links.lock() {
            Ok(links) => links,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut links = std::mem::take(&mut *links);
        links.sort_unstable_by_key(|link| (link.queue, link.sequence));
        let unconsumed = {
            let mut pending = match self.inner.queue_pending.lock() {
                Ok(pending) => pending,
                Err(poisoned) => poisoned.into_inner(),
            };
            let pending = std::mem::take(&mut *pending);
            u64::try_from(pending.len()).unwrap_or(u64::MAX)
        };
        let loss = QueueLinkLossCounts {
            dropped_enqueues: self.inner.queue_dropped_enqueues.swap(0, Ordering::Relaxed),
            dropped_links: self.inner.queue_dropped_links.swap(0, Ordering::Relaxed),
            unmatched_dequeues: self
                .inner
                .queue_unmatched_dequeues
                .swap(0, Ordering::Relaxed),
            unconsumed_enqueues: unconsumed,
        };
        (links, loss)
    }

    fn queue_depth_enqueue(&self, queue: crate::QueueId) {
        if !self.inner.session_recording {
            return;
        }
        let index = queue.index();
        let depth = self.inner.queue_depth_current[index].fetch_add(1, Ordering::Relaxed) + 1;
        self.inner.queue_depth_high_water[index].fetch_max(depth, Ordering::Relaxed);
        self.inner.queue_depth_enqueues[index].fetch_add(1, Ordering::Relaxed);
    }

    fn queue_depth_dequeue(&self, queue: crate::QueueId) {
        if !self.inner.session_recording {
            return;
        }
        let index = queue.index();
        let _ = self.inner.queue_depth_current[index].fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |depth| Some(depth.saturating_sub(1)),
        );
        self.inner.queue_depth_dequeues[index].fetch_add(1, Ordering::Relaxed);
    }

    fn set_queue_depth(&self, queue: crate::QueueId, depth: u64) {
        if !self.inner.session_recording {
            return;
        }
        let index = queue.index();
        self.inner.queue_depth_current[index].store(depth, Ordering::Relaxed);
        self.inner.queue_depth_high_water[index].fetch_max(depth, Ordering::Relaxed);
    }

    /// Drain queue depth occupancy and high-water records in stable queue order.
    ///
    /// The current depth is reported without being reset; the high-water mark
    /// restarts from the current depth and the enqueue/dequeue totals reset.
    pub fn take_session_queue_depths(&self) -> Vec<QueueDepthV2> {
        if !self.inner.session_recording {
            return Vec::new();
        }
        crate::QueueId::ALL
            .into_iter()
            .filter_map(|queue| {
                let index = queue.index();
                let current = self.inner.queue_depth_current[index].load(Ordering::Relaxed);
                let high_water =
                    self.inner.queue_depth_high_water[index].swap(current, Ordering::Relaxed);
                let enqueues = self.inner.queue_depth_enqueues[index].swap(0, Ordering::Relaxed);
                let dequeues = self.inner.queue_depth_dequeues[index].swap(0, Ordering::Relaxed);
                (current != 0 || high_water != 0 || enqueues != 0 || dequeues != 0).then_some(
                    QueueDepthV2 {
                        version: 1,
                        queue,
                        current,
                        high_water,
                        enqueues,
                        dequeues,
                    },
                )
            })
            .collect()
    }

    /// Drain per-worker load and imbalance evidence merged in sorted shard order.
    ///
    /// This drains the same per-stage call and elapsed counters as
    /// `take_session_stage_measurements`; call it once at session drain.
    pub fn take_session_worker_imbalance(&self) -> WorkerImbalanceV2 {
        let shards = self.inner.sorted_shards();
        let workers: Vec<WorkerLoadV2> = shards
            .iter()
            .map(|shard| {
                let mut calls = 0_u64;
                let mut elapsed_ns = 0_u64;
                for index in 0..STAGE_COUNT {
                    calls = calls.saturating_add(shard.calls[index].swap(0, Ordering::Relaxed));
                    elapsed_ns = elapsed_ns
                        .saturating_add(shard.elapsed_ns[index].swap(0, Ordering::Relaxed));
                }
                WorkerLoadV2 {
                    version: 1,
                    worker_id: shard.sequence,
                    calls,
                    elapsed_ns,
                }
            })
            .collect();
        let worker_count = u64::try_from(workers.len()).unwrap_or(u64::MAX);
        let total_calls = workers
            .iter()
            .fold(0_u64, |total, worker| total.saturating_add(worker.calls));
        let total_elapsed_ns = workers.iter().fold(0_u64, |total, worker| {
            total.saturating_add(worker.elapsed_ns)
        });
        let ppm = |part: u64, whole: u64| -> u64 {
            if whole == 0 {
                0
            } else {
                u64::try_from((u128::from(part) * 1_000_000) / u128::from(whole))
                    .unwrap_or(u64::MAX)
            }
        };
        let max_calls = workers.iter().map(|worker| worker.calls).max().unwrap_or(0);
        let mut sorted_calls: Vec<u64> = workers.iter().map(|worker| worker.calls).collect();
        sorted_calls.sort_unstable();
        let median_calls = if sorted_calls.is_empty() {
            0
        } else {
            sorted_calls[sorted_calls.len() / 2]
        };
        let idle_workers = workers.iter().filter(|worker| worker.calls == 0).count() as u64;
        WorkerImbalanceV2 {
            version: 1,
            worker_count,
            total_calls,
            total_elapsed_ns,
            max_share_ppm: ppm(max_calls, total_calls),
            median_share_ppm: ppm(median_calls, total_calls),
            idle_share_ppm: ppm(idle_workers, worker_count),
            workers,
        }
    }

    /// Drain blocked-wait records merged in sorted shard order.
    pub fn take_session_blocked_waits(&self) -> Vec<BlockedWaitRecordV2> {
        let shards = self.inner.sorted_shards();
        Stage::ALL
            .into_iter()
            .filter_map(|stage| {
                let index = stage.index();
                let calls = shards.iter().fold(0_u64, |total, shard| {
                    total.saturating_add(shard.blocked_calls[index].swap(0, Ordering::Relaxed))
                });
                if calls == 0 {
                    return None;
                }
                let blocked_ns = shards.iter().fold(0_u64, |total, shard| {
                    total.saturating_add(shard.blocked_ns[index].swap(0, Ordering::Relaxed))
                });
                Some(BlockedWaitRecordV2 {
                    version: 1,
                    metric_id: stage.metric_id(),
                    macro_stage_id: stage.macro_stage_id(),
                    calls,
                    blocked_ns,
                })
            })
            .collect()
    }

    /// Offset of one instant from this runtime's start, saturating at zero.
    fn offset_ns(&self, at: Instant) -> u64 {
        u64::try_from(
            at.checked_duration_since(self.inner.started)
                .unwrap_or_default()
                .as_nanos(),
        )
        .unwrap_or(u64::MAX)
    }

    /// Drain per-micro-function wall-clock occupancy merged across workers.
    ///
    /// Call this before `Session::finish`, which drains the shared per-stage
    /// call and elapsed counters this record reads.
    pub fn take_session_stage_concurrency(&self) -> Vec<StageConcurrencyV2> {
        let shards = self.inner.sorted_shards();
        Stage::ALL
            .into_iter()
            .filter_map(|stage| {
                let index = stage.index();
                let mut calls = 0_u64;
                let mut elapsed_ns = 0_u64;
                let mut max_worker_elapsed_ns = 0_u64;
                let mut worker_count = 0_u64;
                let mut first_start_ns = u64::MAX;
                let mut last_end_ns = 0_u64;
                let mut declared_serial_ns = 0_u64;
                let mut declared_serial_calls = 0_u64;
                let mut bytes = 0_u64;
                for shard in &shards {
                    let shard_calls = shard.calls[index].load(Ordering::Relaxed);
                    let shard_elapsed = shard.elapsed_ns[index].load(Ordering::Relaxed);
                    if shard_calls != 0 {
                        worker_count += 1;
                    }
                    calls = calls.saturating_add(shard_calls);
                    elapsed_ns = elapsed_ns.saturating_add(shard_elapsed);
                    max_worker_elapsed_ns = max_worker_elapsed_ns.max(shard_elapsed);
                    first_start_ns = first_start_ns
                        .min(shard.stage_first_start_ns[index].load(Ordering::Relaxed));
                    last_end_ns =
                        last_end_ns.max(shard.stage_last_end_ns[index].load(Ordering::Relaxed));
                    declared_serial_ns = declared_serial_ns
                        .saturating_add(shard.serial_ns[index].swap(0, Ordering::Relaxed));
                    declared_serial_calls = declared_serial_calls
                        .saturating_add(shard.serial_calls[index].swap(0, Ordering::Relaxed));
                    bytes =
                        bytes.saturating_add(shard.stage_bytes[index].swap(0, Ordering::Relaxed));
                }
                if calls == 0 {
                    return None;
                }
                let first_start_ns = if first_start_ns == u64::MAX {
                    0
                } else {
                    first_start_ns
                };
                let window_ns = last_end_ns.saturating_sub(first_start_ns);
                // A window of zero means every call fell inside one clock tick;
                // report the calls as serial rather than inventing concurrency.
                // A stage entered recursively on one thread sums its nested
                // time, so raw elapsed can exceed the wall the thread spent
                // there. Average concurrency can never exceed the number of
                // workers that entered the stage, so cap it there rather than
                // report a single-threaded recursion as parallel.
                let ceiling_milli = worker_count.saturating_mul(1_000);
                let concurrency_milli = if window_ns == 0 {
                    1_000
                } else {
                    u64::try_from((u128::from(elapsed_ns) * 1_000) / u128::from(window_ns))
                        .unwrap_or(u64::MAX)
                        .min(ceiling_milli)
                };
                Some(StageConcurrencyV2 {
                    version: crate::schema_v2::STAGE_CONCURRENCY_V2_VERSION,
                    metric_id: stage.metric_id(),
                    macro_stage_id: stage.macro_stage_id(),
                    calls,
                    elapsed_ns,
                    window_ns,
                    first_start_ns,
                    last_end_ns,
                    worker_count,
                    max_worker_elapsed_ns,
                    concurrency_milli,
                    declared_serial_ns,
                    declared_serial_calls,
                    bytes,
                })
            })
            .collect()
    }

    /// Drain per-worker busy and blocked time merged in sorted shard order.
    pub fn take_session_worker_occupancy(&self) -> WorkerOccupancyV2 {
        let shards = self.inner.sorted_shards();
        let workers: Vec<WorkerOccupancyRowV2> = shards
            .iter()
            .map(|shard| WorkerOccupancyRowV2 {
                version: crate::schema_v2::WORKER_OCCUPANCY_V2_VERSION,
                worker_id: shard.sequence,
                busy_ns: shard.top_level_busy_ns.swap(0, Ordering::Relaxed),
                blocked_ns: shard.top_level_blocked_ns.swap(0, Ordering::Relaxed),
                calls: shard.top_level_calls.swap(0, Ordering::Relaxed),
            })
            .collect();
        let busy_ns = workers
            .iter()
            .fold(0_u64, |total, worker| total.saturating_add(worker.busy_ns));
        let blocked_ns = workers.iter().fold(0_u64, |total, worker| {
            total.saturating_add(worker.blocked_ns)
        });
        let calls = workers
            .iter()
            .fold(0_u64, |total, worker| total.saturating_add(worker.calls));
        let mut sorted_busy: Vec<u64> = workers.iter().map(|worker| worker.busy_ns).collect();
        sorted_busy.sort_unstable();
        let median_busy_ns = sorted_busy
            .get(sorted_busy.len() / 2)
            .copied()
            .unwrap_or_default();
        WorkerOccupancyV2 {
            version: crate::schema_v2::WORKER_OCCUPANCY_V2_VERSION,
            worker_count: u64::try_from(workers.len()).unwrap_or(u64::MAX),
            active_worker_count: workers.iter().filter(|worker| worker.calls != 0).count() as u64,
            busy_ns,
            blocked_ns,
            calls,
            busiest_busy_ns: sorted_busy.last().copied().unwrap_or_default(),
            median_busy_ns,
            workers,
        }
    }

    /// Drain reuse-cache hit and miss counts merged in sorted shard order.
    pub fn take_session_cache_effectiveness(&self) -> Vec<CacheEffectivenessV2> {
        let shards = self.inner.sorted_shards();
        crate::CacheId::ALL
            .into_iter()
            .filter_map(|cache| {
                let index = cache.index();
                let mut hits = 0_u64;
                let mut misses = 0_u64;
                for shard in &shards {
                    hits = hits.saturating_add(shard.cache_hits[index].swap(0, Ordering::Relaxed));
                    misses =
                        misses.saturating_add(shard.cache_misses[index].swap(0, Ordering::Relaxed));
                }
                let total = hits.saturating_add(misses);
                if total == 0 {
                    return None;
                }
                Some(CacheEffectivenessV2 {
                    version: crate::schema_v2::CACHE_EFFECTIVENESS_V2_VERSION,
                    cache,
                    hits,
                    misses,
                    hit_rate_ppm: u64::try_from((u128::from(hits) * 1_000_000) / u128::from(total))
                        .unwrap_or(u64::MAX),
                })
            })
            .collect()
    }

    /// Drain retry attempts by cause, merged in sorted shard order.
    pub fn take_session_retries(&self) -> Vec<RetryRecordV2> {
        let shards = self.inner.sorted_shards();
        crate::RetryCause::ALL
            .into_iter()
            .filter_map(|cause| {
                let attempts = shards.iter().fold(0_u64, |total, shard| {
                    total.saturating_add(shard.retries[cause.index()].swap(0, Ordering::Relaxed))
                });
                (attempts != 0).then_some(RetryRecordV2 {
                    version: crate::schema_v2::RETRY_RECORD_V2_VERSION,
                    cause,
                    attempts,
                })
            })
            .collect()
    }

    /// Drain indexed counter families merged in sorted shard order.
    pub fn take_session_indexed_counters(&self) -> Vec<IndexedCounterRecordV2> {
        let shards = self.inner.sorted_shards();
        let dropped_out_of_range = shards.iter().fold(0_u64, |total, shard| {
            total.saturating_add(shard.indexed_counter_dropped.swap(0, Ordering::Relaxed))
        });
        crate::IndexedCounterId::ALL
            .into_iter()
            .filter_map(|counter| {
                let index = counter.index();
                let mut slots = [0_u64; crate::INDEXED_COUNTER_SLOTS];
                for shard in &shards {
                    for (slot, total) in slots.iter_mut().enumerate() {
                        *total = total.saturating_add(
                            shard.indexed_counters[index][slot].swap(0, Ordering::Relaxed),
                        );
                    }
                }
                if slots.iter().all(|value| *value == 0) && dropped_out_of_range == 0 {
                    return None;
                }
                Some(IndexedCounterRecordV2 {
                    version: crate::schema_v2::INDEXED_COUNTER_V2_VERSION,
                    counter,
                    slots: slots.to_vec(),
                    dropped_out_of_range,
                })
            })
            .collect()
    }

    /// Discard every per-run accumulator this runtime owns.
    ///
    /// Benchmarks call this between measured rounds to drop warm-up, so
    /// anything left behind is reported as part of the next round. That makes
    /// a partial reset a wrong number presented as a right one, which is why
    /// this clears the per-worker shards as well as the runtime-level stores.
    fn reset(&self) {
        // Session drains clear their own storage; the legacy drain clears the
        // legacy mirrors. Both are needed because a session runtime keeps two.
        let _ = self.drain_stage_counters(false);
        let _ = self.drain_stage_counters(true);
        let _ = self.take_session_worker_occupancy();
        let _ = self.take_session_blocked_waits();
        let _ = self.take_session_stage_concurrency();
        let _ = self.take_session_cache_effectiveness();
        let _ = self.take_session_indexed_counters();
        let _ = self.take_session_retries();
        let _ = self.take_session_queue_depths();
        self.inner.input_bytes.store(0, Ordering::Relaxed);
        self.inner.input_units.store(0, Ordering::Relaxed);
        for index in 0..crate::MetricId::COUNT {
            self.inner.legacy_typed_counters[index].store(0, Ordering::Relaxed);
            self.inner.distribution_min[index].store(u64::MAX, Ordering::Relaxed);
            self.inner.distribution_max[index].store(0, Ordering::Relaxed);
            for bucket in 0..LATENCY_BUCKET_COUNT {
                self.inner.distribution_buckets[index][bucket].store(0, Ordering::Relaxed);
            }
        }
        for shard in self.inner.sorted_shards() {
            shard.input_bytes.store(0, Ordering::Relaxed);
            shard.input_units.store(0, Ordering::Relaxed);
            shard.legacy_input_bytes.store(0, Ordering::Relaxed);
            shard.legacy_input_units.store(0, Ordering::Relaxed);
            shard.derived_decoder_bytes.store(0, Ordering::Relaxed);
            shard.backend_dispatched_bytes.store(0, Ordering::Relaxed);
            for index in 0..crate::MetricId::COUNT {
                shard.counter_values[index].store(0, Ordering::Relaxed);
            }
            for index in 0..STAGE_COUNT {
                shard.latency_min_ns[index].store(u64::MAX, Ordering::Relaxed);
                shard.latency_max_ns[index].store(0, Ordering::Relaxed);
                shard.stage_first_start_ns[index].store(u64::MAX, Ordering::Relaxed);
                shard.stage_last_end_ns[index].store(0, Ordering::Relaxed);
                for bucket in 0..LATENCY_BUCKET_COUNT {
                    shard.latency_buckets[index][bucket].store(0, Ordering::Relaxed);
                }
            }
        }
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread context guard returned by [`Runtime::enter`].
pub struct ContextGuard {
    runtime: Runtime,
    not_send: PhantomData<Rc<()>>,
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

struct AsyncParentGuard {
    runtime_key: usize,
    span_id: u64,
    stack_slot: usize,
    not_send: PhantomData<Rc<()>>,
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

struct LegacyRuntime {
    runtime: Runtime,
    enabled: bool,
}

impl LegacyRuntime {
    fn new() -> Self {
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

thread_local! {
    static CURRENT: RefCell<Vec<Runtime>> = const { RefCell::new(Vec::new()) };
    static WORK_ORIGIN: Cell<WorkOrigin> = const { Cell::new(WorkOrigin::Root) };
    static TASK_ID: Cell<u64> = const { Cell::new(0) };
    static SPAN_DEPTH: Cell<u32> = const { Cell::new(0) };
    static LEGACY: RefCell<LegacyRuntime> = RefCell::new(LegacyRuntime::new());
    static ACTIVE_SPANS: RefCell<[Option<ActiveSpan>; MAX_NESTED_SPANS]> =
        const { RefCell::new([None; MAX_NESTED_SPANS]) };
    static ASYNC_PARENT_SPANS: RefCell<[Option<ActiveSpan>; MAX_NESTED_SPANS]> =
        const { RefCell::new([None; MAX_NESTED_SPANS]) };
    static NUMERIC_THREAD_ID: u64 = NEXT_THREAD_ID.fetch_add(1, Ordering::Relaxed);
    static THREAD_SHARDS: RefCell<Vec<ThreadShardAssignment>> = const { RefCell::new(Vec::new()) };
}

fn numeric_thread_id() -> u64 {
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

fn evidence_or_unavailable(value: u64) -> Evidence<u64> {
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
                self_ns: elapsed_ns,
                blocked: false,
                serial: false,
                outermost: true,
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
    let (trace, stack_slot) = match (runtime.as_ref(), started) {
        (Some(runtime), Some(started)) => {
            let (parent_slot, current_parent_id) = runtime.current_parent();
            let parent_span_id = match parent_override {
                Some(parent) if runtime.context_id() == parent.context_id() => parent.span_id(),
                _ => current_parent_id,
            };
            runtime.begin_span_with(stage, started, parent_span_id, parent_slot, worker_id)
        }
        _ => (None, None),
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
                        self_ns: u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
                        blocked: false,
                        serial: false,
                        outermost: true,
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
        let self_ns = runtime.pop_active_span(self.stack_slot, elapsed_ns);
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
