//! Worker counter shards, span hardware readings, and latency bucket helpers.

use std::sync::atomic::AtomicU64;

use crate::schema_v2::{Evidence, EvidenceGap, LatencyBucketV2, WorkOrigin};
use super::{LATENCY_BUCKET_COUNT, STAGE_COUNT};

#[derive(Clone, Copy)]
pub(super) struct ActiveSpan {
    pub(super) runtime_key: usize,
    pub(super) span_id: u64,
    pub(super) child_elapsed_ns: u64,
    pub(super) parent_slot: Option<usize>,
}

#[derive(Clone, Copy)]
pub(super) struct SpanTrace {
    pub(super) record_index: usize,
    pub(super) span_id: u64,
}

/// One completed span's recording payload, assembled on the guard's drop path.
#[derive(Clone, Copy)]
pub(super) struct SpanOutcome {
    pub(super) start_offset_ns: u64,
    pub(super) elapsed_ns: u64,
    pub(super) self_ns: u64,
    pub(super) blocked: bool,
    pub(super) serial: bool,
    pub(super) outermost: bool,
}

pub(super) struct RawSpanRecord {
    pub(super) span_id: u64,
    pub(super) parent_span_id: u64,
    pub(super) metric_id: crate::MetricId,
    pub(super) start_ns: u64,
    pub(super) inclusive_ns: u64,
    pub(super) thread_id: u64,
    pub(super) worker_id: u64,
    pub(super) task_id: u64,
    pub(super) work_origin: WorkOrigin,
    pub(super) completed: bool,
    pub(super) hardware: RawSpanHardware,
}

/// Raw counter readings captured at span edges; the cold path joins them.
#[derive(Clone, Copy, Default)]
pub(super) struct RawSpanHardware {
    pub(super) cycles_begin: u64,
    pub(super) cycles_end: u64,
    pub(super) instructions_begin: u64,
    pub(super) instructions_end: u64,
    pub(super) has_cycles: bool,
    pub(super) has_instructions: bool,
    pub(super) finished: bool,
}

impl RawSpanHardware {
    pub(super) fn begin() -> Self {
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

    pub(super) fn finish(&mut self) {
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

    pub(super) fn into_evidence(self) -> Evidence<crate::hardware::SpanHardwareV2> {
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

pub(super) struct PendingQueueEnqueue {
    pub(super) thread_id: u64,
    pub(super) elapsed_ns: u64,
}

pub(super) struct WorkerShard {
    pub(super) sequence: u64,
    pub(super) elapsed_ns: [AtomicU64; STAGE_COUNT],
    pub(super) calls: [AtomicU64; STAGE_COUNT],
    pub(super) attributed_ns: [AtomicU64; STAGE_COUNT],
    pub(super) blocked_ns: [AtomicU64; STAGE_COUNT],
    pub(super) blocked_calls: [AtomicU64; STAGE_COUNT],
    pub(super) legacy_elapsed_ns: [AtomicU64; STAGE_COUNT],
    pub(super) legacy_calls: [AtomicU64; STAGE_COUNT],
    pub(super) legacy_attributed_ns: [AtomicU64; STAGE_COUNT],
    pub(super) latency_buckets: [[AtomicU64; LATENCY_BUCKET_COUNT]; STAGE_COUNT],
    pub(super) latency_min_ns: [AtomicU64; STAGE_COUNT],
    pub(super) latency_max_ns: [AtomicU64; STAGE_COUNT],
    pub(super) counter_values: [AtomicU64; crate::MetricId::COUNT],
    pub(super) input_bytes: AtomicU64,
    pub(super) input_units: AtomicU64,
    pub(super) legacy_input_bytes: AtomicU64,
    pub(super) legacy_input_units: AtomicU64,
    pub(super) derived_decoder_bytes: AtomicU64,
    pub(super) backend_dispatched_bytes: AtomicU64,
    pub(super) stage_first_start_ns: [AtomicU64; STAGE_COUNT],
    pub(super) stage_last_end_ns: [AtomicU64; STAGE_COUNT],
    pub(super) stage_bytes: [AtomicU64; STAGE_COUNT],
    pub(super) serial_ns: [AtomicU64; STAGE_COUNT],
    pub(super) serial_calls: [AtomicU64; STAGE_COUNT],
    pub(super) top_level_busy_ns: AtomicU64,
    pub(super) top_level_blocked_ns: AtomicU64,
    pub(super) top_level_calls: AtomicU64,
    pub(super) cache_hits: [AtomicU64; crate::CacheId::COUNT],
    pub(super) cache_misses: [AtomicU64; crate::CacheId::COUNT],
    pub(super) indexed_counters: [[AtomicU64; crate::INDEXED_COUNTER_SLOTS]; crate::IndexedCounterId::COUNT],
    pub(super) indexed_counter_dropped: AtomicU64,
    pub(super) retries: [AtomicU64; crate::RetryCause::COUNT],
    pub(super) compile_surface_invocations:
        [[AtomicU64; crate::CompilePhase::COUNT]; crate::CompileSurfaceId::COUNT],
    pub(super) compile_surface_loads: [AtomicU64; crate::CompileSurfaceId::COUNT],
}

pub(super) const fn zero_counters() -> [AtomicU64; STAGE_COUNT] {
    [const { AtomicU64::new(0) }; STAGE_COUNT]
}

pub(super) const fn zero_indexed_counters(
) -> [[AtomicU64; crate::INDEXED_COUNTER_SLOTS]; crate::IndexedCounterId::COUNT] {
    [const { [const { AtomicU64::new(0) }; crate::INDEXED_COUNTER_SLOTS] };
        crate::IndexedCounterId::COUNT]
}

pub(super) const fn zero_event_values() -> [AtomicU64; crate::EventId::COUNT] {
    [const { AtomicU64::new(0) }; crate::EventId::COUNT]
}

pub(super) const fn zero_metric_values() -> [AtomicU64; crate::MetricId::COUNT] {
    [const { AtomicU64::new(0) }; crate::MetricId::COUNT]
}

pub(super) const GAUGE_PRESENT_WORDS: usize = crate::MetricId::COUNT.div_ceil(64);

pub(super) const fn zero_latency_buckets() -> [[AtomicU64; LATENCY_BUCKET_COUNT]; STAGE_COUNT] {
    [const { [const { AtomicU64::new(0) }; LATENCY_BUCKET_COUNT] }; STAGE_COUNT]
}

pub(super) const fn max_counters() -> [AtomicU64; STAGE_COUNT] {
    [const { AtomicU64::new(u64::MAX) }; STAGE_COUNT]
}

pub(super) const fn zero_cache_counters() -> [AtomicU64; crate::CacheId::COUNT] {
    [const { AtomicU64::new(0) }; crate::CacheId::COUNT]
}
pub(super) const fn zero_compile_surface_invocations(
) -> [[AtomicU64; crate::CompilePhase::COUNT]; crate::CompileSurfaceId::COUNT] {
    [const { [const { AtomicU64::new(0) }; crate::CompilePhase::COUNT] };
        crate::CompileSurfaceId::COUNT]
}

pub(super) const fn zero_compile_surface_loads() -> [AtomicU64; crate::CompileSurfaceId::COUNT] {
    [const { AtomicU64::new(0) }; crate::CompileSurfaceId::COUNT]
}

impl WorkerShard {
    pub(super) fn new(sequence: u64) -> Self {
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
            compile_surface_invocations: zero_compile_surface_invocations(),
            compile_surface_loads: zero_compile_surface_loads(),
        }
    }
}

pub(super) fn percentile_upper_bound(
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
pub(super) fn latency_bucket_index(elapsed_ns: u64) -> usize {
    if elapsed_ns == 0 {
        0
    } else {
        (u64::BITS - elapsed_ns.leading_zeros()) as usize
    }
}

pub(super) fn latency_bucket_bounds(index: usize) -> (u64, u64) {
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
