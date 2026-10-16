//! Session counter drains, concurrency/imbalance synthesis, and runtime reset.

use std::sync::atomic::Ordering;
use std::time::Instant;

use crate::schema::Stage;
use crate::schema_v2::{
    BatchRouteV2, BlockedWaitRecordV2, CacheEffectivenessV2, Evidence,
    IndexedCounterRecordV2, QueueDepthV2, QueueLinkV2, RetryRecordV2, StageConcurrencyV2,
    WorkerImbalanceV2, WorkerLoadV2, WorkerOccupancyRowV2, WorkerOccupancyV2,
};
use super::shard::{PendingQueueEnqueue, RawStageCounters};
use super::{
    numeric_thread_id, QueueLinkLossCounts, Runtime, LATENCY_BUCKET_COUNT,
    MAX_BATCH_ROUTES, MAX_QUEUE_LINKS, STAGE_COUNT,
};

impl Runtime {
    pub fn set_compile_phase(&self, phase: crate::CompilePhase) {
        self.inner
            .active_compile_phase
            .store(phase as u8, Ordering::Relaxed);
    }

    pub fn active_compile_phase(&self) -> crate::CompilePhase {
        match self.inner.active_compile_phase.load(Ordering::Relaxed) {
            0 => crate::CompilePhase::Install,
            1 => crate::CompilePhase::Update,
            2 => crate::CompilePhase::Scan,
            _ => crate::CompilePhase::Developer,
        }
    }

    pub fn record_compile_surface_invocation(&self, surface: crate::CompileSurfaceId) {
        let phase = self.active_compile_phase();
        self.record_compile_surface_invocation_with_phase(surface, phase);
    }

    pub fn record_compile_surface_invocation_with_phase(
        &self,
        surface: crate::CompileSurfaceId,
        phase: crate::CompilePhase,
    ) {
        if let Some(shard) = self.worker_shard() {
            shard.compile_surface_invocations[surface.index()][phase.index()]
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.inner.legacy_compile_surface_invocations[surface.index()][phase.index()]
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_compile_surface_load(&self, surface: crate::CompileSurfaceId) {
        if let Some(shard) = self.worker_shard() {
            shard.compile_surface_loads[surface.index()].fetch_add(1, Ordering::Relaxed);
        } else {
            self.inner.legacy_compile_surface_loads[surface.index()]
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn total_runtime_compiles(&self) -> u64 {
        let mut total = 0u64;
        for surface in crate::CompileSurfaceId::ALL {
            total = total.saturating_add(
                self.compile_surface_invocations(surface, crate::CompilePhase::Scan),
            );
            total = total.saturating_add(
                self.compile_surface_invocations(surface, crate::CompilePhase::Developer),
            );
        }
        total
    }

    pub fn compile_surface_invocations(
        &self,
        surface: crate::CompileSurfaceId,
        phase: crate::CompilePhase,
    ) -> u64 {
        let mut count = self.inner.legacy_compile_surface_invocations[surface.index()]
            [phase.index()]
        .load(Ordering::Relaxed);
        let shards = self.inner.sorted_shards();
        for shard in shards.iter() {
            count = count.saturating_add(
                shard.compile_surface_invocations[surface.index()][phase.index()]
                    .load(Ordering::Relaxed),
            );
        }
        count
    }

    pub fn compile_surface_loads(&self, surface: crate::CompileSurfaceId) -> u64 {
        let mut count =
            self.inner.legacy_compile_surface_loads[surface.index()].load(Ordering::Relaxed);
        let shards = self.inner.sorted_shards();
        for shard in shards.iter() {
            count = count.saturating_add(
                shard.compile_surface_loads[surface.index()].load(Ordering::Relaxed),
            );
        }
        count
    }

    pub fn compile_surface_reports(&self) -> Vec<crate::schema_v2::CompileSurfaceRecordV2> {
        crate::CompileSurfaceId::ALL
            .iter()
            .map(|&surface| {
                let install_compiles =
                    self.compile_surface_invocations(surface, crate::CompilePhase::Install);
                let update_compiles =
                    self.compile_surface_invocations(surface, crate::CompilePhase::Update);
                let scan_compiles =
                    self.compile_surface_invocations(surface, crate::CompilePhase::Scan);
                let developer_compiles =
                    self.compile_surface_invocations(surface, crate::CompilePhase::Developer);
                let runtime_compiles = scan_compiles.saturating_add(developer_compiles);
                let loads = self.compile_surface_loads(surface);
                crate::schema_v2::CompileSurfaceRecordV2 {
                    version: crate::schema_v2::COMPILE_SURFACE_RECORD_V2_VERSION,
                    surface,
                    name: surface.as_str().to_string(),
                    runtime_compiles,
                    loads,
                    install_compiles,
                    update_compiles,
                    developer_compiles,
                }
            })
            .collect()
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

    pub(super) fn take_input_totals(&self) -> (u64, u64) {
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

    pub(super) fn record_batch_route(
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

    pub(super) fn record_queue_enqueue(&self, queue: crate::QueueId, sequence: u64) {
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

    pub(super) fn record_queue_dequeue(&self, queue: crate::QueueId, sequence: u64) {
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

    pub(super) fn queue_depth_enqueue(&self, queue: crate::QueueId) {
        if !self.inner.session_recording {
            return;
        }
        let index = queue.index();
        let depth = self.inner.queue_depth_current[index].fetch_add(1, Ordering::Relaxed) + 1;
        self.inner.queue_depth_high_water[index].fetch_max(depth, Ordering::Relaxed);
        self.inner.queue_depth_enqueues[index].fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn queue_depth_dequeue(&self, queue: crate::QueueId) {
        if !self.inner.session_recording {
            return;
        }
        let index = queue.index();
        let counter = &self.inner.queue_depth_current[index];
        let mut current = counter.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                break;
            }
            match counter.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        self.inner.queue_depth_dequeues[index].fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn set_queue_depth(&self, queue: crate::QueueId, depth: u64) {
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
    pub(super) fn offset_ns(&self, at: Instant) -> u64 {
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
    pub(super) fn reset(&self) {
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
        self.inner
            .active_compile_phase
            .store(crate::CompilePhase::Scan as u8, Ordering::Relaxed);
        for surface in 0..crate::CompileSurfaceId::COUNT {
            self.inner.legacy_compile_surface_loads[surface].store(0, Ordering::Relaxed);
            for phase in 0..crate::CompilePhase::COUNT {
                self.inner.legacy_compile_surface_invocations[surface][phase]
                    .store(0, Ordering::Relaxed);
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
            for surface in 0..crate::CompileSurfaceId::COUNT {
                shard.compile_surface_loads[surface].store(0, Ordering::Relaxed);
                for phase in 0..crate::CompilePhase::COUNT {
                    shard.compile_surface_invocations[surface][phase].store(0, Ordering::Relaxed);
                }
            }
        }
    }
}
