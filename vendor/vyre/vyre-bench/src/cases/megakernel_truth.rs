use crate::api::case::{
    BenchCase, BenchContext, BenchError, BenchId, BenchLayer, BenchMetadata, BenchRequirements,
    BenchRun, Correctness, DeterminismClass, PreparedCase, WorkloadClass,
};
use crate::api::metric::{BenchMetrics, MetricPoint};
use std::time::{Duration, Instant};
use vyre_driver_wgpu::megakernel::WgpuMegakernelDispatcher;
use vyre_runtime::megakernel::{protocol, MegakernelConfig, MegakernelWorkItem};

pub struct MegakernelTruth;

const WORK_ITEM_COUNT: usize = 1024;
const WORKER_COUNT: u32 = 256;
const SUITES: &[crate::api::suite::SuiteKind] = &[
    crate::api::suite::SuiteKind::Release,
    crate::api::suite::SuiteKind::Gpu,
    crate::api::suite::SuiteKind::Deep,
];

struct MegakernelTruthPrepared {
    work_items: Vec<MegakernelWorkItem>,
    input_bytes_total: u64,
}

impl BenchCase for MegakernelTruth {
    fn id(&self) -> BenchId {
        BenchId("runtime.megakernel.truth.1024".to_string())
    }

    fn metadata(&self) -> BenchMetadata {
        BenchMetadata {
            id: self.id(),
            name: "Megakernel Truth 1024 WorkItems".to_string(),
            description:
                "Actual megakernel dispatcher path with queue planning, publication, and backend timing"
                    .to_string(),
            tags: vec![
                "runtime".to_string(),
                "megakernel".to_string(),
                "truth".to_string(),
                "release".to_string(),
            ],
            layer: BenchLayer::Runtime,
            workload: WorkloadClass::Macro,
            determinism: DeterminismClass::Deterministic,
            owner_crate: "vyre-driver-wgpu".to_string(),
        }
    }

    fn suites(&self) -> &'static [crate::api::suite::SuiteKind] {
        SUITES
    }

    fn requirements(&self) -> BenchRequirements {
        BenchRequirements {
            needs_gpu: true,
            needs_network: false,
            min_vram_bytes: None,
            min_input_bytes: None,
            feature_set: vec![],
        }
    }

    fn prepare(&self, _ctx: &mut BenchContext) -> Result<PreparedCase, BenchError> {
        let work_items = make_work_items(WORK_ITEM_COUNT)?;
        let input_bytes_total =
            (work_items.len() * std::mem::size_of::<MegakernelWorkItem>()) as u64;
        Ok(Box::new(MegakernelTruthPrepared {
            work_items,
            input_bytes_total,
        }))
    }

    fn program<'a>(
        &self,
        _prepared: &'a PreparedCase,
    ) -> Option<&'a vyre_foundation::ir::Program> {
        None
    }

    fn run(
        &self,
        ctx: &mut BenchContext,
        prepared: &mut PreparedCase,
    ) -> Result<BenchRun, BenchError> {
        let prepared = prepared
            .downcast_ref::<MegakernelTruthPrepared>()
            .ok_or_else(|| {
                BenchError::ExecutionFailed(
                    "megakernel truth prepared payload type mismatch".to_string(),
                )
            })?;

        let config = MegakernelConfig {
            worker_count: WORKER_COUNT,
            max_wall_time: Duration::from_secs(5),
            expected_items_per_worker: 1,
        };
        let dispatcher = WgpuMegakernelDispatcher::new(ctx.preferred_backend.as_ref());
        let started = Instant::now();
        let report = dispatcher
            .dispatch_megakernel(&prepared.work_items, &config)
            .map_err(|error| BenchError::BackendFailed(error.to_string()))?;
        let wall_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let baseline_start = Instant::now();
        let baseline_processed = simulate_cpu_drain(&prepared.work_items);
        let baseline_ns = u64::try_from(baseline_start.elapsed().as_nanos()).unwrap_or(u64::MAX);

        Ok(BenchRun {
            metrics: BenchMetrics {
                wall_ns: Some(wall_ns),
                dispatch_ns: Some(report.backend_dispatch_ns),
                kernel_queue_submit_ns: Some(
                    report
                        .queue_plan_ns
                        .saturating_add(report.queue_publish_ns),
                ),
                input_bytes: Some(prepared.input_bytes_total),
                bytes_read: Some(prepared.input_bytes_total),
                bytes_touched: Some(prepared.input_bytes_total),
                atomic_op_count: Some((WORK_ITEM_COUNT as u64).saturating_mul(2)),
                custom: vec![
                    MetricPoint {
                        name: "megakernel_queue_plan_ns".to_string(),
                        value: report.queue_plan_ns,
                    },
                    MetricPoint {
                        name: "megakernel_queue_publish_ns".to_string(),
                        value: report.queue_publish_ns,
                    },
                    MetricPoint {
                        name: "megakernel_backend_dispatch_ns".to_string(),
                        value: report.backend_dispatch_ns,
                    },
                    MetricPoint {
                        name: "megakernel_lineage_ns".to_string(),
                        value: report.lineage_ns,
                    },
                    MetricPoint {
                        name: "megakernel_published_items".to_string(),
                        value: report.published_items,
                    },
                    MetricPoint {
                        name: "megakernel_lineage_items".to_string(),
                        value: report.lineage_items,
                    },
                    MetricPoint {
                        name: "megakernel_deduped_items".to_string(),
                        value: report.deduped_items,
                    },
                    MetricPoint {
                        name: "megakernel_items_processed".to_string(),
                        value: report.items_processed,
                    },
                    MetricPoint {
                        name: "megakernel_items_remaining".to_string(),
                        value: report.items_remaining,
                    },
                ],
                ..Default::default()
            },
            baseline_metrics: Some(BenchMetrics {
                wall_ns: Some(baseline_ns),
                cpu_ns: Some(baseline_ns),
                input_bytes: Some(prepared.input_bytes_total),
                bytes_read: Some(prepared.input_bytes_total),
                bytes_touched: Some(prepared.input_bytes_total),
                custom: vec![MetricPoint {
                    name: "megakernel_items_processed".to_string(),
                    value: baseline_processed,
                }],
                ..Default::default()
            }),
            outputs: vec![report.items_processed.to_le_bytes().to_vec()],
            baseline_outputs: Some(vec![baseline_processed.to_le_bytes().to_vec()]),
        })
    }

    fn verify(&self, _ctx: &mut BenchContext, run: &BenchRun) -> Result<Correctness, BenchError> {
        run.verify_exact_outputs()
    }

    fn bytes_touched(&self, prepared: &PreparedCase) -> (u64, u64) {
        prepared
            .downcast_ref::<MegakernelTruthPrepared>()
            .map(|prepared| (prepared.input_bytes_total, 0))
            .unwrap_or((0, 0))
    }
}

fn make_work_items(count: usize) -> Result<Vec<MegakernelWorkItem>, BenchError> {
    let mut items = Vec::with_capacity(count);
    for index in 0..count {
        let word = u32::try_from(index).map_err(|_| {
            BenchError::ExecutionFailed(
                "megakernel truth work item index exceeded u32::MAX".to_string(),
            )
        })?;
        items.push(MegakernelWorkItem {
            op_handle: protocol::opcode::NOP,
            input_handle: word,
            output_handle: word,
            param: word,
        });
    }
    Ok(items)
}

fn simulate_cpu_drain(items: &[MegakernelWorkItem]) -> u64 {
    items
        .iter()
        .fold(0_u64, |count, item| {
            count.saturating_add(if item.op_handle == protocol::opcode::NOP {
                1
            } else {
                0
            })
        })
}

inventory::submit! {
    &MegakernelTruth as &'static dyn BenchCase
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_items_are_unique_for_dedupe_truth() {
        let items = make_work_items(64).expect("fixture");
        let mut deduped = Vec::new();
        let report = vyre_runtime::megakernel::prune_redundant_work_items_into(
            &items,
            &mut deduped,
        );

        assert!(report.is_empty());
        assert!(deduped.is_empty());
    }

    #[test]
    fn cpu_drain_counts_nop_items() {
        let items = make_work_items(8).expect("fixture");

        assert_eq!(simulate_cpu_drain(&items), 8);
    }
}
