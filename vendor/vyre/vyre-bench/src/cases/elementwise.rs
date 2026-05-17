use crate::api::case::{
    BenchCase, BenchContext, BenchError, BenchId, BenchLayer, BenchMetadata, BenchRequirements,
    BenchRun, Correctness, DeterminismClass, PerformanceContract, PreparedCase, WorkloadClass,
};
use crate::api::metric::{BenchMetrics, MetricPoint};
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};
use vyre_driver::{BackendError, Resource};

const CPU_BASELINE_REPEATS: u32 = 32;

pub struct ElementwiseBench;

struct ElementwisePrepared {
    program: Program,
    inputs: Vec<Vec<u8>>,
    baseline_output: Vec<u8>,
    baseline_wall_ns: u64,
    resident: Option<ResidentElementwise>,
}

struct ResidentElementwise {
    backend: std::sync::Arc<dyn vyre::VyreBackend>,
    resources: Vec<Resource>,
}

impl Drop for ResidentElementwise {
    fn drop(&mut self) {
        for resource in self.resources.drain(..) {
            if let Err(error) = self.backend.free_resident(resource) {
                eprintln!("elementwise bench resident cleanup failed: {error}");
            }
        }
    }
}

impl BenchCase for ElementwiseBench {
    fn id(&self) -> BenchId {
        BenchId("foundation.elementwise.add.1m".to_string())
    }

    fn metadata(&self) -> BenchMetadata {
        BenchMetadata {
            id: self.id(),
            name: "Elementwise Add 1M".to_string(),
            description: "Elementwise f32 addition over 1M elements".to_string(),
            tags: vec!["compute".to_string(), "memory-bound".to_string()],
            layer: BenchLayer::Foundation,
            workload: WorkloadClass::Micro,
            determinism: DeterminismClass::Deterministic,
            owner_crate: "vyre-bench".to_string(),
        }
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

    fn performance_contract(&self) -> Option<PerformanceContract> {
        None
    }

    fn prepare(&self, ctx: &mut BenchContext) -> Result<PreparedCase, BenchError> {
        let size = 1_000_000usize;
        let size_u32 = size as u32;
        let prog = Program::wrapped(
            vec![
                BufferDecl::storage("out", 0, BufferAccess::ReadWrite, DataType::F32)
                    .with_count(size_u32),
                BufferDecl::storage("a", 1, BufferAccess::ReadOnly, DataType::F32)
                    .with_count(size_u32),
                BufferDecl::storage("b", 2, BufferAccess::ReadOnly, DataType::F32)
                    .with_count(size_u32),
            ],
            [256, 1, 1],
            vec![
                Node::let_bind("idx", Expr::gid_x()),
                Node::if_then(
                    Expr::lt(Expr::var("idx"), Expr::u32(size_u32)),
                    vec![Node::store(
                        "out",
                        Expr::var("idx"),
                        Expr::add(
                            Expr::load("a", Expr::var("idx")),
                            Expr::load("b", Expr::var("idx")),
                        ),
                    )],
                ),
            ],
        );

        let inputs = elementwise_inputs(size);
        let resident = match prepare_resident(ctx, &inputs) {
            Ok(resident) => Some(resident),
            Err(BackendError::UnsupportedFeature { name, .. })
                if name == "resident buffer allocation" =>
            {
                None
            }
            Err(error) => return Err(BenchError::BackendFailed(error.to_string())),
        };

        let mut baseline_output = vec![0u8; size * 4];
        let baseline_start = std::time::Instant::now();
        for _ in 0..CPU_BASELINE_REPEATS {
            crate::cases::cpu_baselines::elementwise_add_f32_bytes_into(
                &inputs[1],
                &inputs[2],
                &mut baseline_output,
            );
        }
        let baseline_wall_ns =
            (baseline_start.elapsed().as_nanos() / u128::from(CPU_BASELINE_REPEATS)) as u64;

        Ok(Box::new(ElementwisePrepared {
            program: prog,
            baseline_output,
            baseline_wall_ns,
            inputs,
            resident,
        }))
    }

    fn program<'a>(&self, prepared: &'a PreparedCase) -> Option<&'a Program> {
        prepared
            .downcast_ref::<ElementwisePrepared>()
            .map(|prepared| &prepared.program)
    }

    fn bytes_touched(&self, prepared: &PreparedCase) -> (u64, u64) {
        if let Some(p) = prepared.downcast_ref::<ElementwisePrepared>() {
            let read = p.inputs[1].len() as u64 + p.inputs[2].len() as u64;
            let written = p.inputs[0].len() as u64;
            (read, written)
        } else {
            (0, 0)
        }
    }

    fn run(
        &self,
        ctx: &mut BenchContext,
        prepared: &mut PreparedCase,
    ) -> Result<BenchRun, BenchError> {
        let prepared = prepared
            .downcast_mut::<ElementwisePrepared>()
            .ok_or_else(|| {
                BenchError::ExecutionFailed(
                    "elementwise prepared payload type mismatch".to_string(),
                )
            })?;
        let size = 1_000_000;

        let timed = if let Some(resident) = &prepared.resident {
            let driver_result = resident
                .backend
                .dispatch_resident_timed(
                    &prepared.program,
                    &resident.resources,
                    &ctx.dispatch_config,
                )
                .map_err(|error| BenchError::BackendFailed(error.to_string()))?;

            crate::probes::cuda_events::CudaEventResult {
                outputs: driver_result.outputs,
                wall_ns: driver_result.wall_ns,
                device_ns: driver_result.device_ns,
                kernel_queue_submit_ns: driver_result.enqueue_ns,
                kernel_execute_ns: driver_result.device_ns,
                device_sync_ns: driver_result.wait_ns,
            }
        } else {
            crate::probes::cuda_events::dispatch_with_events(
                ctx,
                &prepared.program,
                &prepared.inputs,
                &ctx.dispatch_config,
            )
            .map_err(|e| BenchError::BackendFailed(e.to_string()))?
        };
        let wall = timed.wall_ns;
        let dispatch_ns = timed.device_ns;
        let kernel_queue_submit_ns = timed.kernel_queue_submit_ns;
        let kernel_execute_ns = timed.kernel_execute_ns;
        let device_sync_ns = timed.device_sync_ns;
        let outputs = timed.outputs;

        let input_bytes = prepared.inputs.iter().map(Vec::len).sum::<usize>() as u64;
        let output_bytes = outputs.iter().map(Vec::len).sum::<usize>() as u64;
        let host_bytes_touched = if prepared.resident.is_some() {
            0
        } else {
            input_bytes + output_bytes
        };

        Ok(BenchRun {
            metrics: BenchMetrics {
                wall_ns: Some(wall),
                dispatch_ns,
                input_bytes: Some(input_bytes),
                output_bytes: Some(output_bytes),
                bytes_touched: Some(host_bytes_touched),
                bytes_read: Some(input_bytes),
                bytes_written: Some(output_bytes),
                kernel_queue_submit_ns,
                kernel_execute_ns,
                device_sync_ns,
                custom: vec![MetricPoint {
                    name: "flop_count".to_string(),
                    value: size as u64,
                }],
                ..Default::default()
            },
            baseline_metrics: Some(BenchMetrics {
                wall_ns: Some(prepared.baseline_wall_ns),
                input_bytes: Some(
                    prepared.inputs[1]
                        .len()
                        .saturating_add(prepared.inputs[2].len()) as u64,
                ),
                output_bytes: Some(prepared.baseline_output.len() as u64),
                custom: vec![MetricPoint {
                    name: "flop_count".to_string(),
                    value: size as u64,
                }],
                ..Default::default()
            }),
            outputs,
            baseline_outputs: ctx
                .include_baseline_outputs
                .then(|| vec![prepared.baseline_output.clone()]),
        })
    }

    fn verify(&self, _ctx: &mut BenchContext, run: &BenchRun) -> Result<Correctness, BenchError> {
        run.verify_exact_outputs()
    }
}

fn elementwise_inputs(size: usize) -> Vec<Vec<u8>> {
    let mut a_bytes = vec![0u8; size * 4];
    let mut b_bytes = vec![0u8; size * 4];
    for i in 0..size {
        let a_val: f32 = i as f32;
        let b_val: f32 = (i * 2) as f32;
        a_bytes[i * 4..i * 4 + 4].copy_from_slice(&a_val.to_le_bytes());
        b_bytes[i * 4..i * 4 + 4].copy_from_slice(&b_val.to_le_bytes());
    }
    vec![vec![0u8; size * 4], a_bytes, b_bytes]
}

fn prepare_resident(
    ctx: &BenchContext,
    inputs: &[Vec<u8>],
) -> Result<ResidentElementwise, BackendError> {
    let backend = std::sync::Arc::clone(&ctx.preferred_backend);
    let mut resources = Vec::with_capacity(inputs.len());
    let result = (|| {
        for input in inputs {
            let resource = backend.allocate_resident(input.len())?;
            backend.upload_resident(&resource, input)?;
            resources.push(resource);
        }
        Ok(())
    })();

    if let Err(error) = result {
        for resource in resources {
            if let Err(cleanup_error) = backend.free_resident(resource) {
                eprintln!("elementwise bench resident rollback cleanup failed: {cleanup_error}");
            }
        }
        return Err(error);
    }

    Ok(ResidentElementwise { backend, resources })
}

inventory::submit! {
    &ElementwiseBench as &'static dyn BenchCase
}
