use crate::api::case::{
    BenchCase, BenchContext, BenchError, BenchId, BenchLayer, BenchMetadata, BenchRequirements,
    BenchRun, Correctness, DeterminismClass, PerformanceContract, PreparedCase, WorkloadClass,
};
use crate::api::metric::{BenchMetrics, MetricPoint};
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

pub struct Stencil;

impl BenchCase for Stencil {
    fn id(&self) -> BenchId {
        BenchId("foundation.stencil3.u32.1m".to_string())
    }

    fn metadata(&self) -> BenchMetadata {
        BenchMetadata {
            id: self.id(),
            name: "Stencil3 U32 1M".to_string(),
            description: "Three-point u32 stencil over 1M elements".to_string(),
            tags: vec!["convolution".to_string(), "memory-bound".to_string()],
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

    fn prepare(&self, _ctx: &mut BenchContext) -> Result<PreparedCase, BenchError> {
        let count = 1_000_000u32;
        let prog = Program::wrapped(
            vec![
                BufferDecl::storage("out", 0, BufferAccess::ReadWrite, DataType::U32)
                    .with_count(count),
                BufferDecl::storage("input", 1, BufferAccess::ReadOnly, DataType::U32)
                    .with_count(count),
            ],
            [256, 1, 1],
            vec![
                Node::let_bind("idx", Expr::gid_x()),
                Node::if_then(
                    Expr::and(
                        Expr::lt(Expr::u32(0), Expr::var("idx")),
                        Expr::lt(Expr::var("idx"), Expr::u32(count - 1)),
                    ),
                    vec![Node::store(
                        "out",
                        Expr::var("idx"),
                        Expr::add(
                            Expr::add(
                                Expr::load("input", Expr::sub(Expr::var("idx"), Expr::u32(1))),
                                Expr::load("input", Expr::var("idx")),
                            ),
                            Expr::load("input", Expr::add(Expr::var("idx"), Expr::u32(1))),
                        ),
                    )],
                ),
            ],
        );
        Ok(Box::new(prog))
    }

    fn run(
        &self,
        ctx: &mut BenchContext,
        prepared: &mut PreparedCase,
    ) -> Result<BenchRun, BenchError> {
        let prog = crate::api::case::prepared_program(prepared)?;
        let count = 1_000_000usize;
        let mut values = vec![0u8; count * 4];
        for i in 0..count {
            values[i * 4..i * 4 + 4].copy_from_slice(&((i % 997) as u32).to_le_bytes());
        }
        let inputs = vec![vec![0u8; count * 4], values];

        let timed = ctx
            .dispatch_timed(prog, &inputs, &ctx.dispatch_config)
            .map_err(|error| BenchError::BackendFailed(error.to_string()))?;
        let elapsed = timed.wall_ns;
        let dispatch_ns = timed.device_ns;
        let outputs = timed.outputs;

        let start_ref = std::time::Instant::now();
        let baseline_outputs = vec![crate::cases::cpu_baselines::stencil3_u32_bytes(&inputs[1])];
        let elapsed_ref = start_ref.elapsed().as_nanos() as u64;

        Ok(BenchRun {
            metrics: BenchMetrics {
                wall_ns: Some(elapsed),
                dispatch_ns,
                input_bytes: Some(inputs.iter().map(Vec::len).sum::<usize>() as u64),
                output_bytes: Some(outputs.iter().map(Vec::len).sum::<usize>() as u64),
                custom: vec![MetricPoint {
                    name: "flop_count".to_string(),
                    value: (count * 2) as u64,
                }],
                ..Default::default()
            },
            baseline_metrics: Some(BenchMetrics {
                wall_ns: Some(elapsed_ref),
                input_bytes: Some(inputs[1].len() as u64),
                output_bytes: Some(baseline_outputs.iter().map(Vec::len).sum::<usize>() as u64),
                custom: vec![MetricPoint {
                    name: "flop_count".to_string(),
                    value: (count * 2) as u64,
                }],
                ..Default::default()
            }),
            outputs,
            baseline_outputs: Some(baseline_outputs),
        })
    }

    fn verify(&self, _ctx: &mut BenchContext, run: &BenchRun) -> Result<Correctness, BenchError> {
        run.verify_exact_outputs()
    }
}

inventory::submit! {
    &Stencil as &'static dyn BenchCase
}
