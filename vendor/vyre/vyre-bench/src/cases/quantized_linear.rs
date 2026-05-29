//! `nn.linear_4bit_affine_grouped.1m` - fused grouped INT4 linear inference.
//!
//! This measures the path LLM inference actually needs: packed 4-bit weights,
//! per-group scale/zero-point metadata, and accumulation without materializing
//! an unpacked weight matrix. The CPU oracle performs the same packed read and
//! affine dequantization loop so the benchmark measures dispatch/runtime
//! advantage rather than changing math.

use super::byte_pack::{f32_bytes, u32_bytes};
use crate::api::case::{
    BenchCase, BenchContext, BenchError, BenchId, BenchLayer, BenchMetadata, BenchRequirements,
    BenchRun, Correctness, DeterminismClass, PerformanceContract, PreparedCase, WorkloadClass,
};
use crate::api::metric::{BenchMetrics, MetricPoint};
use crate::api::resident::{
    dispatch_program_timed, input_bytes_total, transfer_accounting, ResidentInputSet,
};
use crate::api::suite::SuiteKind;
use rayon::prelude::*;
use vyre_foundation::ir::Program;

const IN_DIM: u32 = 256;
const OUT_DIM: u32 = 4096;
const GROUP_SIZE: u32 = 64;
const PACKED_WORDS: u32 = (IN_DIM / 8) * OUT_DIM;
const GROUP_COUNT: u32 = (IN_DIM + GROUP_SIZE - 1) / GROUP_SIZE;
const SIDECAR_WORDS: u32 = GROUP_COUNT * OUT_DIM;
const MAC_COUNT: u64 = (IN_DIM as u64) * (OUT_DIM as u64);

const SUITES: &[SuiteKind] = &[
    SuiteKind::Release,
    SuiteKind::Gpu,
    SuiteKind::Deep,
    SuiteKind::Honest,
];

pub struct QuantizedLinear4BitAffineGrouped;

struct QuantizedLinearPrepared {
    program: Program,
    inputs: Vec<Vec<u8>>,
    input_bytes_total: u64,
    baseline_output: Vec<u8>,
    baseline_wall_ns: u64,
    resident: Option<ResidentInputSet>,
}

impl BenchCase for QuantizedLinear4BitAffineGrouped {
    fn id(&self) -> BenchId {
        BenchId("nn.linear_4bit_affine_grouped.1m".to_string())
    }

    fn metadata(&self) -> BenchMetadata {
        BenchMetadata {
            id: self.id(),
            name: "Fused grouped INT4 linear 1M MAC".to_string(),
            description:
                "Packed 4-bit linear layer with per-group scale/zero-point applied in the dot-product loop"
                    .to_string(),
            tags: vec![
                "nn".to_string(),
                "quantized".to_string(),
                "resident".to_string(),
                "inference".to_string(),
                "release".to_string(),
            ],
            layer: BenchLayer::Runtime,
            workload: WorkloadClass::Macro,
            determinism: DeterminismClass::Deterministic,
            owner_crate: "vyre-bench".to_string(),
        }
    }

    fn suites(&self) -> &'static [SuiteKind] {
        SUITES
    }

    fn requirements(&self) -> BenchRequirements {
        BenchRequirements {
            needs_gpu: true,
            needs_network: false,
            min_vram_bytes: Some(
                u64::from(PACKED_WORDS + SIDECAR_WORDS * 2 + IN_DIM + OUT_DIM * 2) * 4,
            ),
            min_input_bytes: Some(
                u64::from(PACKED_WORDS + SIDECAR_WORDS * 2 + IN_DIM + OUT_DIM) * 4,
            ),
            feature_set: vec![
                "nn.quantized".to_string(),
                "resident".to_string(),
                "packed-int4".to_string(),
            ],
        }
    }

    fn performance_contract(&self) -> Option<PerformanceContract> {
        Some(PerformanceContract::cpu_sota_100x(
            "fused grouped INT4 linear",
            "rayon",
            "Rayon-parallel packed INT4 affine dequantization oracle",
        ))
    }

    fn prepare(&self, ctx: &mut BenchContext) -> Result<PreparedCase, BenchError> {
        let spec =
            vyre_libs::nn::QuantizedLinear4BitSpec::affine_grouped(IN_DIM, OUT_DIM, GROUP_SIZE);
        let program = vyre_libs::nn::linear_4bit_affine_grouped_typed(
            &spec, "x", "w", "scale", "zp", "b", "out",
        )
        .map_err(BenchError::ExecutionFailed)?;
        let (x, packed, scale, zero_point, bias) = quantized_inputs();
        let inputs = vec![
            f32_bytes(&x),
            u32_bytes(&packed),
            f32_bytes(&scale),
            u32_bytes(&zero_point),
            f32_bytes(&bias),
        ];
        let input_bytes_total = input_bytes_total(&inputs);
        let baseline_start = std::time::Instant::now();
        let baseline = cpu_oracle_checked(&x, &packed, &scale, &zero_point, &bias)?;
        let baseline_wall_ns =
            u64::try_from(baseline_start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let baseline_output = f32_bytes(&baseline);
        let resident = ResidentInputSet::upload_optional(ctx, &inputs, "quantized linear")?;

        Ok(Box::new(QuantizedLinearPrepared {
            program,
            inputs,
            input_bytes_total,
            baseline_output,
            baseline_wall_ns,
            resident,
        }))
    }

    fn program<'a>(&self, prepared: &'a PreparedCase) -> Option<&'a Program> {
        prepared
            .downcast_ref::<QuantizedLinearPrepared>()
            .map(|prepared| &prepared.program)
    }

    fn run(
        &self,
        ctx: &mut BenchContext,
        prepared: &mut PreparedCase,
    ) -> Result<BenchRun, BenchError> {
        let prepared = prepared
            .downcast_ref::<QuantizedLinearPrepared>()
            .ok_or_else(|| {
                BenchError::ExecutionFailed(
                    "quantized linear prepared payload type mismatch".to_string(),
                )
            })?;
        let dispatch = dispatch_program_timed(
            ctx,
            &prepared.program,
            prepared.resident.as_ref(),
            &prepared.inputs,
            &ctx.dispatch_config,
        )?;
        let timed = dispatch.timed;
        let outputs = timed.outputs;
        let output_bytes = outputs.iter().map(Vec::len).sum::<usize>() as u64;
        let accounting = transfer_accounting(
            prepared.input_bytes_total,
            output_bytes,
            dispatch.resident_used,
        );

        Ok(BenchRun {
            metrics: BenchMetrics {
                wall_ns: Some(timed.wall_ns),
                dispatch_ns: timed.device_ns,
                input_bytes: Some(prepared.input_bytes_total),
                output_bytes: Some(output_bytes),
                bytes_read: Some(accounting.bytes_read),
                bytes_written: Some(accounting.bytes_written),
                bytes_touched: Some(accounting.bytes_touched),
                custom: vec![
                    MetricPoint {
                        name: "quantized_mac_count".to_string(),
                        value: MAC_COUNT,
                    },
                    MetricPoint {
                        name: "quantized_group_size".to_string(),
                        value: u64::from(GROUP_SIZE),
                    },
                    MetricPoint {
                        name: "quantized_sidecar_groups".to_string(),
                        value: u64::from(GROUP_COUNT),
                    },
                    MetricPoint {
                        name: "packed_weight_bytes".to_string(),
                        value: u64::from(PACKED_WORDS) * 4,
                    },
                    MetricPoint {
                        name: "unpacked_weight_bytes_elided".to_string(),
                        value: u64::from(IN_DIM) * u64::from(OUT_DIM) * 4,
                    },
                    MetricPoint {
                        name: "weight_compression_ratio_x100".to_string(),
                        value: (u64::from(IN_DIM) * u64::from(OUT_DIM) * 4 * 100)
                            / (u64::from(PACKED_WORDS) * 4),
                    },
                    MetricPoint {
                        name: "sidecar_loads_elided_by_group_hoist".to_string(),
                        value: MAC_COUNT
                            .saturating_mul(2)
                            .saturating_sub(u64::from(OUT_DIM) * u64::from(GROUP_COUNT) * 2),
                    },
                    MetricPoint {
                        name: "dequantize_dispatches_elided".to_string(),
                        value: 1,
                    },
                    MetricPoint {
                        name: "resident_buffers".to_string(),
                        value: u64::from(dispatch.resident_used),
                    },
                ],
                ..Default::default()
            },
            baseline_metrics: Some(BenchMetrics {
                wall_ns: Some(prepared.baseline_wall_ns),
                input_bytes: Some(prepared.input_bytes_total),
                output_bytes: Some(prepared.baseline_output.len() as u64),
                bytes_touched: Some(
                    prepared
                        .input_bytes_total
                        .saturating_add(prepared.baseline_output.len() as u64),
                ),
                ..Default::default()
            }),
            outputs,
            baseline_outputs: Some(vec![prepared.baseline_output.clone()]),
        })
    }

    fn verify(&self, _ctx: &mut BenchContext, run: &BenchRun) -> Result<Correctness, BenchError> {
        run.verify_f32_outputs_with_ulp(8)
    }

    fn bytes_touched(&self, prepared: &PreparedCase) -> (u64, u64) {
        prepared
            .downcast_ref::<QuantizedLinearPrepared>()
            .map(|prepared| (prepared.input_bytes_total, u64::from(OUT_DIM) * 4))
            .unwrap_or((
                u64::from(PACKED_WORDS + SIDECAR_WORDS * 2 + IN_DIM + OUT_DIM) * 4,
                u64::from(OUT_DIM) * 4,
            ))
    }
}

fn quantized_inputs() -> (Vec<f32>, Vec<u32>, Vec<f32>, Vec<u32>, Vec<f32>) {
    let x = (0..IN_DIM).map(|k| (k % 17) as f32).collect::<Vec<_>>();
    let mut packed = vec![0u32; PACKED_WORDS as usize];
    for block in 0..(IN_DIM / 8) {
        for out in 0..OUT_DIM {
            let mut word = 0u32;
            for lane in 0..8 {
                let k = block * 8 + lane;
                let nibble = (k
                    .wrapping_mul(3)
                    .wrapping_add(out.wrapping_mul(5))
                    .wrapping_add(7))
                    & 0xF;
                word |= nibble << (lane * 4);
            }
            packed[(block * OUT_DIM + out) as usize] = word;
        }
    }

    let mut scale = vec![0.0f32; SIDECAR_WORDS as usize];
    let mut zero_point = vec![0u32; SIDECAR_WORDS as usize];
    for group in 0..GROUP_COUNT {
        for out in 0..OUT_DIM {
            let idx = (group * OUT_DIM + out) as usize;
            scale[idx] = match (group + out) & 3 {
                0 => 0.25,
                1 => 0.5,
                2 => 1.0,
                _ => 2.0,
            };
            zero_point[idx] = (group.wrapping_mul(3).wrapping_add(out)) & 0x7;
        }
    }

    let bias = (0..OUT_DIM).map(|out| (out & 7) as f32).collect::<Vec<_>>();
    (x, packed, scale, zero_point, bias)
}

fn cpu_oracle_checked(
    x: &[f32],
    packed: &[u32],
    scale: &[f32],
    zero_point: &[u32],
    bias: &[f32],
) -> Result<Vec<f32>, BenchError> {
    if x.len() != IN_DIM as usize {
        return Err(BenchError::ExecutionFailed(format!(
            "quantized linear x length mismatch: got {}, expected {IN_DIM}",
            x.len()
        )));
    }
    if packed.len() != PACKED_WORDS as usize {
        return Err(BenchError::ExecutionFailed(format!(
            "quantized linear packed weight length mismatch: got {}, expected {PACKED_WORDS}",
            packed.len()
        )));
    }
    if scale.len() != SIDECAR_WORDS as usize || zero_point.len() != SIDECAR_WORDS as usize {
        return Err(BenchError::ExecutionFailed(format!(
            "quantized linear sidecar length mismatch: scale={}, zero_point={}, expected {SIDECAR_WORDS}",
            scale.len(),
            zero_point.len()
        )));
    }
    if bias.len() != OUT_DIM as usize {
        return Err(BenchError::ExecutionFailed(format!(
            "quantized linear bias length mismatch: got {}, expected {OUT_DIM}",
            bias.len()
        )));
    }

    Ok((0..OUT_DIM as usize)
        .into_par_iter()
        .map(|out| {
            let mut acc = bias[out];
            for k in 0..IN_DIM as usize {
                let block = k / 8;
                let shift = (k % 8) * 4;
                let word = packed[block * OUT_DIM as usize + out];
                let nibble = ((word >> shift) & 0xF) as f32;
                let group = k / GROUP_SIZE as usize;
                let sidecar_idx = group * OUT_DIM as usize + out;
                let weight = (nibble - zero_point[sidecar_idx] as f32) * scale[sidecar_idx];
                acc += x[k] * weight;
            }
            acc
        })
        .collect())
}

inventory::submit! {
    &QuantizedLinear4BitAffineGrouped as &'static dyn BenchCase
}
