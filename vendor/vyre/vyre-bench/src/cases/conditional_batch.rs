//! `conditions.yara_like.batch.16x64k` — batched sparse rule-condition eval.

use crate::api::case::{
    BenchCase, BenchContext, BenchError, BenchId, BenchLayer, BenchMetadata, BenchRequirements,
    BenchRun, Correctness, DeterminismClass, PreparedCase, WorkloadClass,
};
use crate::api::metric::BenchMetrics;
use crate::api::suite::SuiteKind;
use rayon::prelude::*;
use vyre_driver::{BackendError, Resource};
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

const RULES_PER_FILE: u32 = 1 << 16;
const FILE_COUNT: u32 = 16;
const EVAL_COUNT: u32 = RULES_PER_FILE * FILE_COUNT;
const PATTERN_COUNT: u32 = 1 << 14;
const BASE_FILESIZE_BYTES: u32 = 10 * 1024 * 1024;
const DESC_WORDS: u32 = 9;
const FIRED_COUNT_RESOURCE_INDEX: usize = 6;

const HONEST_SUITES: &[SuiteKind] = &[
    SuiteKind::Honest,
    SuiteKind::Deep,
    SuiteKind::Release,
    SuiteKind::Smoke,
];

pub struct BatchedConditionalEval;

struct BatchedPrepared {
    program: Program,
    inputs: Vec<Vec<u8>>,
    baseline_output: Vec<Vec<u8>>,
    baseline_wall_ns: u64,
    resident: Option<ResidentBatch>,
}

struct ResidentBatch {
    backend: std::sync::Arc<dyn vyre::VyreBackend>,
    resources: Vec<Resource>,
}

impl Drop for ResidentBatch {
    fn drop(&mut self) {
        for resource in self.resources.drain(..) {
            if let Err(error) = self.backend.free_resident(resource) {
                eprintln!("conditional batch bench resident cleanup failed: {error}");
            }
        }
    }
}

impl BenchCase for BatchedConditionalEval {
    fn id(&self) -> BenchId {
        BenchId("conditions.yara_like.batch.16x64k".to_string())
    }

    fn metadata(&self) -> BenchMetadata {
        BenchMetadata {
            id: self.id(),
            name: "Batched YARA-like Conditional Eval 16x64K".to_string(),
            description:
                "Evaluate 65,536 rule conditions across 16 files with sparse fired-pair output"
                    .to_string(),
            tags: vec![
                "honest".to_string(),
                "conditions".to_string(),
                "rule-engine".to_string(),
                "batched".to_string(),
                "sparse-output".to_string(),
            ],
            layer: BenchLayer::Honest,
            workload: WorkloadClass::Honest,
            determinism: DeterminismClass::Deterministic,
            owner_crate: "vyre-bench".to_string(),
        }
    }

    fn suites(&self) -> &'static [SuiteKind] {
        HONEST_SUITES
    }

    fn requirements(&self) -> BenchRequirements {
        BenchRequirements {
            needs_gpu: true,
            needs_network: false,
            min_vram_bytes: Some(
                u64::from(PATTERN_COUNT) * 12
                    + u64::from(RULES_PER_FILE) * 36
                    + u64::from(EVAL_COUNT) * 4
                    + 128,
            ),
            min_input_bytes: None,
            feature_set: vec![],
        }
    }

    fn bytes_touched(&self, prepared: &PreparedCase) -> (u64, u64) {
        let read = prepared
            .downcast_ref::<BatchedPrepared>()
            .map(|prepared| prepared.inputs.iter().map(Vec::len).sum::<usize>() as u64)
            .unwrap_or(0);
        (read, u64::from(EVAL_COUNT) * 4 + 4)
    }

    fn prepare(&self, ctx: &mut BenchContext) -> Result<PreparedCase, BenchError> {
        let program = Program::wrapped(
            vec![
                BufferDecl::storage("matched", 0, BufferAccess::ReadOnly, DataType::U32)
                    .with_count(PATTERN_COUNT),
                BufferDecl::storage("counts", 1, BufferAccess::ReadOnly, DataType::U32)
                    .with_count(PATTERN_COUNT),
                BufferDecl::storage("offsets", 2, BufferAccess::ReadOnly, DataType::U32)
                    .with_count(PATTERN_COUNT),
                BufferDecl::storage("rule_desc", 3, BufferAccess::ReadOnly, DataType::U32)
                    .with_count(RULES_PER_FILE * DESC_WORDS),
                BufferDecl::storage("file_sizes", 4, BufferAccess::ReadOnly, DataType::U32)
                    .with_count(FILE_COUNT),
                BufferDecl::storage("file_entropy", 5, BufferAccess::ReadOnly, DataType::U32)
                    .with_count(FILE_COUNT),
                BufferDecl::storage("fired_count", 6, BufferAccess::ReadWrite, DataType::U32)
                    .with_count(1),
                BufferDecl::output("fired_pairs", 7, DataType::U32).with_count(EVAL_COUNT),
            ],
            [256, 1, 1],
            vec![
                Node::let_bind("tid", Expr::gid_x()),
                Node::if_then(
                    Expr::lt(Expr::var("tid"), Expr::u32(EVAL_COUNT)),
                    vec![
                        Node::let_bind(
                            "file",
                            Expr::div(Expr::var("tid"), Expr::u32(RULES_PER_FILE)),
                        ),
                        Node::let_bind(
                            "rule",
                            Expr::rem(Expr::var("tid"), Expr::u32(RULES_PER_FILE)),
                        ),
                        Node::let_bind("desc", Expr::mul(Expr::var("rule"), Expr::u32(DESC_WORDS))),
                        Node::let_bind("pa", Expr::load("rule_desc", Expr::var("desc"))),
                        Node::let_bind(
                            "pb",
                            Expr::load("rule_desc", Expr::add(Expr::var("desc"), Expr::u32(1))),
                        ),
                        Node::let_bind(
                            "pc",
                            Expr::load("rule_desc", Expr::add(Expr::var("desc"), Expr::u32(2))),
                        ),
                        Node::let_bind(
                            "pd",
                            Expr::load("rule_desc", Expr::add(Expr::var("desc"), Expr::u32(3))),
                        ),
                        Node::let_bind(
                            "both_literals",
                            Expr::and(
                                Expr::ne(Expr::load("matched", Expr::var("pa")), Expr::u32(0)),
                                Expr::ne(Expr::load("matched", Expr::var("pb")), Expr::u32(0)),
                            ),
                        ),
                        Node::let_bind(
                            "count_ok",
                            Expr::ge(
                                Expr::load("counts", Expr::var("pc")),
                                Expr::load("rule_desc", Expr::add(Expr::var("desc"), Expr::u32(4))),
                            ),
                        ),
                        Node::let_bind(
                            "offset_ok",
                            Expr::le(
                                Expr::load("offsets", Expr::var("pd")),
                                Expr::load("rule_desc", Expr::add(Expr::var("desc"), Expr::u32(5))),
                            ),
                        ),
                        Node::let_bind("filesize", Expr::load("file_sizes", Expr::var("file"))),
                        Node::let_bind(
                            "size_ok",
                            Expr::and(
                                Expr::ge(
                                    Expr::var("filesize"),
                                    Expr::load(
                                        "rule_desc",
                                        Expr::add(Expr::var("desc"), Expr::u32(6)),
                                    ),
                                ),
                                Expr::le(
                                    Expr::var("filesize"),
                                    Expr::load(
                                        "rule_desc",
                                        Expr::add(Expr::var("desc"), Expr::u32(7)),
                                    ),
                                ),
                            ),
                        ),
                        Node::let_bind(
                            "entropy_ok",
                            Expr::le(
                                Expr::load("file_entropy", Expr::var("file")),
                                Expr::load("rule_desc", Expr::add(Expr::var("desc"), Expr::u32(8))),
                            ),
                        ),
                        Node::let_bind(
                            "fired",
                            Expr::and(
                                Expr::and(Expr::var("both_literals"), Expr::var("count_ok")),
                                Expr::and(
                                    Expr::var("offset_ok"),
                                    Expr::and(Expr::var("size_ok"), Expr::var("entropy_ok")),
                                ),
                            ),
                        ),
                        Node::if_then(
                            Expr::var("fired"),
                            vec![
                                Node::let_bind(
                                    "slot",
                                    Expr::atomic_add("fired_count", Expr::u32(0), Expr::u32(1)),
                                ),
                                Node::store("fired_pairs", Expr::var("slot"), Expr::var("tid")),
                            ],
                        ),
                    ],
                ),
            ],
        );

        let matched: Vec<u32> = (0..PATTERN_COUNT)
            .map(|index| u32::from((mix32(index) & 7) != 0))
            .collect();
        let counts: Vec<u32> = (0..PATTERN_COUNT)
            .map(|index| (mix32(index ^ 0xA5A5_5A5A) & 7) + 1)
            .collect();
        let offsets: Vec<u32> = (0..PATTERN_COUNT)
            .map(|index| mix32(index ^ 0x517C_C1B7) % BASE_FILESIZE_BYTES)
            .collect();
        let mut rule_desc = Vec::with_capacity((RULES_PER_FILE * DESC_WORDS) as usize);
        for rule in 0..RULES_PER_FILE {
            let seed = mix32(rule);
            rule_desc.push(seed & (PATTERN_COUNT - 1));
            rule_desc.push(mix32(seed ^ 0x9E37_79B9) & (PATTERN_COUNT - 1));
            rule_desc.push(mix32(seed ^ 0x85EB_CA6B) & (PATTERN_COUNT - 1));
            rule_desc.push(mix32(seed ^ 0xC2B2_AE35) & (PATTERN_COUNT - 1));
            rule_desc.push((seed >> 5) % 7 + 1);
            rule_desc.push(BASE_FILESIZE_BYTES - ((seed >> 11) % (BASE_FILESIZE_BYTES / 2)));
            rule_desc.push(BASE_FILESIZE_BYTES - ((seed >> 17) & 4095));
            rule_desc.push(BASE_FILESIZE_BYTES + ((seed >> 3) & 8191));
            rule_desc.push(600 + ((seed >> 9) % 320));
        }
        let file_sizes: Vec<u32> = (0..FILE_COUNT)
            .map(|file| BASE_FILESIZE_BYTES + file * 257)
            .collect();
        let file_entropy: Vec<u32> = (0..FILE_COUNT)
            .map(|file| 640 + ((file * 37) % 220))
            .collect();
        let inputs = vec![
            u32_bytes(&matched),
            u32_bytes(&counts),
            u32_bytes(&offsets),
            u32_bytes(&rule_desc),
            u32_bytes(&file_sizes),
            u32_bytes(&file_entropy),
            vec![0u8; 4],
        ];
        let resident = match prepare_resident(ctx, &inputs) {
            Ok(resident) => Some(resident),
            Err(BackendError::UnsupportedFeature { name, .. })
                if name == "resident buffer allocation" =>
            {
                None
            }
            Err(error) => return Err(BenchError::BackendFailed(error.to_string())),
        };
        let baseline_start = std::time::Instant::now();
        let baseline_output = cpu_batch(
            &matched,
            &counts,
            &offsets,
            &rule_desc,
            &file_sizes,
            &file_entropy,
        );
        let baseline_wall_ns = baseline_start.elapsed().as_nanos() as u64;
        Ok(Box::new(BatchedPrepared {
            program,
            inputs,
            baseline_output,
            baseline_wall_ns,
            resident,
        }))
    }

    fn program<'a>(&self, prepared: &'a PreparedCase) -> Option<&'a Program> {
        prepared
            .downcast_ref::<BatchedPrepared>()
            .map(|prepared| &prepared.program)
    }

    fn run(
        &self,
        ctx: &mut BenchContext,
        prepared: &mut PreparedCase,
    ) -> Result<BenchRun, BenchError> {
        let prepared = prepared.downcast_ref::<BatchedPrepared>().ok_or_else(|| {
            BenchError::ExecutionFailed(
                "batched conditional prepared payload type mismatch".to_string(),
            )
        })?;
        let timed = if let Some(resident) = &prepared.resident {
            reset_resident_fired_count(resident)?;
            resident
                .backend
                .dispatch_resident_timed(
                    &prepared.program,
                    &resident.resources,
                    &ctx.dispatch_config,
                )
                .map_err(|error| BenchError::BackendFailed(error.to_string()))?
        } else {
            ctx.dispatch_timed(&prepared.program, &prepared.inputs, &ctx.dispatch_config)
                .map_err(|error| BenchError::BackendFailed(error.to_string()))?
        };
        let outputs = timed.outputs;
        let input_bytes = prepared.inputs.iter().map(Vec::len).sum::<usize>() as u64;
        Ok(BenchRun {
            metrics: BenchMetrics {
                wall_ns: Some(timed.wall_ns),
                dispatch_ns: timed.device_ns,
                input_bytes: Some(input_bytes),
                output_bytes: Some(outputs.iter().map(Vec::len).sum::<usize>() as u64),
                bytes_read: Some(input_bytes),
                bytes_written: Some(u64::from(EVAL_COUNT) * 4 + 4),
                ..Default::default()
            },
            baseline_metrics: Some(BenchMetrics {
                wall_ns: Some(prepared.baseline_wall_ns),
                input_bytes: Some(input_bytes),
                output_bytes: Some(
                    prepared.baseline_output.iter().map(Vec::len).sum::<usize>() as u64
                ),
                ..Default::default()
            }),
            outputs,
            baseline_outputs: ctx
                .include_baseline_outputs
                .then(|| prepared.baseline_output.clone()),
        })
    }

    fn verify(&self, _ctx: &mut BenchContext, run: &BenchRun) -> Result<Correctness, BenchError> {
        verify_sparse_outputs(&run.outputs, run.baseline_outputs.as_deref())
    }
}

#[allow(clippy::too_many_arguments)]
fn cpu_batch(
    matched: &[u32],
    counts: &[u32],
    offsets: &[u32],
    rule_desc: &[u32],
    file_sizes: &[u32],
    file_entropy: &[u32],
) -> Vec<Vec<u8>> {
    let mut fired: Vec<u32> = (0..EVAL_COUNT as usize)
        .into_par_iter()
        .filter_map(|tid| {
            let file = tid / RULES_PER_FILE as usize;
            let rule = tid % RULES_PER_FILE as usize;
            let desc = rule * DESC_WORDS as usize;
            if matched[rule_desc[desc] as usize] == 0 || matched[rule_desc[desc + 1] as usize] == 0
            {
                return None;
            }
            if counts[rule_desc[desc + 2] as usize] < rule_desc[desc + 4] {
                return None;
            }
            if offsets[rule_desc[desc + 3] as usize] > rule_desc[desc + 5] {
                return None;
            }
            let filesize = file_sizes[file];
            if filesize < rule_desc[desc + 6] || filesize > rule_desc[desc + 7] {
                return None;
            }
            if file_entropy[file] > rule_desc[desc + 8] {
                return None;
            }
            Some(tid as u32)
        })
        .collect();
    fired.sort_unstable();
    let count = fired.len() as u32;
    fired.resize(EVAL_COUNT as usize, 0);
    vec![u32_bytes(&[count]), u32_bytes(&fired)]
}

fn verify_sparse_outputs(
    outputs: &[Vec<u8>],
    baseline_outputs: Option<&[Vec<u8>]>,
) -> Result<Correctness, BenchError> {
    let baseline = baseline_outputs.ok_or_else(|| {
        BenchError::CorrectnessViolation(
            "batched conditional eval did not capture baseline sparse output".to_string(),
        )
    })?;
    if outputs.len() != 2 || baseline.len() != 2 {
        return Err(BenchError::CorrectnessViolation(format!(
            "sparse output count mismatch: backend returned {}, baseline returned {}",
            outputs.len(),
            baseline.len()
        )));
    }
    let backend_count = read_le_u32(&outputs[0], 0)? as usize;
    let baseline_count = read_le_u32(&baseline[0], 0)? as usize;
    if backend_count != baseline_count {
        return Err(BenchError::CorrectnessViolation(format!(
            "fired-pair count mismatch: backend returned {backend_count}, baseline returned {baseline_count}"
        )));
    }
    let mut backend_rules = read_u32_prefix(&outputs[1], backend_count)?;
    let mut baseline_rules = read_u32_prefix(&baseline[1], baseline_count)?;
    backend_rules.sort_unstable();
    baseline_rules.sort_unstable();
    if backend_rules == baseline_rules {
        Ok(Correctness::Exact)
    } else {
        Err(BenchError::CorrectnessViolation(
            "fired-pair set differs between backend and baseline".to_string(),
        ))
    }
}

fn read_le_u32(bytes: &[u8], word_index: usize) -> Result<u32, BenchError> {
    let start = word_index.saturating_mul(4);
    let end = start.saturating_add(4);
    let chunk = bytes.get(start..end).ok_or_else(|| {
        BenchError::CorrectnessViolation(format!(
            "u32 read out of bounds at word {word_index}; buffer has {} bytes",
            bytes.len()
        ))
    })?;
    Ok(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
}

fn read_u32_prefix(bytes: &[u8], count: usize) -> Result<Vec<u32>, BenchError> {
    (0..count).map(|index| read_le_u32(bytes, index)).collect()
}

fn prepare_resident(ctx: &BenchContext, inputs: &[Vec<u8>]) -> Result<ResidentBatch, BackendError> {
    let backend = std::sync::Arc::clone(&ctx.preferred_backend);
    let mut resources = Vec::with_capacity(inputs.len() + 1);
    let result = (|| {
        for input in inputs {
            let resource = backend.allocate_resident(input.len())?;
            backend.upload_resident(&resource, input)?;
            resources.push(resource);
        }
        let output = backend.allocate_resident(EVAL_COUNT as usize * 4)?;
        backend.upload_resident(&output, &vec![0u8; EVAL_COUNT as usize * 4])?;
        resources.push(output);
        Ok(())
    })();
    if let Err(error) = result {
        for resource in resources {
            if let Err(cleanup_error) = backend.free_resident(resource) {
                eprintln!(
                    "conditional batch bench resident rollback cleanup failed: {cleanup_error}"
                );
            }
        }
        return Err(error);
    }
    Ok(ResidentBatch { backend, resources })
}

fn reset_resident_fired_count(resident: &ResidentBatch) -> Result<(), BenchError> {
    let resource = resident
        .resources
        .get(FIRED_COUNT_RESOURCE_INDEX)
        .ok_or_else(|| {
            BenchError::ExecutionFailed(format!(
                "batched conditional resident resources missing fired_count at index {FIRED_COUNT_RESOURCE_INDEX}"
            ))
        })?;
    resident
        .backend
        .upload_resident(resource, &[0u8; 4])
        .map_err(|error| BenchError::BackendFailed(error.to_string()))
}

fn mix32(mut value: u32) -> u32 {
    value ^= value >> 16;
    value = value.wrapping_mul(0x7FEB_352D);
    value ^= value >> 15;
    value = value.wrapping_mul(0x846C_A68B);
    value ^ (value >> 16)
}

fn u32_bytes(values: &[u32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

inventory::submit! {
    &BatchedConditionalEval as &'static dyn BenchCase
}
