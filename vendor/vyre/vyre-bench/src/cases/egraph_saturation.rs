use crate::api::case::{
    BenchCase, BenchContext, BenchError, BenchId, BenchLayer, BenchMetadata, BenchRequirements,
    BenchRun, Correctness, DeterminismClass, PreparedCase, WorkloadClass,
};
use crate::api::metric::{BenchMetrics, MetricPoint};
use crate::api::suite::SuiteKind;
use crate::cases::byte_pack::decode_u64_words;
use std::time::Instant;
use vyre_lower::rewrites;
use vyre_lower::rewrites::egraph_saturation::{saturate_descriptor, SaturationLimits};
use vyre_lower::KernelDescriptor;

/// Release benchmark case for bounded e-graph saturation coverage.
pub struct EgraphSaturation;

const SUITES: &[SuiteKind] = &[SuiteKind::Release, SuiteKind::Deep];
const MIN_BITWISE_EGRAPH_CASES: u64 = 192;
const MIN_BOOLEAN_EGRAPH_CASES: u64 = 128;

impl BenchCase for EgraphSaturation {
    fn id(&self) -> BenchId {
        BenchId("lower.egraph_saturation".to_string())
    }

    fn metadata(&self) -> BenchMetadata {
        BenchMetadata {
            id: self.id(),
            name: "Lower E-Graph Saturation".to_string(),
            description:
                "Measures bounded descriptor saturation against the release optimization corpus"
                    .to_string(),
            tags: vec![
                "lower".to_string(),
                "egraph".to_string(),
                "saturation".to_string(),
                "optimizer".to_string(),
                "release".to_string(),
            ],
            layer: BenchLayer::Backend,
            workload: WorkloadClass::Micro,
            determinism: DeterminismClass::Deterministic,
            owner_crate: "vyre-lower".to_string(),
        }
    }

    fn suites(&self) -> &'static [SuiteKind] {
        SUITES
    }

    fn requirements(&self) -> BenchRequirements {
        BenchRequirements {
            needs_gpu: false,
            needs_network: false,
            min_vram_bytes: None,
            min_input_bytes: None,
            feature_set: vec![],
        }
    }

    fn prepare(&self, _ctx: &mut BenchContext) -> Result<PreparedCase, BenchError> {
        let cases = vyre_lower::optimization_corpus::generate_release_corpus()
            .into_iter()
            .map(|case| case.descriptor)
            .collect::<Vec<_>>();
        Ok(Box::new(cases))
    }

    fn program<'a>(&self, _prepared: &'a PreparedCase) -> Option<&'a vyre_foundation::ir::Program> {
        None
    }

    fn run(
        &self,
        _ctx: &mut BenchContext,
        prepared: &mut PreparedCase,
    ) -> Result<BenchRun, BenchError> {
        let corpus = prepared
            .downcast_ref::<Vec<KernelDescriptor>>()
            .ok_or_else(|| {
                BenchError::ExecutionFailed(
                    "egraph saturation prepared payload type mismatch".to_string(),
                )
            })?;

        let baseline_start = Instant::now();
        let bitwise_case_count = corpus
            .iter()
            .filter(|desc| is_bitwise_egraph_case(desc))
            .count() as u64;
        let boolean_case_count = corpus
            .iter()
            .filter(|desc| is_boolean_egraph_case(desc))
            .count() as u64;
        let mut baseline_ops_after = 0u64;
        for desc in corpus {
            let (rewritten, _) = rewrites::run_all_with_stats(desc);
            baseline_ops_after += total_ops(&rewritten);
        }
        let baseline_ns = baseline_start.elapsed().as_nanos() as u64;

        let saturation_start = Instant::now();
        let mut input_ops = 0u64;
        let mut output_ops = 0u64;
        let mut iterations = 0u64;
        let mut equality_classes = 0u64;
        let mut applied_rewrites = 0u64;
        let mut hit_iteration_limit = 0u64;
        let mut hit_node_limit = 0u64;
        for desc in corpus {
            let (rewritten, report) = saturate_descriptor(desc, SaturationLimits::default());
            input_ops += report.input_ops as u64;
            output_ops += total_ops(&rewritten);
            iterations += report.iterations as u64;
            equality_classes += report.equality_classes as u64;
            applied_rewrites += report.applied_rewrites as u64;
            hit_iteration_limit += if report.hit_iteration_limit { 1 } else { 0 };
            hit_node_limit += if report.hit_node_limit { 1 } else { 0 };
        }
        let saturation_ns = saturation_start.elapsed().as_nanos() as u64;

        let mut output = Vec::with_capacity(11 * 8);
        for value in [
            corpus.len() as u64,
            bitwise_case_count,
            boolean_case_count,
            input_ops,
            output_ops,
            baseline_ops_after,
            iterations,
            equality_classes,
            applied_rewrites,
            hit_iteration_limit,
            hit_node_limit,
        ] {
            output.extend_from_slice(&value.to_le_bytes());
        }

        Ok(BenchRun {
            metrics: BenchMetrics {
                wall_ns: Some(saturation_ns),
                optimize_ns: Some(saturation_ns),
                ir_nodes: Some(output_ops),
                custom: vec![
                    MetricPoint {
                        name: "egraph_case_count".to_string(),
                        value: corpus.len() as u64,
                    },
                    MetricPoint {
                        name: "egraph_bitwise_case_count".to_string(),
                        value: bitwise_case_count,
                    },
                    MetricPoint {
                        name: "egraph_boolean_case_count".to_string(),
                        value: boolean_case_count,
                    },
                    MetricPoint {
                        name: "egraph_input_ops".to_string(),
                        value: input_ops,
                    },
                    MetricPoint {
                        name: "egraph_output_ops".to_string(),
                        value: output_ops,
                    },
                    MetricPoint {
                        name: "egraph_baseline_ops_after".to_string(),
                        value: baseline_ops_after,
                    },
                    MetricPoint {
                        name: "egraph_iterations".to_string(),
                        value: iterations,
                    },
                    MetricPoint {
                        name: "egraph_equality_classes".to_string(),
                        value: equality_classes,
                    },
                    MetricPoint {
                        name: "egraph_applied_rewrites".to_string(),
                        value: applied_rewrites,
                    },
                    MetricPoint {
                        name: "egraph_hit_iteration_limit".to_string(),
                        value: hit_iteration_limit,
                    },
                    MetricPoint {
                        name: "egraph_hit_node_limit".to_string(),
                        value: hit_node_limit,
                    },
                ],
                ..Default::default()
            },
            baseline_metrics: Some(BenchMetrics {
                wall_ns: Some(baseline_ns),
                optimize_ns: Some(baseline_ns),
                ir_nodes: Some(baseline_ops_after),
                ..Default::default()
            }),
            outputs: vec![output.clone()],
            baseline_outputs: Some(vec![output]),
        })
    }

    fn verify(&self, _ctx: &mut BenchContext, run: &BenchRun) -> Result<Correctness, BenchError> {
        let output = run.outputs.first().ok_or_else(|| {
            BenchError::CorrectnessViolation(
                "egraph saturation benchmark produced no structural output".to_string(),
            )
        })?;
        let words = decode_u64_words(output, "egraph saturation")?;
        if words.len() != 11 {
            return Err(BenchError::CorrectnessViolation(format!(
                "egraph saturation metric payload contained {} u64 word(s), expected 11",
                words.len()
            )));
        }
        let case_count = words[0];
        let bitwise_case_count = words[1];
        let boolean_case_count = words[2];
        let input_ops = words[3];
        let output_ops = words[4];
        let baseline_ops_after = words[5];
        let iterations = words[6];
        let equality_classes = words[7];
        let applied_rewrites = words[8];
        let hit_iteration_limit = words[9];
        let hit_node_limit = words[10];
        if case_count < 1_000 {
            return Err(BenchError::CorrectnessViolation(format!(
                "egraph saturation covered {case_count} cases, expected at least 1000"
            )));
        }
        if bitwise_case_count < MIN_BITWISE_EGRAPH_CASES {
            return Err(BenchError::CorrectnessViolation(format!(
                "egraph saturation covered {bitwise_case_count} bitwise chain cases, expected at least {MIN_BITWISE_EGRAPH_CASES}"
            )));
        }
        if boolean_case_count < MIN_BOOLEAN_EGRAPH_CASES {
            return Err(BenchError::CorrectnessViolation(format!(
                "egraph saturation covered {boolean_case_count} boolean predicate chain cases, expected at least {MIN_BOOLEAN_EGRAPH_CASES}"
            )));
        }
        if output_ops > input_ops {
            return Err(BenchError::CorrectnessViolation(format!(
                "egraph saturation grew total ops from {input_ops} to {output_ops}"
            )));
        }
        if output_ops > baseline_ops_after {
            return Err(BenchError::CorrectnessViolation(format!(
                "bounded saturation output ops {output_ops} exceeded canonical rewrite fixed point {baseline_ops_after}"
            )));
        }
        if iterations < case_count {
            return Err(BenchError::CorrectnessViolation(format!(
                "egraph saturation reported {iterations} total iterations for {case_count} cases"
            )));
        }
        if equality_classes == 0 || applied_rewrites == 0 {
            return Err(BenchError::CorrectnessViolation(format!(
                "egraph saturation reported equality_classes={equality_classes}, applied_rewrites={applied_rewrites}; release requires real saturation rewrites"
            )));
        }
        if hit_iteration_limit != 0 || hit_node_limit != 0 {
            return Err(BenchError::CorrectnessViolation(format!(
                "egraph saturation hit {hit_iteration_limit} iteration limit(s) and {hit_node_limit} node limit(s)"
            )));
        }
        Ok(Correctness::Exact)
    }
}

fn total_ops(desc: &KernelDescriptor) -> u64 {
    total_body_ops(&desc.body)
}

fn is_bitwise_egraph_case(desc: &KernelDescriptor) -> bool {
    desc.id.contains("egraph.bitand_const_chain")
        || desc.id.contains("egraph.bitor_const_chain")
        || desc.id.contains("egraph.bitxor_const_chain")
}

fn is_boolean_egraph_case(desc: &KernelDescriptor) -> bool {
    desc.id.contains("egraph.bool_and_const_chain")
        || desc.id.contains("egraph.bool_or_const_chain")
}

fn total_body_ops(body: &vyre_lower::KernelBody) -> u64 {
    body.ops.len() as u64 + body.child_bodies.iter().map(total_body_ops).sum::<u64>()
}

inventory::submit! {
    &EgraphSaturation as &'static dyn BenchCase
}
