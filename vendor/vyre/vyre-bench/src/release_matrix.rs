//! Release workload matrix for the Vyre release plan.
//!
//! The release plan requires at least twelve proof workload families and at
//! at least ten formerly CPU-only workload families with 100x targets where the
//! workload exposes enough parallelism. This module makes those
//! requirements auditable from the benchmark registry.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::api::case::{BaselineClass, BenchCase, PerformanceContract};
use crate::api::suite::SuiteKind;
use crate::registry::BenchRegistry;

const REQUIRED_CLOSED_FAMILIES: usize = 12;
const REQUIRED_CPU_SOTA_100X_FAMILIES: usize = 10;
const REQUIRED_CPU_SOTA_100X_FAMILY_IDS: &[&str] = &[
    "condition-eval",
    "string-bitmap-scatter",
    "offset-count-aggregation",
    "entropy-window",
    "quantified-condition-loops",
    "alias-reaching-def",
    "ifds-witness",
    "c-ast-traversal",
    "megakernel-queued-batches",
    "egraph-saturation",
    "sparse-output-compaction",
];

#[derive(Debug, Serialize)]
pub struct ReleaseWorkloadMatrix {
    pub schema_version: u32,
    pub required_closed_families: usize,
    pub required_cpu_sota_100x_families: Vec<&'static str>,
    pub missing_required_cpu_sota_100x_families: Vec<&'static str>,
    pub matched_required_families: usize,
    pub release_suite_case_count: usize,
    pub cpu_sota_contract_count: usize,
    pub cpu_sota_100x_contract_count: usize,
    pub cpu_sota_100x_contract_cases: Vec<String>,
    pub cpu_sota_100x_family_count: usize,
    pub cpu_sota_100x_families: Vec<&'static str>,
    pub families: Vec<ReleaseWorkloadFamilyReport>,
    pub blockers: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ReleaseWorkloadFamilyReport {
    pub id: &'static str,
    pub title: &'static str,
    pub release_plan_workload: u8,
    pub required: bool,
    pub dispatch_policy: &'static str,
    pub non_megakernel_justification: Option<&'static str>,
    pub matched_cases: Vec<String>,
    pub evidence_artifact: String,
    pub benchmark_command: Option<String>,
    pub bench_target_ids: Vec<&'static str>,
    pub cpu_sota_contracts: Vec<String>,
    pub cpu_sota_100x_cases: Vec<String>,
    pub cpu_sota_baseline_names: Vec<String>,
    pub cpu_sota_baseline_crates: Vec<String>,
    pub cpu_sota_backend_ids: Vec<String>,
    pub fair_cpu_sota_baseline_count: usize,
    pub reproducible_cuda_command: bool,
    pub max_cpu_sota_min_speedup_x: Option<f64>,
}

struct ReleaseWorkloadFamily {
    id: &'static str,
    title: &'static str,
    release_plan_workload: u8,
    required: bool,
    any_terms: &'static [&'static str],
    all_terms: &'static [&'static str],
    bench_target_id: &'static str,
    dispatch_policy: &'static str,
    non_megakernel_justification: Option<&'static str>,
}

const RELEASE_WORKLOADS: &[ReleaseWorkloadFamily] = &[
    ReleaseWorkloadFamily {
        id: "condition-eval",
        title: "Bytecode-compatible condition evaluation",
        release_plan_workload: 1,
        required: true,
        any_terms: &["release.condition_eval", "conditions.yara_like"],
        all_terms: &["condition"],
        bench_target_id: "release.workload.condition_eval",
        dispatch_policy: "megakernel",
        non_megakernel_justification: None,
    },
    ReleaseWorkloadFamily {
        id: "string-bitmap-scatter",
        title: "String bitmap scatter",
        release_plan_workload: 2,
        required: true,
        any_terms: &["release.string_bitmap_scatter"],
        all_terms: &["string", "bitmap"],
        bench_target_id: "release.workload.string_bitmap_scatter",
        dispatch_policy: "megakernel",
        non_megakernel_justification: None,
    },
    ReleaseWorkloadFamily {
        id: "offset-count-aggregation",
        title: "Offset/count/length aggregation",
        release_plan_workload: 3,
        required: true,
        any_terms: &["release.offset_count_aggregation"],
        all_terms: &["offset", "count"],
        bench_target_id: "release.workload.offset_count_aggregation",
        dispatch_policy: "megakernel",
        non_megakernel_justification: None,
    },
    ReleaseWorkloadFamily {
        id: "metadata-conditions",
        title: "PE/header/file metadata condition evaluation",
        release_plan_workload: 4,
        required: true,
        any_terms: &["metadata.condition", "pe.header", "filesize"],
        all_terms: &["metadata"],
        bench_target_id: "release.workload.pe_metadata",
        dispatch_policy: "megakernel",
        non_megakernel_justification: None,
    },
    ReleaseWorkloadFamily {
        id: "entropy-window",
        title: "Entropy/window predicates",
        release_plan_workload: 5,
        required: true,
        any_terms: &["release.entropy_window"],
        all_terms: &["entropy"],
        bench_target_id: "release.workload.entropy_window",
        dispatch_policy: "megakernel",
        non_megakernel_justification: None,
    },
    ReleaseWorkloadFamily {
        id: "quantified-condition-loops",
        title: "Bounded quantified condition loops",
        release_plan_workload: 6,
        required: true,
        any_terms: &["release.quantified_condition_loops"],
        all_terms: &["quantifier", "condition"],
        bench_target_id: "release.workload.for_any_all_n",
        dispatch_policy: "megakernel",
        non_megakernel_justification: None,
    },
    ReleaseWorkloadFamily {
        id: "alias-reaching-def",
        title: "Alias-aware reaching-definition predicates",
        release_plan_workload: 7,
        required: true,
        any_terms: &["release.alias_reaching_def", "dataflow.reaching_def.bitset"],
        all_terms: &["alias"],
        bench_target_id: "release.workload.alias_reaching_def",
        dispatch_policy: "specialized-dataflow-kernel",
        non_megakernel_justification: Some(
            "architectural: alias-aware reaching-definition workloads use sparse relation kernels with fixpoint convergence rather than independent condition-slot dispatch",
        ),
    },
    ReleaseWorkloadFamily {
        id: "ifds-witness",
        title: "IFDS reachability and witness predicates",
        release_plan_workload: 8,
        required: true,
        any_terms: &["release.ifds_witness", "dataflow.ifds"],
        all_terms: &["ifds", "witness"],
        bench_target_id: "release.workload.ifds_witness",
        dispatch_policy: "specialized-dataflow-kernel",
        non_megakernel_justification: Some(
            "architectural: IFDS witness extraction uses frontier/fact-table scheduling and predecessor reconstruction that need dataflow-specific kernels",
        ),
    },
    ReleaseWorkloadFamily {
        id: "c-ast-traversal",
        title: "C AST traversal and motif predicates",
        release_plan_workload: 9,
        required: true,
        any_terms: &["release.c_ast_traversal", "frontend.c.parser"],
        all_terms: &["parser", "ast"],
        bench_target_id: "release.workload.c_ast_traversal",
        dispatch_policy: "specialized-parser-kernel",
        non_megakernel_justification: Some(
            "architectural: C AST traversal consumes parser-owned AST buffers with table/stream access patterns that remain outside the condition megakernel for this release",
        ),
    },
    ReleaseWorkloadFamily {
        id: "megakernel-queued-batches",
        title: "Persistent megakernel queued condition batches",
        release_plan_workload: 10,
        required: true,
        any_terms: &["release.megakernel_queue", "runtime.megakernel.condition"],
        all_terms: &["megakernel", "queue"],
        bench_target_id: "release.workload.megakernel_stream",
        dispatch_policy: "megakernel",
        non_megakernel_justification: None,
    },
    ReleaseWorkloadFamily {
        id: "egraph-saturation",
        title: "E-graph rewrite saturation and optimization impact",
        release_plan_workload: 11,
        required: true,
        any_terms: &["release.egraph_saturation", "egraph", "egglog", "lower.rewrites", "optimizer.impact"],
        all_terms: &[],
        bench_target_id: "release.workload.egraph_saturation",
        dispatch_policy: "bounded-saturation-kernel",
        non_megakernel_justification: Some(
            "architectural: e-graph saturation is a bounded rewrite worklist with fuel and equivalence-class state, so it uses saturation-specific kernels",
        ),
    },
    ReleaseWorkloadFamily {
        id: "sparse-output-compaction",
        title: "Sparse fired-rule readback and output compaction",
        release_plan_workload: 12,
        required: true,
        any_terms: &["sparse.compaction", "sparse_output"],
        all_terms: &["sparse"],
        bench_target_id: "release.workload.conformance_sparse_readback",
        dispatch_policy: "megakernel",
        non_megakernel_justification: None,
    },
    ReleaseWorkloadFamily {
        id: "callgraph-reachability",
        title: "Graph traversal and callgraph reachability",
        release_plan_workload: 13,
        required: true,
        any_terms: &["callgraph.reachability", "graph.reachability"],
        all_terms: &["reachability"],
        bench_target_id: "release.workload.callgraph_reachability",
        dispatch_policy: "specialized-graph-kernel",
        non_megakernel_justification: Some(
            "architectural: callgraph reachability is frontier graph traversal with convergence state, not independent rule-condition slot evaluation",
        ),
    },
    ReleaseWorkloadFamily {
        id: "compound-fused-filter",
        title: "Compound resident literal/dataflow/score filtering",
        release_plan_workload: 14,
        required: false,
        any_terms: &["compound.pipeline.fused_filter", "compound"],
        all_terms: &["resident", "dataflow"],
        bench_target_id: "release.workload.compound_fused_filter",
        dispatch_policy: "resident-fused-kernel",
        non_megakernel_justification: Some(
            "architectural: compound filtering fuses independent matching, dataflow, score, and taint-class predicates into one resident pass without condition-slot queue orchestration",
        ),
    },
    ReleaseWorkloadFamily {
        id: "adaptive-routing",
        title: "GPU-resident adaptive workload routing",
        release_plan_workload: 15,
        required: false,
        any_terms: &["runtime.adaptive_routing", "adaptive-routing"],
        all_terms: &["resident", "scheduler"],
        bench_target_id: "release.workload.adaptive_routing",
        dispatch_policy: "resident-routing-kernel",
        non_megakernel_justification: Some(
            "architectural: adaptive routing is GPU-side scheduling metadata generation rather than execution of a queued rule opcode stream",
        ),
    },
    ReleaseWorkloadFamily {
        id: "quantized-linear",
        title: "Fused grouped INT4 linear inference",
        release_plan_workload: 16,
        required: false,
        any_terms: &["nn.linear_4bit_affine_grouped", "quantized"],
        all_terms: &["resident", "inference"],
        bench_target_id: "release.workload.quantized_linear",
        dispatch_policy: "resident-fused-kernel",
        non_megakernel_justification: Some(
            "architectural: grouped INT4 linear fuses packed weight decode, scale/zero-point sidecars, and accumulation in one inference kernel instead of queueing scalar condition opcodes",
        ),
    },
];

pub fn build_release_matrix(registry: &BenchRegistry) -> ReleaseWorkloadMatrix {
    let release_cases: Vec<_> = registry
        .iter()
        .filter(|case| case.active_in_suite(SuiteKind::Release))
        .collect();

    let mut cpu_sota_contract_ids = BTreeSet::new();
    let mut cpu_sota_100x_contract_ids = BTreeSet::new();
    for case in &release_cases {
        if let Some(contract) = case.performance_contract() {
            for baseline in &contract.baselines {
                if matches!(baseline.class, BaselineClass::CpuSota) {
                    let id = case.id().0;
                    cpu_sota_contract_ids.insert(id.clone());
                    if baseline.min_speedup_x >= 100.0 {
                        cpu_sota_100x_contract_ids.insert(id);
                    }
                }
            }
        }
    }

    let mut families = Vec::new();
    for family in RELEASE_WORKLOADS {
        families.push(build_family_report(family, &release_cases));
    }

    let matched_required_families = families
        .iter()
        .filter(|family| family.required && !family.matched_cases.is_empty())
        .count();
    let mut cpu_sota_100x_families = families
        .iter()
        .filter(|family| {
            family
                .matched_cases
                .iter()
                .any(|case| cpu_sota_100x_contract_ids.contains(case))
        })
        .map(|family| family.id)
        .collect::<Vec<_>>();
    cpu_sota_100x_families.sort_unstable();
    let cpu_sota_100x_family_count = cpu_sota_100x_families.len();
    let missing_required_cpu_sota_100x_families = REQUIRED_CPU_SOTA_100X_FAMILY_IDS
        .iter()
        .copied()
        .filter(|required| {
            !cpu_sota_100x_families
                .iter()
                .any(|family| *family == *required)
        })
        .collect::<Vec<_>>();
    let cpu_sota_100x_contract_cases = cpu_sota_100x_contract_ids.iter().cloned().collect();
    let mut blockers = Vec::new();
    if matched_required_families < REQUIRED_CLOSED_FAMILIES {
        blockers.push(format!(
            "release suite covers {matched_required_families} required workload families; needs at least {REQUIRED_CLOSED_FAMILIES}"
        ));
    }
    for family in &families {
        if family.required && family.matched_cases.is_empty() {
            blockers.push(format!(
                "release workload {} `{}` has no active release benchmark case",
                family.release_plan_workload, family.id
            ));
        }
        if family.required && family.bench_target_ids.is_empty() {
            blockers.push(format!(
                "release workload {} `{}` has no canonical BENCH_TARGETS.toml target id",
                family.release_plan_workload, family.id
            ));
        }
        if family.required
            && !family.matched_cases.is_empty()
            && family.cpu_sota_contracts.is_empty()
        {
            blockers.push(format!(
                "release workload {} `{}` has active cases but no CPU-SOTA baseline contract",
                family.release_plan_workload, family.id
            ));
        }
        if family.required
            && !family.matched_cases.is_empty()
            && family.fair_cpu_sota_baseline_count == 0
        {
            blockers.push(format!(
                "release workload {} `{}` has no fair CPU-SOTA baseline crate with CUDA backend binding",
                family.release_plan_workload, family.id
            ));
        }
        if family.required && !family.matched_cases.is_empty() && !family.reproducible_cuda_command
        {
            blockers.push(format!(
                "release workload {} `{}` has no reproducible cargo_full CUDA benchmark command",
                family.release_plan_workload, family.id
            ));
        }
        if family.required
            && family.dispatch_policy != "megakernel"
            && family
                .non_megakernel_justification
                .is_none_or(|justification| justification.len() < 48)
        {
            blockers.push(format!(
                "release workload {} `{}` uses non-megakernel dispatch policy `{}` without a concrete architectural or measured justification",
                family.release_plan_workload, family.id, family.dispatch_policy
            ));
        }
    }
    if cpu_sota_100x_contract_ids.len() < REQUIRED_CPU_SOTA_100X_FAMILIES {
        blockers.push(format!(
            "release suite declares {} CPU-SOTA 100x performance contract(s); needs at least {REQUIRED_CPU_SOTA_100X_FAMILIES}",
            cpu_sota_100x_contract_ids.len()
        ));
    }
    if cpu_sota_100x_family_count < REQUIRED_CPU_SOTA_100X_FAMILIES {
        blockers.push(format!(
            "release suite covers {cpu_sota_100x_family_count} CPU-SOTA 100x workload family/families; needs at least {REQUIRED_CPU_SOTA_100X_FAMILIES}"
        ));
    }
    for family in &missing_required_cpu_sota_100x_families {
        blockers.push(format!(
            "release suite must prove CPU-SOTA 100x for required family `{family}`"
        ));
    }

    ReleaseWorkloadMatrix {
        schema_version: 1,
        required_closed_families: REQUIRED_CLOSED_FAMILIES,
        required_cpu_sota_100x_families: REQUIRED_CPU_SOTA_100X_FAMILY_IDS.to_vec(),
        missing_required_cpu_sota_100x_families,
        matched_required_families,
        release_suite_case_count: release_cases.len(),
        cpu_sota_contract_count: cpu_sota_contract_ids.len(),
        cpu_sota_100x_contract_count: cpu_sota_100x_contract_ids.len(),
        cpu_sota_100x_contract_cases,
        cpu_sota_100x_family_count,
        cpu_sota_100x_families,
        families,
        blockers,
    }
}

pub fn emit_release_matrix(
    matrix: &ReleaseWorkloadMatrix,
    format: &str,
    output: Option<&str>,
) -> anyhow::Result<()> {
    let rendered = render_release_matrix(matrix, format)?;
    if let Some(output) = output {
        let output = Path::new(output);
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(output, rendered)?;
        return Ok(());
    }
    print!("{rendered}");
    Ok(())
}

fn render_release_matrix(matrix: &ReleaseWorkloadMatrix, format: &str) -> anyhow::Result<String> {
    if format == "json" {
        return Ok(format!("{}\n", serde_json::to_string_pretty(matrix)?));
    }

    let mut out = String::new();
    out.push_str(&format!(
        "release workload families: {}/{} required, {} release cases, {} CPU-SOTA contracts, {} CPU-SOTA 100x contracts",
        matrix.matched_required_families,
        matrix.required_closed_families,
        matrix.release_suite_case_count,
        matrix.cpu_sota_contract_count,
        matrix.cpu_sota_100x_contract_count
    ));
    out.push('\n');
    if !matrix.cpu_sota_100x_families.is_empty() {
        out.push_str(&format!(
            "CPU-SOTA 100x release families: {}\n",
            matrix.cpu_sota_100x_families.join(", ")
        ));
    }
    for family in &matrix.families {
        let status = if family.matched_cases.is_empty() {
            "open"
        } else {
            "covered"
        };
        out.push_str(&format!(
            "W{} {:<28} {:<7} {}",
            family.release_plan_workload, family.id, status, family.title
        ));
        out.push('\n');
        out.push_str(&format!("  dispatch-policy: {}\n", family.dispatch_policy));
        if let Some(justification) = family.non_megakernel_justification {
            out.push_str(&format!(
                "  non-megakernel-justification: {justification}\n"
            ));
        }
        for case in &family.matched_cases {
            out.push_str(&format!("  case: {case}\n"));
        }
        for contract in &family.cpu_sota_contracts {
            out.push_str(&format!("  contract: {contract}\n"));
        }
        if !family.cpu_sota_baseline_crates.is_empty() {
            out.push_str(&format!(
                "  cpu-baseline-crates: {}\n",
                family.cpu_sota_baseline_crates.join(", ")
            ));
        }
        if !family.cpu_sota_backend_ids.is_empty() {
            out.push_str(&format!(
                "  contract-backends: {}\n",
                family.cpu_sota_backend_ids.join(", ")
            ));
        }
        out.push_str(&format!("  artifact: {}\n", family.evidence_artifact));
        out.push_str(&format!(
            "  bench-targets: {}\n",
            family.bench_target_ids.join(", ")
        ));
        if let Some(command) = &family.benchmark_command {
            out.push_str(&format!("  command: {command}\n"));
        }
    }
    if !matrix.blockers.is_empty() {
        out.push_str("blockers:\n");
        for blocker in &matrix.blockers {
            out.push_str(&format!("  - {blocker}\n"));
        }
    }
    Ok(out)
}


pub fn enforce_release_matrix(matrix: &ReleaseWorkloadMatrix) -> anyhow::Result<()> {
    if matrix.blockers.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "release workload matrix has {} blocker(s): {}",
        matrix.blockers.len(),
        matrix.blockers.join("; ")
    )
}

fn build_family_report(
    family: &ReleaseWorkloadFamily,
    release_cases: &[&'static dyn BenchCase],
) -> ReleaseWorkloadFamilyReport {
    let mut matched_cases = Vec::new();
    let mut cpu_sota_contracts = Vec::new();
    let mut cpu_sota_100x_cases = Vec::new();
    let mut cpu_sota_baseline_names = BTreeSet::new();
    let mut cpu_sota_baseline_crates = BTreeSet::new();
    let mut cpu_sota_backend_ids = BTreeSet::new();
    let mut max_cpu_sota_min_speedup_x: Option<f64> = None;

    for case in release_cases {
        if !case_matches_family(*case, family) {
            continue;
        }
        let id = case.id().0;
        matched_cases.push(id.clone());
        if has_cpu_sota_100x_contract(case.performance_contract().as_ref()) {
            cpu_sota_100x_cases.push(id.clone());
        }
        collect_cpu_sota_contracts(
            &id,
            case.performance_contract().as_ref(),
            &mut cpu_sota_contracts,
            &mut cpu_sota_baseline_names,
            &mut cpu_sota_baseline_crates,
            &mut cpu_sota_backend_ids,
            &mut max_cpu_sota_min_speedup_x,
        );
    }

    matched_cases.sort();
    cpu_sota_100x_cases.sort();
    let evidence_artifact = format!(
        "release/evidence/benchmarks/workload-{:02}-{}.json",
        family.release_plan_workload, family.id
    );
    let benchmark_command = matched_cases.first().map(|case_id| {
        format!(
            "cargo_full run -p vyre-bench -- run --suite release --case {case_id} --backend cuda --enforce-budgets --output {evidence_artifact}"
        )
    });
    cpu_sota_contracts.sort();
    let cpu_sota_baseline_names = cpu_sota_baseline_names.into_iter().collect::<Vec<_>>();
    let cpu_sota_baseline_crates = cpu_sota_baseline_crates.into_iter().collect::<Vec<_>>();
    let cpu_sota_backend_ids = cpu_sota_backend_ids.into_iter().collect::<Vec<_>>();
    let fair_cpu_sota_baseline_count = if cpu_sota_baseline_crates.is_empty()
        || cpu_sota_baseline_names.is_empty()
        || !cpu_sota_backend_ids.iter().any(|backend| backend == "cuda")
    {
        0
    } else {
        cpu_sota_baseline_crates.len()
    };
    let reproducible_cuda_command = benchmark_command.as_ref().is_some_and(|command| {
        command.contains("cargo_full")
            && command.contains("--backend cuda")
            && command.contains("--enforce-budgets")
            && command.contains(&evidence_artifact)
    });
    ReleaseWorkloadFamilyReport {
        id: family.id,
        title: family.title,
        release_plan_workload: family.release_plan_workload,
        required: family.required,
        dispatch_policy: family.dispatch_policy,
        non_megakernel_justification: family.non_megakernel_justification,
        matched_cases,
        evidence_artifact,
        benchmark_command,
        bench_target_ids: vec![family.bench_target_id],
        cpu_sota_contracts,
        cpu_sota_100x_cases,
        cpu_sota_baseline_names,
        cpu_sota_baseline_crates,
        cpu_sota_backend_ids,
        fair_cpu_sota_baseline_count,
        reproducible_cuda_command,
        max_cpu_sota_min_speedup_x,
    }
}

fn has_cpu_sota_100x_contract(contract: Option<&PerformanceContract>) -> bool {
    contract.is_some_and(|contract| {
        contract.baselines.iter().any(|baseline| {
            matches!(baseline.class, BaselineClass::CpuSota) && baseline.min_speedup_x >= 100.0
        })
    })
}

fn case_matches_family(case: &'static dyn BenchCase, family: &ReleaseWorkloadFamily) -> bool {
    let metadata = case.metadata();
    let id = metadata.id.0.to_ascii_lowercase();
    let name = metadata.name.to_ascii_lowercase();
    let description = metadata.description.to_ascii_lowercase();
    let tags: Vec<String> = metadata
        .tags
        .iter()
        .map(|tag| tag.to_ascii_lowercase())
        .collect();
    let any_match = family.any_terms.iter().any(|term| {
        let term = term.to_ascii_lowercase();
        id.contains(&term)
            || name.contains(&term)
            || description.contains(&term)
            || tags.iter().any(|tag| tag.contains(&term))
    });
    let all_match = !family.all_terms.is_empty()
        && family.all_terms.iter().all(|term| {
            let term = term.to_ascii_lowercase();
            id.contains(&term)
                || name.contains(&term)
                || description.contains(&term)
                || tags.iter().any(|tag| tag.contains(&term))
        });
    any_match || all_match
}

fn collect_cpu_sota_contracts(
    case_id: &str,
    contract: Option<&PerformanceContract>,
    cpu_sota_contracts: &mut Vec<String>,
    cpu_sota_baseline_names: &mut BTreeSet<String>,
    cpu_sota_baseline_crates: &mut BTreeSet<String>,
    cpu_sota_backend_ids: &mut BTreeSet<String>,
    max_cpu_sota_min_speedup_x: &mut Option<f64>,
) {
    let Some(contract) = contract else {
        return;
    };
    for baseline in &contract.baselines {
        if !matches!(baseline.class, BaselineClass::CpuSota) {
            continue;
        }
        cpu_sota_contracts.push(format!(
            "{} => {} {}x",
            case_id, baseline.name, baseline.min_speedup_x
        ));
        if !baseline.crate_name.trim().is_empty() {
            cpu_sota_baseline_crates.insert(baseline.crate_name.clone());
        }
        if !baseline.name.trim().is_empty() {
            cpu_sota_baseline_names.insert(baseline.name.clone());
        }
        for backend in &baseline.backend_ids {
            cpu_sota_backend_ids.insert(backend.clone());
        }
        *max_cpu_sota_min_speedup_x = Some(
            max_cpu_sota_min_speedup_x
                .unwrap_or(0.0)
                .max(baseline.min_speedup_x),
        );
    }
}

