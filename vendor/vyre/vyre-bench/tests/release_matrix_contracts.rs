//! Release matrix coverage contracts. Asserts that every required
//! workload family declared in `vyre-bench::release_matrix` ships with
//! a registered runner, so a release sweep cannot silently skip a
//! family.

use std::path::Path;

use serde_json::Value;
use vyre_bench::api::case::{BaselineClass, WorkloadClass};
use vyre_bench::api::suite::SuiteKind;

#[test]
fn release_matrix_covers_required_workload_families() {
    let registry = vyre_bench::registry::collect_all();
    let matrix = vyre_bench::release_matrix::build_release_matrix(&registry);
    assert!(
        matrix.required_closed_families >= 12,
        "Fix: release matrix declares {} required workload families; release requires at least 12 proof workloads.",
        matrix.required_closed_families
    );
    assert!(
        matrix
            .families
            .iter()
            .filter(|family| family.required)
            .count()
            >= 12,
        "Fix: release matrix must enumerate at least 12 required proof workload families."
    );
    assert!(
        matrix.matched_required_families >= matrix.required_closed_families,
        "Fix: release matrix covers {} workload families, but release requires at least {}. Blockers: {:?}",
        matrix.matched_required_families,
        matrix.required_closed_families,
        matrix.blockers
    );
}

#[test]
fn release_matrix_has_cpu_sota_hundred_x_contract() {
    let registry = vyre_bench::registry::collect_all();
    let matrix = vyre_bench::release_matrix::build_release_matrix(&registry);
    let required_cases = [
        "release.condition_eval.1m",
        "release.string_bitmap_scatter.1m",
        "release.offset_count_aggregation.1m",
        "release.entropy_window.1m",
        "release.quantified_condition_loops.1m",
        "release.alias_reaching_def.1m",
        "release.ifds_witness.1m",
        "release.c_ast_traversal.1m",
        "release.megakernel_queue.1m",
        "release.egraph_saturation.1m",
        "sparse.compaction.count.1m",
    ];
    assert!(
        matrix.cpu_sota_100x_contract_count >= 10,
        "Fix: release matrix must include at least ten CPU-SOTA 100x contracts for the CUDA release proof workloads."
    );
    assert!(
        matrix.cpu_sota_100x_family_count >= 10,
        "Fix: release matrix must cover at least ten CPU-SOTA 100x workload families."
    );
    assert!(
        matrix.missing_required_cpu_sota_100x_families.is_empty(),
        "Fix: release matrix is missing required CPU-SOTA 100x family/families: {:?}",
        matrix.missing_required_cpu_sota_100x_families
    );
    for case_id in required_cases {
        assert!(
            matrix
                .cpu_sota_100x_contract_cases
                .iter()
                .any(|actual| actual == case_id),
            "Fix: release matrix does not list required CPU-SOTA 100x case `{case_id}`."
        );
    }
}

#[test]
fn release_matrix_contains_current_required_family_ids() {
    let registry = vyre_bench::registry::collect_all();
    let matrix = vyre_bench::release_matrix::build_release_matrix(&registry);
    let required_families = [
        "condition-eval",
        "string-bitmap-scatter",
        "offset-count-aggregation",
        "metadata-conditions",
        "entropy-window",
        "quantified-condition-loops",
        "alias-reaching-def",
        "ifds-witness",
        "c-ast-traversal",
        "megakernel-queued-batches",
        "egraph-saturation",
        "sparse-output-compaction",
        "callgraph-reachability",
    ];
    for family_id in required_families {
        let Some(family) = matrix.families.iter().find(|family| family.id == family_id) else {
            panic!("Fix: release matrix is missing required family `{family_id}`.");
        };
        assert!(
            family.required,
            "Fix: release matrix family `{family_id}` must be release-required."
        );
        assert!(
            !family.matched_cases.is_empty(),
            "Fix: release matrix family `{family_id}` has no active release case."
        );
        assert!(
            family
                .bench_target_ids
                .iter()
                .all(|target| target.starts_with("release.workload.")),
            "Fix: release matrix family `{family_id}` must map to canonical release benchmark target ids."
        );
    }
}

#[test]
fn release_suite_proves_compiler_grade_gpu_thesis_axes() {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Fix: vyre-bench must live under the workspace root")
        .join("release/evidence/benchmarks/compiler-grade-thesis-workloads.json");
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(&manifest_path)
            .expect("Fix: compiler-grade thesis benchmark manifest must be readable"),
    )
    .expect("Fix: compiler-grade thesis benchmark manifest must be valid JSON");
    let axes = manifest["axes"]
        .as_array()
        .expect("Fix: compiler-grade thesis benchmark manifest must define an axes array");
    assert!(
        axes.len() >= manifest["minimum_axes"].as_u64().unwrap_or(7) as usize,
        "Fix: compiler-grade thesis benchmark manifest has too few axes."
    );

    let registry = vyre_bench::registry::collect_all();
    for axis in axes {
        let axis_id = axis["id"]
            .as_str()
            .expect("Fix: every thesis benchmark axis needs an id");
        let terms = axis["terms"]
            .as_array()
            .expect("Fix: every thesis benchmark axis needs search terms")
            .iter()
            .map(|term| {
                term.as_str()
                    .expect("Fix: thesis benchmark axis terms must be strings")
            })
            .collect::<Vec<_>>();
        let minimum_matching_cases = axis["minimum_matching_cases"].as_u64().unwrap_or(1) as usize;
        let minimum_input_bytes = axis["minimum_input_bytes"].as_u64().unwrap_or(1_048_576);
        let evidence_artifact = axis["evidence_artifact"]
            .as_str()
            .expect("Fix: every thesis benchmark axis needs an evidence artifact");
        let artifact_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("Fix: vyre-bench must live under the workspace root")
            .join(evidence_artifact);
        assert!(
            artifact_path.exists(),
            "Fix: thesis benchmark axis `{axis_id}` references missing artifact `{evidence_artifact}`."
        );

        let mut matched = Vec::new();
        for case in registry
            .iter()
            .filter(|case| case.active_in_suite(SuiteKind::Release))
        {
            let metadata = case.metadata();
            if !case_matches_any_axis_term(&metadata, &terms) {
                continue;
            }
            let requirements = case.requirements();
            let contract = case.performance_contract();
            if matches!(metadata.workload, WorkloadClass::Macro)
                && requirements.needs_gpu
                && requirements.min_input_bytes.unwrap_or(0) >= minimum_input_bytes
                && contract_has_cuda_cpu_sota_baseline(contract.as_ref())
            {
                matched.push(metadata.id.0);
            }
        }

        assert!(
            matched.len() >= minimum_matching_cases,
            "Fix: thesis benchmark axis `{axis_id}` matched eligible cases {matched:?}; needs at least {minimum_matching_cases} release macro GPU workload(s) with >= {minimum_input_bytes} input bytes and CUDA-bound CPU-SOTA baselines."
        );
    }
}

#[test]
fn cuda_release_suite_artifact_proves_real_gpu_macro_workloads() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Fix: vyre-bench must live under the workspace root");
    let suite_path = workspace.join("release/evidence/benchmarks/cuda-release-suite.json");
    let suite = read_json(&suite_path);
    assert_eq!(
        suite["schema_version"], 2,
        "Fix: CUDA release benchmark suite evidence must use schema v2."
    );
    assert_eq!(
        suite["backend"], "cuda",
        "Fix: CUDA release benchmark suite must be CUDA-bound evidence."
    );
    assert!(
        json_usize(&suite, "family_count") >= 13,
        "Fix: CUDA release benchmark suite must cover at least 13 macro workload families."
    );

    let artifacts = suite["artifacts"]
        .as_array()
        .expect("Fix: CUDA release suite must list artifacts.");
    let statuses = suite["artifact_statuses"]
        .as_array()
        .expect("Fix: CUDA release suite must list artifact_statuses.");
    assert_eq!(
        artifacts.len(),
        statuses.len(),
        "Fix: CUDA release suite artifacts and statuses must have one row per workload."
    );

    let mut covered_families = std::collections::BTreeSet::new();
    for status in statuses {
        let path = json_str(status, "path");
        assert!(
            artifacts
                .iter()
                .any(|artifact| artifact.as_str() == Some(path)),
            "Fix: CUDA release suite status references `{path}` but artifacts[] does not."
        );
        assert_eq!(
            status["exists"], true,
            "Fix: CUDA workload artifact `{path}` must exist."
        );
        assert!(
            json_usize(status, "bytes") > 16_000,
            "Fix: CUDA workload artifact `{path}` is too small to be real benchmark evidence."
        );
        assert!(
            status["read_error"].is_null(),
            "Fix: CUDA workload artifact `{path}` must be readable."
        );
        assert_eq!(
            json_str(status, "selected_backend"),
            "cuda",
            "Fix: CUDA workload artifact `{path}` status must be CUDA-selected."
        );
        assert!(
            json_str(status, "gpu_model").contains("NVIDIA"),
            "Fix: CUDA workload artifact `{path}` must record NVIDIA GPU provenance."
        );
        assert!(
            json_usize(status, "gpu_memory_total_mib") >= 24 * 1024,
            "Fix: CUDA workload artifact `{path}` must record release-class GPU memory."
        );
        assert!(
            json_usize(status, "min_wall_samples") >= 30
                && json_usize(status, "min_baseline_wall_samples") >= 30,
            "Fix: CUDA workload artifact `{path}` must record at least 30 GPU and baseline timing samples."
        );
        assert!(
            json_usize(status, "case_count") >= 1 && json_usize(status, "failed_count") == 0,
            "Fix: CUDA workload artifact `{path}` must contain at least one passing benchmark case."
        );
        assert_eq!(
            status["cpu_sota_100x_required"], true,
            "Fix: CUDA workload artifact `{path}` must require the CPU-SOTA 100x release contract."
        );
        assert!(
            json_usize(status, "cpu_sota_100x_contract_cases") >= 1
                && json_usize(status, "cpu_sota_100x_passing_cases")
                    == json_usize(status, "cpu_sota_100x_contract_cases"),
            "Fix: CUDA workload artifact `{path}` must pass every CPU-SOTA 100x contract case."
        );
        assert!(
            status["blockers"].as_array().is_some_and(Vec::is_empty),
            "Fix: CUDA workload artifact `{path}` must not carry blockers."
        );

        let artifact = read_json(&workspace.join(path));
        assert_eq!(
            artifact["schema"], "vyre-bench.result.v1",
            "Fix: `{path}` must be a vyre-bench result artifact."
        );
        assert_eq!(
            artifact["suite"], "release",
            "Fix: `{path}` must be release-suite evidence."
        );
        assert_eq!(
            artifact["selected_backend"], "cuda",
            "Fix: `{path}` must be CUDA evidence."
        );
        assert_eq!(
            artifact["environment"]["has_gpu"], true,
            "Fix: `{path}` must record a live GPU environment."
        );
        assert!(
            artifact["environment"]["features"]
                .as_array()
                .expect("Fix: benchmark environment features must be an array.")
                .iter()
                .any(|feature| feature.as_str() == Some("backend.usable.cuda")),
            "Fix: `{path}` must prove CUDA was usable, not merely linked."
        );
        let cases = artifact["cases"]
            .as_array()
            .expect("Fix: benchmark artifact cases must be an array.");
        assert!(
            !cases.is_empty(),
            "Fix: `{path}` must include benchmark cases."
        );
        for case in cases {
            assert_eq!(
                case["status"], "pass",
                "Fix: `{path}` has a non-passing benchmark case."
            );
            assert_eq!(
                case["backend_id"], "cuda",
                "Fix: `{path}` contains a non-CUDA case."
            );
            assert_eq!(
                case["workload_class"], "Macro",
                "Fix: `{path}` must prove macro workloads, not primitive-only microbenchmarks."
            );
            assert_eq!(
                case["needs_gpu"], true,
                "Fix: `{path}` release cases must require GPU execution."
            );
            assert!(
                case["min_input_bytes"].as_u64().unwrap_or(0) >= 1_048_576,
                "Fix: `{path}` release cases must use at least 1 MiB input."
            );
            assert!(
                case["performance"]["contract_passed"]
                    .as_bool()
                    .unwrap_or(false),
                "Fix: `{path}` benchmark case failed its performance contract."
            );
            assert!(
                case["performance"]["speedup_x"].as_f64().unwrap_or(0.0) >= 100.0,
                "Fix: `{path}` benchmark case must prove at least 100x speedup."
            );
            assert!(
                case["metrics"]["wall_ns"]["samples"].as_u64().unwrap_or(0) >= 30,
                "Fix: `{path}` benchmark case must contain at least 30 wall-clock samples."
            );
        }
        covered_families.insert(json_str(status, "family_id").to_owned());
    }

    assert!(
        covered_families.len() >= 13,
        "Fix: CUDA release suite covered only {} families: {:?}.",
        covered_families.len(),
        covered_families
    );
}

#[test]
fn readme_benchmark_section_leads_with_cuda_macro_release_evidence() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Fix: vyre-bench must live under the workspace root.");
    let readme = std::fs::read_to_string(workspace.join("README.md"))
        .expect("Fix: README.md must remain readable.");
    let section = readme
        .split("## Benchmarks\n")
        .nth(1)
        .expect("Fix: README.md must contain a Benchmarks section.")
        .split("Auto-registration is handled by link-time")
        .next()
        .expect("Fix: README.md benchmark section must precede registration docs.");

    assert!(
        section.contains("release/evidence/benchmarks/cuda-release-suite.json"),
        "Fix: README benchmark claims must point at CUDA release-suite evidence."
    );
    assert!(
        section.contains("13 macro workload families")
            && section.contains("CPU-SOTA 100x contract for every family"),
        "Fix: README benchmark section must lead with macro release workloads and the 100x CPU-SOTA gate."
    );
    for required_case in [
        "release.condition_eval.1m",
        "release.string_bitmap_scatter.1m",
        "release.offset_count_aggregation.1m",
        "conditions.yara_like.eval.1m",
        "release.entropy_window.1m",
        "release.quantified_condition_loops.1m",
        "release.alias_reaching_def.1m",
        "release.ifds_witness.1m",
        "release.c_ast_traversal.1m",
        "release.megakernel_queue.1m",
        "release.egraph_saturation.1m",
        "sparse.compaction.count.1m",
        "callgraph.reachability.step.262k",
    ] {
        assert!(
            section.contains(required_case),
            "Fix: README benchmark section must include release case `{required_case}`."
        );
    }
    assert!(
        !section.contains("| primitive.") && !section.contains(">1048576"),
        "Fix: README benchmark section must not resurrect the stale primitive-only crossover table."
    );
}

fn case_matches_any_axis_term(
    metadata: &vyre_bench::api::case::BenchMetadata,
    terms: &[&str],
) -> bool {
    let id = metadata.id.0.to_ascii_lowercase();
    let name = metadata.name.to_ascii_lowercase();
    let description = metadata.description.to_ascii_lowercase();
    let tags = metadata
        .tags
        .iter()
        .map(|tag| tag.to_ascii_lowercase())
        .collect::<Vec<_>>();
    terms.iter().any(|term| {
        let term = term.to_ascii_lowercase();
        id.contains(&term)
            || name.contains(&term)
            || description.contains(&term)
            || tags.iter().any(|tag| tag.contains(&term))
    })
}

fn contract_has_cuda_cpu_sota_baseline(
    contract: Option<&vyre_bench::api::case::PerformanceContract>,
) -> bool {
    contract.is_some_and(|contract| {
        contract.baselines.iter().any(|baseline| {
            matches!(&baseline.class, BaselineClass::CpuSota)
                && baseline.backend_ids.iter().any(|backend| backend == "cuda")
                && baseline.min_speedup_x > 1.0
                && !baseline.name.trim().is_empty()
                && !baseline.crate_name.trim().is_empty()
        })
    })
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("Fix: `{}` must be readable: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("Fix: `{}` must be valid JSON: {error}", path.display()))
}

fn json_str<'a>(json: &'a Value, key: &str) -> &'a str {
    json[key]
        .as_str()
        .unwrap_or_else(|| panic!("Fix: JSON field `{key}` must be a string."))
}

fn json_usize(json: &Value, key: &str) -> usize {
    json[key]
        .as_u64()
        .unwrap_or_else(|| panic!("Fix: JSON field `{key}` must be an unsigned integer."))
        .try_into()
        .unwrap_or_else(|_| panic!("Fix: JSON field `{key}` must fit usize."))
}

#[test]
fn release_matrix_reports_no_structural_blockers() {
    let registry = vyre_bench::registry::collect_all();
    let matrix = vyre_bench::release_matrix::build_release_matrix(&registry);
    assert!(
        matrix.blockers.is_empty(),
        "Fix: release workload matrix still has structural blockers: {:?}",
        matrix.blockers
    );
}

#[test]
fn release_matrix_links_workloads_to_artifact_commands() {
    let registry = vyre_bench::registry::collect_all();
    let matrix = vyre_bench::release_matrix::build_release_matrix(&registry);
    for family in matrix
        .families
        .iter()
        .filter(|family| family.required && !family.matched_cases.is_empty())
    {
        assert!(
            family
                .evidence_artifact
                .starts_with("release/evidence/benchmarks/workload-"),
            "Fix: workload `{}` must point at a release benchmark evidence artifact, got `{}`.",
            family.id,
            family.evidence_artifact
        );
        let command = family.benchmark_command.as_deref().unwrap_or("");
        assert!(
            command.starts_with("cargo_full ")
                && command.contains("vyre-bench")
                && command.contains("--suite release")
                && command.contains("--backend cuda")
                && command.contains("--enforce-budgets")
                && command.contains(&family.evidence_artifact),
            "Fix: workload `{}` must publish a reproducible CUDA release benchmark command, got `{command}`.",
            family.id
        );
    }
}

#[test]
fn release_matrix_commands_prefer_release_defining_cpu_sota_cases() {
    let registry = vyre_bench::registry::collect_all();
    let matrix = vyre_bench::release_matrix::build_release_matrix(&registry);
    let expected = [
        ("condition-eval", "release.condition_eval.1m"),
        (
            "offset-count-aggregation",
            "release.offset_count_aggregation.1m",
        ),
        ("entropy-window", "release.entropy_window.1m"),
        ("alias-reaching-def", "release.alias_reaching_def.1m"),
        ("ifds-witness", "release.ifds_witness.1m"),
        ("c-ast-traversal", "release.c_ast_traversal.1m"),
        ("egraph-saturation", "release.egraph_saturation.1m"),
        ("sparse-output-compaction", "sparse.compaction.count.1m"),
    ];

    for (family_id, case_id) in expected {
        let family = matrix
            .families
            .iter()
            .find(|family| family.id == family_id)
            .unwrap_or_else(|| panic!("Fix: release matrix missing family `{family_id}`."));
        let command = family.benchmark_command.as_deref().unwrap_or("");
        assert!(
            command.contains(&format!("--case {case_id} ")),
            "Fix: workload `{family_id}` command must prefer release-defining case `{case_id}`, got `{command}`."
        );
    }
}
