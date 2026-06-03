//! Organization contracts for the self-substrate crate.

use std::path::Path;

const GRAPH_WRAPPERS: &[&str] = &[
    "adaptive_traverse.rs",
    "alias_registry.rs",
    "csr_bidirectional.rs",
    "csr_forward_or_changed.rs",
    "csr_frontier_queue_batch_memory.rs",
    "csr_frontier_queue_batch_resident.rs",
    "csr_frontier_queue_resident.rs",
    "dominator_frontier.rs",
    "exploded.rs",
    "level_wave_pass.rs",
    "motif.rs",
    "path_reconstruct.rs",
    "persistent_bfs.rs",
    "toposort.rs",
    "union_find_emit.rs",
    "vast_tree_walk.rs",
];

const CONSOLIDATED_GRAPH_WRAPPERS: &[(&str, &str)] = &[
    ("adaptive_traverse.rs", "adaptive_traverse"),
    ("alias_registry.rs", "alias_registry"),
    ("csr_bidirectional.rs", "csr_bidirectional"),
    ("csr_forward_or_changed.rs", "csr_forward_or_changed"),
    ("dominator_frontier.rs", "dominator_frontier"),
    ("exploded.rs", "exploded"),
    ("motif.rs", "motif"),
    ("path_reconstruct.rs", "path_reconstruct"),
    ("persistent_bfs.rs", "persistent_bfs"),
    ("toposort.rs", "toposort"),
    ("vast_tree_walk.rs", "vast_tree_walk"),
];

const RELEASE_GATES: &[&str] = &[
    "release_checklist_gate.rs",
    "release_completion_audit.rs",
    "release_gap_findings.rs",
    "release_gpu_evidence.rs",
    "release_launch_sequence.rs",
    "release_scope_docs.rs",
    "release_validation_matrix.rs",
];

const HARDWARE_MODULES: &[&str] = &[
    "dispatch_buffers.rs",
    "device_resident_token_fact_graph.rs",
    "gpu_preprocessing_coverage.rs",
    "gpu_probe_contract.rs",
    "memory_ownership_contract.rs",
    "scratch.rs",
];

const EVIDENCE_MODULES: &[&str] = &[
    "benchmark_baselines.rs",
    "c_parser_benchmark_evidence.rs",
    "cuda_ptx_pattern_evidence.rs",
    "optimization_release_evidence.rs",
];

const COVERAGE_MODULES: &[&str] = &[
    "c_dialect_matrix.rs",
    "clang_parity_dashboard.rs",
    "hostile_input_coverage.rs",
    "linux_corpus_parity.rs",
    "parser_semantic_safety.rs",
    "semantic_parity_coverage.rs",
    "test_taxonomy_coverage.rs",
    "analysis_coverage.rs",
    "graph_layout_coverage.rs",
];

const MATH_MODULES: &[&str] = &[
    "amg_pass_solver.rs",
    "bellman_tn_order.rs",
    "differentiable_autotune.rs",
    "fmm_polyhedral_compress.rs",
    "kfac_autotune_step.rs",
    "mori_zwanzig_region_coarsen.rs",
    "multigrid_matroid_solver.rs",
    "natural_gradient_autotuner.rs",
    "persistent_homology_loop_signature.rs",
    "qsvt_matrix_function_fusion.rs",
    "sheaf_heterophilic_dispatch.rs",
    "sheaf_spectral_clustering.rs",
    "sinkhorn_dispatch_clustering.rs",
    "sinkhorn_full_clustering.rs",
    "tensor_network_fusion_order.rs",
    "tensor_train_chain_fusion.rs",
    "tensor_train_compression.rs",
];

const OPTIMIZER_MODULES: &[&str] = &[
    "canonicalize_via_encoded.rs",
    "const_fold_via_encoded.rs",
    "const_prop.rs",
    "cross_scope_cse.rs",
    "cse_via_encoded.rs",
    "dce_program.rs",
    "dce_via_encoded.rs",
    "dead_branch.rs",
    "dispatcher.rs",
    "encode.rs",
    "expr_arena.rs",
    "licm.rs",
    "pattern_match_via_encoded.rs",
    "pipeline.rs",
    "pipeline_resident.rs",
    "pipeline_resident_decode.rs",
    "validate_via_encoded.rs",
];

const OPTIMIZER_CONTRACT_MODULES: &[&str] = &[
    "cross_crate_perf_contracts.rs",
    "optimization_composition_contracts.rs",
    "optimization_pass_selection.rs",
    "optimization_registry.rs",
    "optimization_release_passes.rs",
];

const QUALITY_MODULES: &[&str] = &[
    "allocation_regression.rs",
    "architecture_boundary_map.rs",
    "contributor_module_map.rs",
    "cpu_fallback_reachability.rs",
    "crate_metadata_readiness.rs",
    "deep_review_gate.rs",
    "paradigm_shift_plan_audit.rs",
    "public_api_boundary.rs",
    "public_api_doctest_gate.rs",
];

const ANALYSIS_MODULES: &[&str] = &[
    "cost_model.rs",
    "dataflow_fixpoint.rs",
    "decision_telemetry.rs",
    "diagnostic_aggregation.rs",
    "diagnostic_comparison.rs",
    "effect_signature_check.rs",
    "incremental_invalidation.rs",
    "knowledge_compile_pass_precondition.rs",
    "linear_type_check.rs",
    "persistent_fixpoint_program.rs",
    "shape_smt_check.rs",
];

const SCHEDULING_MODULES: &[&str] = &[
    "branch_compaction.rs",
    "frontier_partitioning.rs",
    "frontier_typed_ir.rs",
    "megakernel_schedule.rs",
    "multi_corpus_batching.rs",
    "planar_rewrite_pass_scheduler.rs",
    "polyhedral_fusion.rs",
    "spectral_schedule.rs",
    "submodular_cache_eviction.rs",
];

const LOGIC_MODULES: &[&str] = &[
    "adjustment_set_pass_dependency.rs",
    "categorical_check.rs",
    "dnnf_compile.rs",
    "do_calculus_change_impact.rs",
    "functorial_pass_composition.rs",
    "string_diagram_ir_rewrite.rs",
    "zx_rewrite.rs",
];

const DATA_MODULES: &[&str] = &[
    "bitset_compression.rs",
    "bitset_summary.rs",
    "matroid_exact_megakernel.rs",
    "matroid_megakernel_scheduler.rs",
    "scallop_provenance.rs",
    "scallop_provenance_wide.rs",
    "vsa_fingerprint.rs",
];

const TELEMETRY_MODULES: &[&str] = &["observability.rs"];

const DOMAIN_MODULES: &[(&str, &[&str])] = &[
    ("analysis", ANALYSIS_MODULES),
    ("integration/coverage", COVERAGE_MODULES),
    ("data", DATA_MODULES),
    ("integration/evidence", EVIDENCE_MODULES),
    ("graph", GRAPH_WRAPPERS),
    ("hardware", HARDWARE_MODULES),
    ("logic", LOGIC_MODULES),
    ("math", MATH_MODULES),
    ("optimizer", OPTIMIZER_MODULES),
    ("integration/quality", QUALITY_MODULES),
    ("integration/release", RELEASE_GATES),
    ("scheduling", SCHEDULING_MODULES),
    ("telemetry", TELEMETRY_MODULES),
];

#[test]
fn self_substrate_root_contains_no_flat_domain_modules() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_root = manifest.join("src");
    let mut flat_modules = Vec::new();

    for entry in std::fs::read_dir(&source_root)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", source_root.display()))
    {
        let path = entry
            .unwrap_or_else(|err| panic!("src/ entry must be readable: {err}"))
            .path();
        if path.is_file() && path.file_name().is_some_and(|name| name != "lib.rs") {
            flat_modules.push(
                path.file_name()
                    .expect("root file must have a name")
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }

    assert!(
        flat_modules.is_empty(),
        "vyre-self-substrate must not regress to flat src/ modules; move files into domain directories: {flat_modules:?}"
    );
}

#[test]
fn every_domain_module_is_declared_by_its_domain_mod_file() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_root = manifest.join("src");

    for (domain, modules) in DOMAIN_MODULES {
        let mod_path = source_root.join(domain).join("mod.rs");
        let mod_source = std::fs::read_to_string(&mod_path)
            .unwrap_or_else(|err| panic!("{} must be readable: {err}", mod_path.display()));

        for module_file in *modules {
            let module_path = source_root.join(domain).join(module_file);
            let directory_module_path = module_file
                .strip_suffix(".rs")
                .map(|stem| source_root.join(domain).join(stem).join("mod.rs"));
            assert!(
                module_path.exists()
                    || directory_module_path
                        .as_ref()
                        .is_some_and(|path| path.exists()),
                "{domain}/{module_file} must exist because it is part of the self-substrate organization contract"
            );
            let stem = module_file
                .strip_suffix(".rs")
                .expect("organization module entries must be Rust source files");
            assert!(
                mod_source.contains(&format!("mod {stem};")),
                "{domain}/mod.rs must declare mod {stem}; so imports cross the domain boundary through one file"
            );
        }
    }
}

#[test]
fn graph_wrappers_live_under_graph_module() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_root = manifest.join("src");
    let graph_root = source_root.join("graph");

    for wrapper in GRAPH_WRAPPERS {
        let root_path = source_root.join(wrapper);
        assert!(
            !root_path.exists(),
            "graph wrapper {wrapper} must not live at src/ root; move it under src/graph/"
        );

        let graph_path = graph_root.join(wrapper);
        let graph_directory_path = wrapper
            .strip_suffix(".rs")
            .map(|stem| graph_root.join(stem).join("mod.rs"));
        assert!(
            graph_path.exists()
                || graph_directory_path
                    .as_ref()
                    .is_some_and(|path| path.exists()),
            "graph wrapper {wrapper} must live under src/graph/"
        );
    }
}

#[test]
fn consolidated_graph_wrappers_remain_primitive_backed() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest
        .parent()
        .expect("vyre-self-substrate should live directly under workspace root");
    let graph_root = manifest.join("src").join("graph");
    let primitive_graph_root = workspace.join("vyre-primitives").join("src").join("graph");

    for (wrapper, primitive_module) in CONSOLIDATED_GRAPH_WRAPPERS {
        let wrapper_path = graph_root.join(wrapper);
        let wrapper_source = read_graph_wrapper_source(&wrapper_path);
        let primitive_path = primitive_graph_root.join(wrapper);

        assert!(
            primitive_path.exists(),
            "consolidated graph wrapper {wrapper} must have a same-named primitive authority"
        );
        assert!(
            wrapper_source.contains(&format!("vyre_primitives::graph::{primitive_module}")),
            "consolidated graph wrapper {wrapper} must import vyre_primitives::graph::{primitive_module}"
        );
        assert!(
            !wrapper_source.contains("pub const OP_ID")
                && !wrapper_source.contains("pub const BATCH_OP_ID")
                && !wrapper_source.contains("pub const BATCHED_OP_ID"),
            "consolidated graph wrapper {wrapper} must not declare primitive op ids; op identity belongs in vyre-primitives"
        );
        assert!(
            !wrapper_source.contains("checked_mul(std::mem::size_of::<u32>())")
                && !wrapper_source.contains("checked_mul(core::mem::size_of::<u32>())")
                && !wrapper_source.contains("fn write_zero_words")
                && !wrapper_source.contains("fn write_padded_u32_slice_bytes")
                && !wrapper_source.contains("fn write_edge_offsets_bytes")
                && !wrapper_source.contains("fn write_padded_one_u32_bytes")
                && !wrapper_source.contains("fn write_padded_edge_bytes")
                && !wrapper_source.contains("write_zero_bytes(out, std::mem::size_of::<u32>())")
                && !wrapper_source.contains("depth * std::mem::size_of::<u32>()"),
            "consolidated graph wrapper {wrapper} must not own dispatcher byte-marshalling helpers; use hardware::dispatch_buffers"
        );
    }
}

#[test]
fn graph_wrappers_do_not_define_local_u32_byte_helpers() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let graph_root = manifest.join("src").join("graph");

    for wrapper in GRAPH_WRAPPERS {
        let wrapper_path = graph_root.join(wrapper);
        let wrapper_source = read_graph_wrapper_source(&wrapper_path);
        assert!(
            !wrapper_source.contains("fn size_of_u32"),
            "graph wrapper {wrapper} must not define local u32 byte-size helpers; use hardware::dispatch_buffers or a typed constant"
        );
    }
}

fn read_graph_wrapper_source(wrapper_path: &Path) -> String {
    let actual_wrapper_path = if wrapper_path.exists() {
        wrapper_path.to_path_buf()
    } else {
        let stem = wrapper_path
            .file_stem()
            .unwrap_or_else(|| panic!("{} must have a stem", wrapper_path.display()));
        wrapper_path
            .parent()
            .unwrap_or_else(|| panic!("{} must have a parent", wrapper_path.display()))
            .join(stem)
            .join("mod.rs")
    };
    let mut source = std::fs::read_to_string(&actual_wrapper_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", actual_wrapper_path.display()));
    let Some(parent) = actual_wrapper_path.parent() else {
        return source;
    };
    let Some(stem) = actual_wrapper_path.file_stem() else {
        return source;
    };
    let child_dir = if actual_wrapper_path
        .file_name()
        .is_some_and(|name| name == "mod.rs")
    {
        parent.to_path_buf()
    } else {
        parent.join(stem)
    };
    if !child_dir.is_dir() {
        return source;
    }
    let mut child_modules = std::fs::read_dir(&child_dir)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", child_dir.display()))
        .map(|entry| {
            entry
                .unwrap_or_else(|err| {
                    panic!("{} entry must be readable: {err}", child_dir.display())
                })
                .path()
        })
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .collect::<Vec<_>>();
    child_modules.sort();
    for child in child_modules {
        source.push('\n');
        source.push_str(
            &std::fs::read_to_string(&child)
                .unwrap_or_else(|err| panic!("{} must be readable: {err}", child.display())),
        );
    }
    source
}

#[test]
fn csr_frontier_queue_batch_resident_uses_primitive_batch_contract() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let wrapper_path = manifest
        .join("src")
        .join("graph")
        .join("csr_frontier_queue_batch_resident.rs");
    let wrapper_source = std::fs::read_to_string(&wrapper_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", wrapper_path.display()));
    let dispatch_path = manifest
        .join("src")
        .join("graph")
        .join("csr_frontier_queue_batch_resident")
        .join("dispatch.rs");
    let dispatch_source = std::fs::read_to_string(&dispatch_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", dispatch_path.display()));
    let resident_source = format!("{wrapper_source}\n{dispatch_source}");

    assert!(
        resident_source.contains("validate_frontier_queue_batch"),
        "resident CSR queue batch wrapper must delegate batch-shape validation to vyre-primitives"
    );
    assert!(
        !resident_source.contains("fn validate_batch(")
            && !resident_source.contains("frontiers.is_empty()")
            && !resident_source.contains("queue_capacity == 0")
            && !resident_source.contains("frontier.len() != graph.words()"),
        "resident CSR queue batch wrapper must not own the primitive batch validation contract"
    );
}

#[test]
fn csr_frontier_queue_resident_uses_primitive_query_contract() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let query_path = manifest
        .join("src")
        .join("graph")
        .join("csr_frontier_queue_resident")
        .join("query.rs");
    let query_section = std::fs::read_to_string(&query_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", query_path.display()));

    assert!(
        query_section.contains("validate_frontier_queue_query"),
        "resident CSR queue query wrapper must delegate queue/frontier validation to vyre-primitives"
    );
    assert!(
        !query_section.contains("queue_capacity == 0")
            && !query_section.contains("frontier_words.len() != graph.words"),
        "resident CSR queue query wrapper must not own primitive queue-capacity or frontier-width validation"
    );
}

#[test]
fn csr_frontier_queue_resident_graph_upload_uses_primitive_layout_contract() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let upload_path = manifest
        .join("src")
        .join("graph")
        .join("csr_frontier_queue_resident")
        .join("upload.rs");
    let upload_section = std::fs::read_to_string(&upload_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", upload_path.display()));

    assert!(
        upload_section.contains("let layout =")
            && upload_section.contains("validate_csr_queue_graph"),
        "resident CSR queue graph upload must use primitive-returned graph layout"
    );
    assert!(
        !upload_section.contains("bitset_words(node_count)")
            && !upload_section.contains("let edge_count =")
            && !upload_section.contains("edge_targets,\n        1,")
            && !upload_section.contains("edge_kind_mask,\n        1,"),
        "resident CSR queue graph upload must not recompute primitive frontier width, edge count, or edge padding"
    );
}

#[test]
fn persistent_bfs_resident_batch_uses_primitive_batch_contract() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let wrapper_path = manifest
        .join("src")
        .join("graph")
        .join("persistent_bfs")
        .join("resident.rs");
    let wrapper_source = std::fs::read_to_string(&wrapper_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", wrapper_path.display()));
    let batch_section = wrapper_source
        .split("pub fn bfs_expand_resident_graph_batch_with_scratch_into")
        .nth(1)
        .expect("resident batch BFS wrapper must exist")
        .split("fn ensure_resident_frontier_handles")
        .next()
        .expect("resident batch BFS wrapper must precede resident handle helpers");

    assert!(
        batch_section.contains("let plan = plan_persistent_bfs_resident_batch_dispatch"),
        "persistent BFS resident batch wrapper must delegate flat-frontier batch planning to vyre-primitives"
    );
    assert!(
        !batch_section.contains("graph.words.checked_mul(query_count)")
            && !batch_section.contains("frontier_inputs.len() != expected_words")
            && !batch_section.contains("u32::try_from(query_count)"),
        "persistent BFS resident batch wrapper must not own primitive batch overflow, length, or query-count validation"
    );
}

#[test]
fn persistent_bfs_resident_single_uses_primitive_frontier_contract() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let wrapper_path = manifest
        .join("src")
        .join("graph")
        .join("persistent_bfs")
        .join("resident.rs");
    let wrapper_source = std::fs::read_to_string(&wrapper_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", wrapper_path.display()));
    let single_section = wrapper_source
        .split("pub fn bfs_expand_resident_graph_with_scratch_into")
        .nth(1)
        .expect("resident single BFS wrapper must exist")
        .split("pub fn bfs_expand_resident_graph_batch_with_scratch_into")
        .next()
        .expect("resident single BFS wrapper must precede batch wrapper");

    assert!(
        single_section.contains("let plan = plan_persistent_bfs_resident_dispatch"),
        "persistent BFS resident single wrapper must delegate frontier planning to vyre-primitives"
    );
    assert!(
        single_section.contains("resident_dispatch_two_u32_outputs_into"),
        "persistent BFS resident single wrapper must use the shared resident readback dispatch bridge"
    );
    assert!(
        !single_section.contains("frontier_in.len() != graph.words")
            && !single_section.contains("u32::try_from(graph.words)"),
        "persistent BFS resident single wrapper must not own primitive frontier-width or word-count narrowing validation"
    );
}

#[test]
fn persistent_bfs_dispatch_paths_use_primitive_layout_contract() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dispatch_path = manifest
        .join("src")
        .join("graph")
        .join("persistent_bfs")
        .join("dispatch.rs");
    let resident_path = manifest
        .join("src")
        .join("graph")
        .join("persistent_bfs")
        .join("resident.rs");
    let dispatch_source = std::fs::read_to_string(&dispatch_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", dispatch_path.display()));
    let resident_source = std::fs::read_to_string(&resident_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", resident_path.display()));
    let via_section = dispatch_source
        .split("pub fn bfs_expand_via_with_scratch_into")
        .nth(1)
        .expect("non-resident persistent BFS wrapper must exist");
    let upload_section = resident_source
        .split("pub fn upload_resident_bfs_graph")
        .nth(1)
        .expect("resident persistent BFS graph upload must exist")
        .split("pub fn bfs_expand_resident_graph_with_scratch_into")
        .next()
        .expect("resident persistent BFS upload must precede query wrapper");
    let batch_section = resident_source
        .split("pub fn bfs_expand_resident_graph_batch_with_scratch_into")
        .nth(1)
        .expect("resident persistent BFS batch wrapper must exist")
        .split("fn ensure_resident_frontier_handles")
        .next()
        .expect("resident persistent BFS batch wrapper must precede handle helpers");

    assert!(
        via_section.contains("let plan = plan_persistent_bfs_dispatch"),
        "persistent BFS non-resident wrapper must use primitive-returned graph/frontier dispatch plan"
    );
    assert!(
        via_section.contains("refresh_keyed_dispatch_inputs")
            && via_section.contains("decode_u32_output_exact")
            && via_section.contains("changed_words"),
        "persistent BFS non-resident wrapper must reuse keyed graph input refresh and decode the primitive-owned changed scratch width explicitly"
    );
    assert!(
        !via_section.contains("bitset_words(node_count)")
            && !via_section.contains("node_count as usize")
            && !via_section.contains("u32::try_from(words)")
            && !via_section.contains("edge_targets.is_empty()")
            && !via_section.contains("edge_kind_mask.is_empty()"),
        "persistent BFS non-resident wrapper must not recompute frontier words, node scratch size, word narrowing, or edge padding"
    );

    assert!(
        upload_section.contains("let layout = validate_persistent_bfs_graph_layout"),
        "resident persistent BFS upload must use primitive-returned graph layout"
    );
    assert!(
        upload_section.contains("upload_resident_dispatch_inputs"),
        "resident persistent BFS upload must use the graph dispatch bridge for payload packing and failure-clean resident allocation"
    );
    assert!(
        !upload_section.contains("node_count as usize")
            && !upload_section.contains("let nodes = vec!")
            && !upload_section.contains("edge_targets.is_empty()")
            && !upload_section.contains("edge_kind_mask.is_empty()"),
        "resident persistent BFS upload must not recompute node scratch or edge padding layout"
    );

    assert!(
        batch_section.contains("resident_dispatch_two_u32_outputs_into") &&
        !batch_section.contains("u32::try_from(graph.words)"),
        "resident persistent BFS batch wrapper must reuse primitive-narrowed frontier word count and shared resident readback dispatch"
    );
}

#[test]
fn dominator_frontier_wrapper_uses_primitive_layout_contract() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let wrapper_path = manifest
        .join("src")
        .join("graph")
        .join("dominator_frontier")
        .join("mod.rs");
    let dispatch_path = manifest
        .join("src")
        .join("graph")
        .join("dominator_frontier")
        .join("dispatch.rs");
    let wrapper_source = std::fs::read_to_string(&wrapper_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", wrapper_path.display()));
    let dispatch_source = std::fs::read_to_string(&dispatch_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", dispatch_path.display()));
    let via_section = dispatch_source
        .split("pub fn compute_dominance_frontier_via_with_scratch_into")
        .nth(1)
        .expect("dominance-frontier dispatch wrapper must exist")
        .split("dispatch_single_u32_output_from_prepared_into")
        .next()
        .expect(
            "dominance-frontier wrapper must cross the shared graph dispatch bridge after setup",
        );

    assert!(
        via_section.contains("let plan = plan_dominator_frontier_launch"),
        "dominance-frontier wrapper must use primitive-returned launch plan without eager IR rebuild"
    );
    assert!(
        wrapper_source.contains("pub use dispatch")
            && dispatch_source.contains("dispatch_single_u32_output_from_prepared_into"),
        "dominance-frontier wrapper must reuse the graph dispatch bridge instead of open-coding buffer/dispatch/decode plumbing"
    );
    assert!(
        !via_section.contains("bitset_words(node_count)")
            && !via_section.contains("u32::try_from(dom_targets.len())")
            && !via_section.contains("u32::try_from(pred_targets.len())"),
        "dominance-frontier wrapper must not recompute primitive frontier words or CSR edge-count narrowing"
    );
}

#[test]
fn csr_bidirectional_wrapper_uses_primitive_layout_contract() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let wrapper_path = manifest
        .join("src")
        .join("graph")
        .join("csr_bidirectional")
        .join("mod.rs");
    let wrapper_source = std::fs::read_to_string(&wrapper_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", wrapper_path.display()));
    let dispatch_path = manifest
        .join("src")
        .join("graph")
        .join("csr_bidirectional")
        .join("dispatch.rs");
    let dispatch_source = std::fs::read_to_string(&dispatch_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", dispatch_path.display()));
    let via_section = dispatch_source
        .split("pub fn bidirectional_step_via_with_scratch_into")
        .nth(1)
        .expect("bidirectional dispatch wrapper must exist")
        .split("dispatch_single_u32_output_from_prepared_into")
        .next()
        .expect("bidirectional wrapper must cross the shared graph dispatch bridge after setup");

    assert!(
        via_section.contains("let plan = plan_csr_bidirectional_step"),
        "bidirectional wrapper must use primitive-returned dispatch layout"
    );
    assert!(
        wrapper_source.contains("pub use dispatch")
            && dispatch_source.contains("dispatch_single_u32_output_from_prepared_into"),
        "bidirectional wrapper must reuse the graph dispatch bridge instead of open-coding buffer/dispatch/decode plumbing"
    );
    assert!(
        !via_section.contains("bitset_words(node_count)")
            && !via_section.contains("node_count as usize")
            && !via_section.contains("ProgramGraphShape::new(node_count")
            && !via_section.contains("let edge_count = validate_csr_bidirectional_inputs")
            && !via_section.contains("edge_targets.is_empty()")
            && !via_section.contains("edge_kind_mask.is_empty()"),
        "bidirectional wrapper must not recompute primitive frontier words, node scratch length, edge-count layout, or edge-buffer padding"
    );
}

#[test]
fn csr_forward_or_changed_wrapper_uses_primitive_layout_contract() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let wrapper_path = manifest
        .join("src")
        .join("graph")
        .join("csr_forward_or_changed")
        .join("mod.rs");
    let wrapper_source = std::fs::read_to_string(&wrapper_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", wrapper_path.display()));
    let dispatch_path = manifest
        .join("src")
        .join("graph")
        .join("csr_forward_or_changed")
        .join("dispatch.rs");
    let dispatch_source = std::fs::read_to_string(&dispatch_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", dispatch_path.display()));
    let via_section = dispatch_source
        .split("pub fn forward_closure_via_change_flag_gpu_with_scratch_into")
        .nth(1)
        .expect("forward-or-changed dispatch wrapper must exist")
        .split("for iter in 0..max_iters")
        .next()
        .expect("forward-or-changed wrapper must prepare dispatch before loop");

    assert!(
        via_section.contains("let plan = plan_csr_forward_or_changed_launch")
            && via_section.contains("program_cache.get_or_try_insert_with("),
        "forward-or-changed wrapper must use the primitive-owned launch plan and shared program cache"
    );
    assert!(
        wrapper_source.contains("pub use dispatch")
            && dispatch_source.contains("refresh_keyed_dispatch_inputs")
            && dispatch_source.contains("write_dispatch_input")
            && dispatch_source.contains("dispatch_two_u32_outputs_from_prepared_into"),
        "forward-or-changed wrapper must reuse the graph dispatch bridge without re-copying fixed CSR buffers per iteration"
    );
    assert!(
        !via_section.contains("checked_add(1)")
            && !via_section.contains("edge_targets.len() > u32::MAX")
            && !via_section.contains("edge_kind_mask.len() as u32")
            && !via_section.contains("node_count.max(1) as usize")
            && !via_section.contains("frontier_words = frontier.len()"),
        "forward-or-changed wrapper must not own primitive offset, edge-count, node scratch, or frontier layout validation"
    );
}

#[test]
fn toposort_wrapper_uses_primitive_layout_contract() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let wrapper_path = manifest
        .join("src")
        .join("graph")
        .join("toposort")
        .join("mod.rs");
    let dispatch_path = manifest
        .join("src")
        .join("graph")
        .join("toposort")
        .join("dispatch.rs");
    let wrapper_source = std::fs::read_to_string(&wrapper_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", wrapper_path.display()));
    let dispatch_source = std::fs::read_to_string(&dispatch_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", dispatch_path.display()));
    let via_section = dispatch_source
        .split("pub fn topo_order_csr_via_with_scratch_into")
        .nth(1)
        .expect("toposort dispatch wrapper must exist")
        .split("dispatch_single_u32_output_from_prepared_into")
        .next()
        .expect("toposort wrapper must cross the shared graph dispatch bridge after setup");

    assert!(
        via_section.contains("let plan =") && via_section.contains("plan_toposort_csr_dispatch"),
        "toposort wrapper must use primitive-returned dispatch layout"
    );
    assert!(
        wrapper_source.contains("pub use dispatch")
            && dispatch_source.contains("dispatch_single_u32_output_from_prepared_into"),
        "toposort wrapper must reuse the graph dispatch bridge instead of open-coding buffer/dispatch/decode plumbing"
    );
    assert!(
        !via_section.contains("let node_words = node_count as usize")
            && !via_section.contains("toposort_program(\n        node_count")
            && !via_section.contains("u32_word_bytes(node_count"),
        "toposort wrapper must not recompute primitive node scratch or program-shape layout"
    );
}

#[test]
fn union_find_wrapper_uses_primitive_layout_contract() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let wrapper_path = manifest
        .join("src")
        .join("graph")
        .join("union_find_emit.rs");
    let wrapper_source = std::fs::read_to_string(&wrapper_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", wrapper_path.display()));
    let dispatch_path = manifest
        .join("src")
        .join("graph")
        .join("union_find_emit")
        .join("dispatch.rs");
    let dispatch_source = std::fs::read_to_string(&dispatch_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", dispatch_path.display()));
    let via_section = dispatch_source
        .split("pub fn union_find_alias_via_with_scratch_into")
        .nth(1)
        .expect("union-find dispatch wrapper must exist")
        .split("dispatch_single_u32_output_from_prepared_into")
        .next()
        .expect("union-find wrapper must cross the shared graph dispatch bridge after setup");

    assert!(
        via_section.contains("let layout = validate_union_find_inputs"),
        "union-find wrapper must use primitive-returned dispatch layout"
    );
    assert!(
        wrapper_source.contains("pub use dispatch")
            && dispatch_source.contains("dispatch_single_u32_output_from_prepared_into"),
        "union-find wrapper must stay a facade over dispatch.rs and reuse the graph dispatch bridge"
    );
    assert!(
        !via_section.contains("node_count as usize")
            && !via_section.contains("let (node_count, edge_count)")
            && !via_section.contains("edge_a,\n        1,")
            && !via_section.contains("edge_b,\n        1,"),
        "union-find wrapper must not recompute primitive output width or edge-buffer padding"
    );
}

#[test]
fn exploded_wrapper_uses_primitive_input_layout_contract() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let wrapper_path = manifest
        .join("src")
        .join("graph")
        .join("exploded")
        .join("mod.rs");
    let wrapper_source = std::fs::read_to_string(&wrapper_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", wrapper_path.display()));
    let dispatch_path = manifest
        .join("src")
        .join("graph")
        .join("exploded")
        .join("dispatch.rs");
    let dispatch_source = std::fs::read_to_string(&dispatch_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", dispatch_path.display()));
    let via_section = dispatch_source
        .split("pub fn build_ifds_csr_via_with_scratch_into")
        .nth(1)
        .expect("exploded IFDS dispatch wrapper must exist")
        .split("dispatch_four_u32_outputs_from_prepared_into")
        .next()
        .expect("exploded IFDS wrapper must cross the shared graph dispatch bridge after setup");

    assert!(
        via_section.contains("let plan = plan_ifds_csr_dispatch"),
        "exploded IFDS wrapper must use primitive-returned input/count layout"
    );
    assert!(
        wrapper_source.contains("pub use dispatch")
            && dispatch_source.contains("refresh_keyed_dispatch_inputs")
            && dispatch_source.contains("dispatch_four_u32_outputs_from_prepared_into"),
        "exploded IFDS wrapper must reuse the graph dispatch bridge instead of open-coding 17-input/four-output byte plumbing"
    );
    assert!(
        !via_section.contains("u32::try_from")
            && !via_section.contains("intra_edges.len()")
            && !via_section.contains("inter_edges.len()")
            && !via_section.contains("flow_gen.len()")
            && !via_section.contains("flow_kill.len()")
            && !via_section.contains("validate_ifds_csr_layout")
            && !via_section.contains("&scratch.intra_proc,\n        1,")
            && !via_section.contains("&scratch.inter_src_proc,\n        1,")
            && !via_section.contains("&scratch.gen_proc,\n        1,")
            && !via_section.contains("&scratch.kill_proc,\n        1,"),
        "exploded IFDS wrapper must not own primitive count narrowing, layout validation, or input-buffer padding"
    );
}

#[test]
fn motif_wrapper_uses_primitive_layout_contract() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let wrapper_path = manifest
        .join("src")
        .join("graph")
        .join("motif")
        .join("mod.rs");
    let wrapper_source = std::fs::read_to_string(&wrapper_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", wrapper_path.display()));
    let dispatch_path = manifest
        .join("src")
        .join("graph")
        .join("motif")
        .join("dispatch.rs");
    let dispatch_source = std::fs::read_to_string(&dispatch_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", dispatch_path.display()));
    let release_section = dispatch_source
        .split("pub fn match_motif_via(")
        .nth(1)
        .expect("motif dispatch wrappers must exist")
        .split("pub fn motif_matches_via")
        .next()
        .expect("motif match wrapper must precede predicate wrappers");

    assert!(
        release_section.contains("let plan = plan_motif_launch"),
        "motif wrapper must use primitive-returned launch/cache plan"
    );
    assert!(
        wrapper_source.contains("pub use dispatch")
            && release_section.contains("dispatch_two_u32_outputs_from_prepared_into"),
        "motif wrapper must reuse the graph dispatch bridge instead of open-coding buffer/dispatch/decode plumbing"
    );
    assert!(
        !release_section.contains("validate_motif_inputs")
            && !release_section.contains("validate_motif_csr_inputs")
            && !release_section.contains("motif_edges.len() > u32::MAX")
            && !release_section.contains("u32::try_from")
            && !release_section.contains("node_count as usize")
            && !release_section.contains("edge_targets,\n        1,")
            && !release_section.contains("edge_kind_mask,\n        1,"),
        "motif wrapper must not recompute primitive motif edge-count, output layout, witness-count, or edge-buffer padding validation"
    );
}

#[test]
fn path_reconstruct_batch_uses_primitive_layout_contract() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let wrapper_path = manifest
        .join("src")
        .join("graph")
        .join("path_reconstruct")
        .join("mod.rs");
    let wrapper_source = std::fs::read_to_string(&wrapper_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", wrapper_path.display()));
    let dispatch_path = manifest
        .join("src")
        .join("graph")
        .join("path_reconstruct")
        .join("dispatch.rs");
    let dispatch_source = std::fs::read_to_string(&dispatch_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", dispatch_path.display()));
    let batch_section = dispatch_source
        .split("pub fn reconstruct_paths_via_with_scratch_into")
        .nth(1)
        .expect("batched path reconstruction wrapper must exist")
        .split("dispatch_two_u32_outputs_into")
        .next()
        .expect("batched path reconstruction wrapper must cross the shared graph dispatch bridge");

    assert!(
        batch_section.contains("plan_batched_path_reconstruct_dispatch"),
        "batched path reconstruction wrapper must delegate target/depth layout validation to vyre-primitives"
    );
    assert!(
        wrapper_source.contains("pub use dispatch")
            && dispatch_source.contains("dispatch_two_u32_outputs_from_prepared_into"),
        "path reconstruction wrapper must stay a facade over the shared graph dispatch bridge"
    );
    assert!(
        !batch_section.contains("max_depth == 0")
            && !batch_section.contains("u32::try_from(targets.len())")
            && !batch_section.contains("checked_product_count")
            && !batch_section.contains("target_count.checked_mul(max_depth)"),
        "batched path reconstruction wrapper must not own primitive max-depth, target-count, or path-buffer overflow validation"
    );
}

#[test]
fn adaptive_traverse_resident_paths_use_primitive_frontier_contract() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let wrapper_path = manifest
        .join("src")
        .join("graph")
        .join("adaptive_traverse")
        .join("resident_steps.rs");
    let release_path = std::fs::read_to_string(&wrapper_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", wrapper_path.display()));

    assert!(
        release_path.matches("plan_adaptive_resident_frontier_step").count() >= 2
            && release_path.contains("plan_adaptive_resident_sparse_queue_step")
            && release_path.contains("plan_adaptive_resident_auto_step")
            && release_path.matches(".work.has_active_bits").count() >= 4,
        "adaptive resident sparse/dense, Four-Russians, sparse-queue, and auto paths must delegate frontier validation and zero-work classification to vyre-primitives resident planners"
    );
    assert!(
        release_path.matches("resident_sequence_single_u32_output_into").count() >= 2,
        "adaptive resident sparse/dense and sparse-queue paths must reuse the graph dispatch bridge for resident readback/decode"
    );
    assert!(
        !release_path.contains("frontier_in.len() != graph.words")
            && !release_path.contains("u32::try_from(graph.words)"),
        "adaptive resident wrappers must not own primitive frontier-width or word-count narrowing validation"
    );
}

#[test]
fn adaptive_traverse_resident_upload_uses_primitive_layout_contract() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let wrapper_path = manifest
        .join("src")
        .join("graph")
        .join("adaptive_traverse")
        .join("upload.rs");
    let upload_section = std::fs::read_to_string(&wrapper_path)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", wrapper_path.display()));

    assert!(
        upload_section.contains("let layout = validate_adaptive_traversal_layout"),
        "adaptive resident upload must use primitive-returned graph layout"
    );
    assert!(
        upload_section.contains("upload_resident_dispatch_inputs"),
        "adaptive resident upload must use the graph dispatch bridge for payload packing and failure-clean resident allocation"
    );
    assert!(
        !upload_section.contains("edge_targets.is_empty()")
            && !upload_section.contains("edge_kind_mask.is_empty()")
            && !upload_section.contains("dummy_edge"),
        "adaptive resident upload must not own primitive edge-buffer padding policy"
    );
}

#[test]
fn telemetry_lives_under_telemetry_module() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_root = manifest.join("src");
    let telemetry_root = source_root.join("telemetry");

    assert!(
        telemetry_root.join("mod.rs").exists(),
        "telemetry must be grouped behind src/telemetry/mod.rs"
    );

    for module in TELEMETRY_MODULES {
        let root_path = source_root.join(module);
        assert!(
            !root_path.exists(),
            "telemetry module {module} must not live at src/ root; move it under src/telemetry/"
        );

        let telemetry_path = telemetry_root.join(module);
        assert!(
            telemetry_path.exists(),
            "telemetry module {module} must live under src/telemetry/"
        );
    }
}

#[test]
fn source_root_only_contains_crate_entrypoint() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_root = manifest.join("src");
    let mut root_files = std::fs::read_dir(&source_root)
        .expect("src directory must be readable")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "rs")
        })
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    root_files.sort();

    assert_eq!(
        root_files,
        vec!["lib.rs".to_string()],
        "self-substrate source root must stay a namespace table, not a flat module dump"
    );
}

#[test]
fn data_substrate_lives_under_data_module() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_root = manifest.join("src");
    let data_root = source_root.join("data");

    assert!(
        data_root.join("mod.rs").exists(),
        "data substrate must be grouped behind src/data/mod.rs"
    );

    for module in DATA_MODULES {
        let root_path = source_root.join(module);
        assert!(
            !root_path.exists(),
            "data module {module} must not live at src/ root; move it under src/data/"
        );

        let data_path = data_root.join(module);
        assert!(
            data_path.exists(),
            "data module {module} must live under src/data/"
        );
    }
}

#[test]
fn logic_rewrite_substrate_lives_under_logic_module() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_root = manifest.join("src");
    let logic_root = source_root.join("logic");

    assert!(
        logic_root.join("mod.rs").exists(),
        "logic and rewrite substrate must be grouped behind src/logic/mod.rs"
    );

    for module in LOGIC_MODULES {
        let root_path = source_root.join(module);
        assert!(
            !root_path.exists(),
            "logic module {module} must not live at src/ root; move it under src/logic/"
        );

        let logic_path = logic_root.join(module);
        assert!(
            logic_path.exists(),
            "logic module {module} must live under src/logic/"
        );
    }
}

#[test]
fn scheduling_strategies_live_under_scheduling_module() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_root = manifest.join("src");
    let scheduling_root = source_root.join("scheduling");

    assert!(
        scheduling_root.join("mod.rs").exists(),
        "scheduling strategies must be grouped behind src/scheduling/mod.rs"
    );

    for module in SCHEDULING_MODULES {
        let root_path = source_root.join(module);
        assert!(
            !root_path.exists(),
            "scheduling module {module} must not live at src/ root; move it under src/scheduling/"
        );

        let scheduling_path = scheduling_root.join(module);
        assert!(
            scheduling_path.exists(),
            "scheduling module {module} must live under src/scheduling/"
        );
    }
}

#[test]
fn analysis_substrate_lives_under_analysis_module() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_root = manifest.join("src");
    let analysis_root = source_root.join("analysis");

    assert!(
        analysis_root.join("mod.rs").exists(),
        "analysis substrate must be grouped behind src/analysis/mod.rs"
    );

    for module in ANALYSIS_MODULES {
        let root_path = source_root.join(module);
        assert!(
            !root_path.exists(),
            "analysis module {module} must not live at src/ root; move it under src/analysis/"
        );

        let analysis_path = analysis_root.join(module);
        assert!(
            analysis_path.exists(),
            "analysis module {module} must live under src/analysis/"
        );
    }
}

#[test]
fn quality_gates_live_under_quality_module() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_root = manifest.join("src");
    let legacy_quality_root = source_root.join("quality");
    let quality_root = source_root.join("integration").join("quality");
    assert!(
        !legacy_quality_root.exists(),
        "legacy src/quality/ must stay empty or absent; quality gates belong under src/integration/quality/"
    );

    assert!(
        quality_root.join("mod.rs").exists(),
        "quality gates must be grouped behind src/integration/quality/mod.rs"
    );

    for module in QUALITY_MODULES {
        let root_path = source_root.join(module);
        assert!(
            !root_path.exists(),
            "quality module {module} must not live at src/ root; move it under src/integration/quality/"
        );

        let quality_path = quality_root.join(module);
        assert!(
            quality_path.exists(),
            "quality module {module} must live under src/integration/quality/"
        );
    }
}

#[test]
fn optimization_contracts_live_under_optimizer_contracts_module() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_root = manifest.join("src");
    let optimization_facade = source_root.join("optimization").join("mod.rs");
    let contracts_root = source_root.join("optimizer").join("contracts");

    assert!(
        optimization_facade.exists(),
        "historic src/optimization/mod.rs facade must remain for compatibility"
    );
    let facade_source = std::fs::read_to_string(&optimization_facade)
        .unwrap_or_else(|err| panic!("{} must be readable: {err}", optimization_facade.display()));
    assert!(
        facade_source.contains("pub use crate::optimizer::contracts"),
        "optimization facade must re-export optimizer::contracts instead of owning implementation files"
    );
    assert!(
        contracts_root.join("mod.rs").exists(),
        "optimizer contracts must be grouped behind src/optimizer/contracts/mod.rs"
    );
    let contracts_mod =
        std::fs::read_to_string(contracts_root.join("mod.rs")).unwrap_or_else(|err| {
            panic!(
                "{} must be readable: {err}",
                contracts_root.join("mod.rs").display()
            )
        });

    for module in OPTIMIZER_CONTRACT_MODULES {
        let root_path = source_root.join(module);
        assert!(
            !root_path.exists(),
            "optimization module {module} must not live at src/ root; move it under src/optimizer/contracts/"
        );

        let old_optimization_path = source_root.join("optimization").join(module);
        assert!(
            !old_optimization_path.exists(),
            "optimization module {module} must not live beside the compatibility facade; move implementation into src/optimizer/contracts/"
        );

        let contracts_path = contracts_root.join(module);
        assert!(
            contracts_path.exists(),
            "optimization module {module} must live under src/optimizer/contracts/"
        );

        let stem = module
            .strip_suffix(".rs")
            .expect("optimizer contract entries must be Rust source files");
        assert!(
            contracts_mod.contains(&format!("mod {stem};")),
            "optimizer/contracts/mod.rs must declare mod {stem}; so contract imports cross one optimizer-owned boundary"
        );
    }
}

#[test]
fn math_kernels_live_under_math_module() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_root = manifest.join("src");
    let math_root = source_root.join("math");

    assert!(
        math_root.join("mod.rs").exists(),
        "advanced math kernels must be grouped behind src/math/mod.rs"
    );

    for module in MATH_MODULES {
        let root_path = source_root.join(module);
        assert!(
            !root_path.exists(),
            "math module {module} must not live at src/ root; move it under src/math/"
        );

        let math_path = math_root.join(module);
        assert!(
            math_path.exists(),
            "math module {module} must live under src/math/"
        );
    }
}

#[test]
fn coverage_contracts_live_under_coverage_module() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_root = manifest.join("src");
    let legacy_coverage_root = source_root.join("coverage");
    let coverage_root = source_root.join("integration").join("coverage");
    assert!(
        !legacy_coverage_root.exists(),
        "legacy src/coverage/ must stay empty or absent; coverage contracts belong under src/integration/coverage/"
    );

    assert!(
        coverage_root.join("mod.rs").exists(),
        "coverage contracts must be grouped behind src/integration/coverage/mod.rs"
    );

    for module in COVERAGE_MODULES {
        let root_path = source_root.join(module);
        assert!(
            !root_path.exists(),
            "coverage module {module} must not live at src/ root; move it under src/integration/coverage/"
        );

        let coverage_path = coverage_root.join(module);
        assert!(
            coverage_path.exists(),
            "coverage module {module} must live under src/integration/coverage/"
        );
    }
}

#[test]
fn evidence_validators_live_under_evidence_module() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_root = manifest.join("src");
    let legacy_evidence_root = source_root.join("evidence");
    let evidence_root = source_root.join("integration").join("evidence");
    assert!(
        !legacy_evidence_root.exists(),
        "legacy src/evidence/ must stay empty or absent; evidence validators belong under src/integration/evidence/"
    );

    assert!(
        evidence_root.join("mod.rs").exists(),
        "evidence validators must be grouped behind src/integration/evidence/mod.rs"
    );

    for module in EVIDENCE_MODULES {
        let root_path = source_root.join(module);
        assert!(
            !root_path.exists(),
            "evidence module {module} must not live at src/ root; move it under src/integration/evidence/"
        );

        let evidence_path = evidence_root.join(module);
        assert!(
            evidence_path.exists(),
            "evidence module {module} must live under src/integration/evidence/"
        );
    }
}

#[test]
fn hardware_contracts_live_under_hardware_module() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_root = manifest.join("src");
    let hardware_root = source_root.join("hardware");

    assert!(
        hardware_root.join("mod.rs").exists(),
        "hardware contracts must be grouped behind src/hardware/mod.rs"
    );

    for module in HARDWARE_MODULES {
        let root_path = source_root.join(module);
        assert!(
            !root_path.exists(),
            "hardware module {module} must not live at src/ root; move it under src/hardware/"
        );

        let hardware_path = hardware_root.join(module);
        assert!(
            hardware_path.exists(),
            "hardware module {module} must live under src/hardware/"
        );
    }
}

#[test]
fn release_gates_live_under_release_module() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_root = manifest.join("src");
    let legacy_release_root = source_root.join("release");
    let release_root = source_root.join("integration").join("release");
    assert!(
        !legacy_release_root.exists(),
        "legacy src/release/ must stay empty or absent; release gates belong under src/integration/release/"
    );

    assert!(
        release_root.join("mod.rs").exists(),
        "release gates must be grouped behind src/integration/release/mod.rs"
    );

    for gate in RELEASE_GATES {
        let root_path = source_root.join(gate);
        assert!(
            !root_path.exists(),
            "release gate {gate} must not live at src/ root; move it under src/integration/release/"
        );

        let release_path = release_root.join(gate);
        assert!(
            release_path.exists(),
            "release gate {gate} must live under src/integration/release/"
        );
    }
}
