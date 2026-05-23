//! Registered Tier-3 consumers for Tier-2.5 primitives.
//!
//! These wrappers keep the primitive substrate executable from the same
//! inventory surface as the rest of `vyre-libs`. Each wrapper builds the real
//! primitive Program and tags it under an owning library op id, so conformance,
//! composition audits, and downstream catalogs see runnable IR rather than an
//! orphan primitive.

use std::sync::Arc;

use vyre::ir::{BufferAccess, Node, Program};
use vyre_foundation::ir::model::expr::{GeneratorRef, Ident};

fn primitive_program(wrapper_id: &str, primitive_id: &str) -> Program {
    let Some(entry) =
        vyre_primitives::harness::all_entries().find(|entry| entry.id == primitive_id)
    else {
        panic!(
            "vyre-libs primitive catalog wrapper `{wrapper_id}` targets unregistered primitive `{primitive_id}`. Fix: register the primitive harness entry or remove the stale wrapper."
        );
    };
    let primitive = (entry.build)();
    let primitive_child = Node::Region {
        generator: Ident::from(primitive_id),
        source_region: Some(GeneratorRef {
            name: wrapper_id.to_string(),
        }),
        body: Arc::new(primitive.entry().to_vec()),
    };
    Program::wrapped(
        primitive.buffers().to_vec(),
        primitive.workgroup_size(),
        vec![crate::region::wrap_anonymous(
            wrapper_id,
            vec![primitive_child],
        )],
    )
}

fn backend_owned_output(access: BufferAccess, is_output: bool, is_pipeline_live_out: bool) -> bool {
    matches!(access, BufferAccess::WriteOnly)
        || is_output
        || (is_pipeline_live_out && matches!(access, BufferAccess::ReadWrite))
}

fn catalog_inputs_for(entry: &vyre_primitives::harness::OpEntry) -> Vec<Vec<Vec<u8>>> {
    let program = (entry.build)();
    let logical_input_count = program
        .buffers()
        .iter()
        .filter(|buffer| {
            !matches!(buffer.access(), BufferAccess::Workgroup)
                && !backend_owned_output(
                    buffer.access(),
                    buffer.is_output(),
                    buffer.is_pipeline_live_out(),
                )
        })
        .count();
    let legacy_input_count = program
        .buffers()
        .iter()
        .filter(|buffer| !matches!(buffer.access(), BufferAccess::Workgroup))
        .count();
    let raw_cases = entry.test_inputs.map(|build| build()).unwrap_or_else(|| {
        panic!(
            "vyre-libs primitive catalog fixture targets primitive `{}` without test inputs. Fix: add primitive harness inputs before wrapping it.",
            entry.id
        )
    });
    raw_cases
        .into_iter()
        .map(|case| {
            if case.len() == logical_input_count {
                return case;
            }
            if case.len() != legacy_input_count {
                panic!(
                    "vyre-libs primitive catalog fixture `{}` has {} input buffers but program expects {} logical inputs or {} legacy non-workgroup buffers. Fix: repair the primitive harness fixture.",
                    entry.id,
                    case.len(),
                    logical_input_count,
                    legacy_input_count
                );
            }
            program
                .buffers()
                .iter()
                .filter(|buffer| !matches!(buffer.access(), BufferAccess::Workgroup))
                .zip(case)
                .filter_map(|(buffer, value)| {
                    if backend_owned_output(
                        buffer.access(),
                        buffer.is_output(),
                        buffer.is_pipeline_live_out(),
                    ) {
                        None
                    } else {
                        Some(value)
                    }
                })
                .collect()
        })
        .collect()
}

macro_rules! catalog_pair {
    ($base:literal, $primitive:literal) => {
        const _: () = {
            fn inputs() -> Vec<Vec<Vec<u8>>> {
                let Some(entry) =
                    vyre_primitives::harness::all_entries().find(|entry| entry.id == $primitive)
                else {
                    panic!(
                        "vyre-libs primitive catalog fixture `{}` targets unregistered primitive `{}`. Fix: register the primitive harness entry or remove the stale wrapper.",
                        concat!($base, "::consumer_a"),
                        $primitive
                    );
                };
                catalog_inputs_for(entry)
            }
            fn expected() -> Vec<Vec<Vec<u8>>> {
                let Some(entry) =
                    vyre_primitives::harness::all_entries().find(|entry| entry.id == $primitive)
                else {
                    panic!(
                        "vyre-libs primitive catalog fixture `{}` targets unregistered primitive `{}`. Fix: register the primitive harness entry or remove the stale wrapper.",
                        concat!($base, "::consumer_a"),
                        $primitive
                    );
                };
                entry
                    .expected_output
                    .map(|build| build())
                    .unwrap_or_else(|| {
                        panic!(
                            "vyre-libs primitive catalog fixture `{}` targets primitive `{}` without expected outputs. Fix: add primitive harness expected outputs before wrapping it.",
                            concat!($base, "::consumer_a"),
                            $primitive
                        )
                    })
            }

            inventory::submit! {
                crate::harness::OpEntry {
                    id: concat!($base, "::consumer_a"),
                    build: || primitive_program(concat!($base, "::consumer_a"), $primitive),
                    test_inputs: Some(inputs),
                    expected_output: Some(expected),
                    category: None,
                }
            }
            inventory::submit! {
                crate::harness::OpEntry {
                    id: concat!($base, "::consumer_b"),
                    build: || primitive_program(concat!($base, "::consumer_b"), $primitive),
                    test_inputs: Some(inputs),
                    expected_output: Some(expected),
                    category: None,
                }
            }
        };
    };
}

catalog_pair!(
    "vyre-libs::catalog::predicate::return_value_of",
    "vyre-primitives::predicate::return_value_of"
);
catalog_pair!(
    "vyre-libs::catalog::bitset::popcount",
    "vyre-primitives::bitset::popcount"
);
catalog_pair!(
    "vyre-libs::catalog::predicate::size_argument_of",
    "vyre-primitives::predicate::size_argument_of"
);
catalog_pair!(
    "vyre-libs::catalog::predicate::node_kind_eq",
    "vyre-primitives::predicate::node_kind_eq"
);
catalog_pair!(
    "vyre-libs::catalog::predicate::in_function",
    "vyre-primitives::predicate::in_function"
);
catalog_pair!(
    "vyre-libs::catalog::bitset::not",
    "vyre-primitives::bitset::not"
);
catalog_pair!(
    "vyre-libs::catalog::graph::tensor_flow_forward",
    "vyre-primitives::graph::tensor_flow_forward"
);
catalog_pair!(
    "vyre-libs::catalog::predicate::literal_of",
    "vyre-primitives::predicate::literal_of"
);
catalog_pair!(
    "vyre-libs::catalog::reduce::segment_reduce_sum",
    "vyre-primitives::reduce::segment_reduce_sum"
);
catalog_pair!(
    "vyre-libs::catalog::reduce::min",
    "vyre-primitives::reduce::min"
);
catalog_pair!(
    "vyre-libs::catalog::reduce::count",
    "vyre-primitives::reduce::count"
);
catalog_pair!(
    "vyre-libs::catalog::graph::scc_decompose",
    "vyre-primitives::graph::scc_decompose"
);
catalog_pair!(
    "vyre-libs::catalog::math::scallop_join_wide",
    "vyre-primitives::math::scallop_join_wide"
);
catalog_pair!(
    "vyre-libs::catalog::decode::inflate_stored",
    "vyre-primitives::decode::inflate_stored"
);
catalog_pair!(
    "vyre-libs::catalog::vfs::resolve",
    "vyre-primitives::vfs::resolve"
);
catalog_pair!(
    "vyre-libs::catalog::predicate::call_to",
    "vyre-primitives::predicate::call_to"
);
catalog_pair!(
    "vyre-libs::catalog::predicate::arg_of",
    "vyre-primitives::predicate::arg_of"
);
catalog_pair!(
    "vyre-libs::catalog::bitset::contains",
    "vyre-primitives::bitset::contains"
);
catalog_pair!(
    "vyre-libs::catalog::nn::quest_score_pages",
    "vyre-primitives::nn::quest_score_pages"
);
catalog_pair!(
    "vyre-libs::catalog::nn::quest_zero_fill",
    "vyre-primitives::nn::quest_zero_fill"
);
catalog_pair!(
    "vyre-libs::catalog::text::byte_histogram_256",
    "vyre-primitives::text::byte_histogram_256"
);
catalog_pair!(
    "vyre-libs::catalog::bitset::four_russians_apply_byte_lut",
    "vyre-primitives::bitset::four_russians_apply_byte_lut"
);
catalog_pair!(
    "vyre-libs::catalog::math::sheaf_laplacian_eigenvalue",
    "vyre-primitives::math::sheaf_laplacian_eigenvalue"
);
catalog_pair!(
    "vyre-libs::catalog::hash::fnv1a64",
    "vyre-primitives::hash::fnv1a64"
);
catalog_pair!(
    "vyre-libs::catalog::hash::fnv1a32",
    "vyre-primitives::hash::fnv1a32"
);
catalog_pair!(
    "vyre-libs::catalog::decode::base64_decode",
    "vyre-primitives::decode::base64_decode"
);
catalog_pair!(
    "vyre-libs::catalog::math::amg_v_cycle",
    "vyre-primitives::math::amg_v_cycle"
);
catalog_pair!(
    "vyre-libs::catalog::predicate::in_package",
    "vyre-primitives::predicate::in_package"
);
catalog_pair!(
    "vyre-libs::catalog::reduce::scatter",
    "vyre-primitives::reduce::scatter"
);
catalog_pair!(
    "vyre-libs::catalog::bitset::xor",
    "vyre-primitives::bitset::xor"
);
catalog_pair!(
    "vyre-libs::catalog::graph::persistent_bfs",
    "vyre-primitives::graph::persistent_bfs"
);
catalog_pair!(
    "vyre-libs::catalog::hash::blake3_round",
    "vyre-primitives::hash::blake3_round"
);
catalog_pair!(
    "vyre-libs::catalog::reduce::max",
    "vyre-primitives::reduce::max"
);
catalog_pair!(
    "vyre-libs::catalog::math::scallop_join",
    "vyre-primitives::math::scallop_join"
);
catalog_pair!(
    "vyre-libs::catalog::predicate::edge",
    "vyre-primitives::predicate::edge"
);
catalog_pair!(
    "vyre-libs::catalog::reduce::histogram",
    "vyre-primitives::reduce::histogram"
);
catalog_pair!(
    "vyre-libs::catalog::bitset::any",
    "vyre-primitives::bitset::any"
);
catalog_pair!(
    "vyre-libs::catalog::math::sinkhorn_iterate",
    "vyre-primitives::math::sinkhorn_iterate"
);
catalog_pair!(
    "vyre-libs::catalog::fixpoint::bitset_fixpoint",
    "vyre-primitives::fixpoint::bitset_fixpoint"
);
catalog_pair!(
    "vyre-libs::catalog::bitset::or",
    "vyre-primitives::bitset::or"
);
catalog_pair!(
    "vyre-libs::catalog::reduce::sum",
    "vyre-primitives::reduce::sum"
);
catalog_pair!(
    "vyre-libs::catalog::reduce::gather",
    "vyre-primitives::reduce::gather"
);
catalog_pair!(
    "vyre-libs::catalog::graph::persistent_bfs_step",
    "vyre-primitives::graph::persistent_bfs_step"
);
catalog_pair!(
    "vyre-libs::catalog::math::tensor_train_decompose",
    "vyre-primitives::math::tensor_train_decompose"
);
catalog_pair!(
    "vyre-libs::catalog::predicate::in_file",
    "vyre-primitives::predicate::in_file"
);
catalog_pair!(
    "vyre-libs::catalog::math::bellman_shortest_path",
    "vyre-primitives::math::bellman_shortest_path"
);
catalog_pair!(
    "vyre-libs::catalog::matching::bracket_match",
    "vyre-primitives::matching::bracket_match"
);
catalog_pair!(
    "vyre-libs::catalog::math::newton_schulz_poly5_f32",
    "vyre-primitives::math::newton_schulz_poly5_f32"
);
catalog_pair!(
    "vyre-libs::catalog::reduce::workgroup_sum_u32",
    "vyre-primitives::reduce::workgroup_sum_u32"
);
catalog_pair!(
    "vyre-libs::catalog::parsing::ast_cse_structural_hash",
    "vyre-primitives::parsing::ast_cse_structural_hash"
);
catalog_pair!(
    "vyre-libs::catalog::decode::rle_segment_lengths",
    "vyre-primitives::decode::rle_segment_lengths"
);
catalog_pair!(
    "vyre-libs::catalog::graph::vast_walk_postorder",
    "vyre-primitives::graph::vast_walk_postorder"
);
catalog_pair!(
    "vyre-libs::catalog::graph::vast_walk_preorder",
    "vyre-primitives::graph::vast_walk_preorder"
);
catalog_pair!(
    "vyre-libs::catalog::parsing::ssa_dominance_scan",
    "vyre-primitives::parsing::ssa_dominance_scan"
);
catalog_pair!(
    "vyre-libs::catalog::text::encoding_classify",
    "vyre-primitives::text::encoding_classify"
);
