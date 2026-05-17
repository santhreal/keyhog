use crate::harness::OpEntry;

fn u32s(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|value| value.to_le_bytes()).collect()
}

macro_rules! bitset_and_entry {
    ($module:ident, $build:expr) => {
        inventory::submit! {
            OpEntry {
                id: super::$module::OP_ID,
                build: $build,
                test_inputs: Some(|| vec![vec![
                    u32s(&[0b1100]),
                    u32s(&[0b1010]),
                    u32s(&[0]),
                ]]),
                expected_output: Some(|| vec![vec![u32s(&[0b1000])]]),
            }
        }
    };
}

bitset_and_entry!(escapes, || super::escapes::escapes(4, "a", "b", "out"));
bitset_and_entry!(live_at, || super::live_at::live_at(4, "a", "b", "out"));
bitset_and_entry!(must_init, || super::must_init::must_init(
    4, "a", "b", "out"
));
bitset_and_entry!(post_dominates, || {
    super::post_dominates::post_dominates(4, "a", "b", "out")
});
bitset_and_entry!(reaching_def, || {
    super::reaching_def::reaching_def(4, "a", "b", "out")
});
bitset_and_entry!(scc_query, || super::scc_query::scc_query(
    4, "a", "b", "out"
));
bitset_and_entry!(value_set, || super::value_set::value_set(
    4, "a", "b", "out"
));

inventory::submit! {
    OpEntry {
        id: super::control_dependence::OP_ID,
        build: || super::control_dependence::control_dependence(4, "a", "b", "out"),
        test_inputs: Some(|| vec![vec![
            u32s(&[0b1111]),
            u32s(&[0b1100]),
            u32s(&[0]),
        ]]),
        expected_output: Some(|| vec![vec![u32s(&[0b0011])]]),
    }
}

inventory::submit! {
    OpEntry {
        id: super::may_alias::OP_ID,
        build: || super::may_alias::may_alias(4, "a", "b", "scratch", "out"),
        test_inputs: Some(|| vec![vec![
            u32s(&[0b1100]),
            u32s(&[0b1010]),
            u32s(&[0]),
        ]]),
        expected_output: Some(|| vec![vec![
            u32s(&[0b1000]),
            u32s(&[1]),
        ]]),
    }
}


// ---- Legendary-plan dataflow primitives (DF-5, DF-6, DF-7, DF-8, DF-9, DF-10) ----

inventory::submit! {
    OpEntry {
        id: super::callgraph::OP_ID,
        build: || super::callgraph::callgraph_build("direct", "indirect", "pts", "out"),
        test_inputs: Some(|| vec![vec![
            u32s(&[0b1100]),       // direct
            u32s(&[0b1010]),       // indirect
            u32s(&[0b0110]),       // pts_closure
            u32s(&[0b0000]),       // out accumulator
        ]]),
        expected_output: Some(|| vec![vec![u32s(&[0b1110])]]),
    }
}

inventory::submit! {
    OpEntry {
        id: super::slice::OP_ID,
        build: || super::slice::backward_slice(
            vyre_primitives::graph::program_graph::ProgramGraphShape::new(4, 3),
            "fin",
            "fout",
        ),
        test_inputs: Some(|| vec![vec![
            u32s(&[0, 0, 0, 0]),          // pg_nodes
            u32s(&[0, 1, 2, 3, 3]),       // pg_edge_offsets
            u32s(&[1, 2, 3]),             // pg_edge_targets
            u32s(&[
                vyre_primitives::predicate::edge_kind::ASSIGNMENT,
                vyre_primitives::predicate::edge_kind::ASSIGNMENT,
                vyre_primitives::predicate::edge_kind::ASSIGNMENT,
            ]),                           // pg_edge_kind_mask
            u32s(&[0, 0, 0, 0]),          // pg_node_tags
            u32s(&[0b1000]),              // fin = {3} (sink)
            u32s(&[0b1000]),              // fout accumulator seed = {3}
        ]]),
        expected_output: Some(|| vec![vec![u32s(&[0b1100])]]),
    }
}

inventory::submit! {
    OpEntry {
        id: super::range::OP_ID,
        build: || super::range::range_propagate("defs", "edges", "out"),
        test_inputs: Some(|| vec![vec![
            u32s(&[1, 5, 2, 8, 0, 0, 0, 0]),   // defs [lo0, hi0, lo1, hi1, ...]
            u32s(&[10, 1, 3, 2, 0, 0, 0, 0]),  // edges [t_lo0, t_hi0, ...]
            u32s(&[0, 0, 0, 0, 0, 0, 0, 0]),   // out accumulator
        ]]),
        expected_output: Some(|| vec![vec![u32s(&[11, 6, 5, 10, 0, 0, 0, 0])]]),
    }
}

inventory::submit! {
    OpEntry {
        id: super::escape::OP_ID,
        build: || super::escape::escape_analyze("pts", "cg", "out"),
        test_inputs: Some(|| vec![vec![
            u32s(&[0b1100, 0]),     // pts (2 words for 64 nodes)
            u32s(&[0b1010, 0]),     // cg
            u32s(&[0b0000, 0]),     // out accumulator
        ]]),
        expected_output: Some(|| vec![vec![u32s(&[0b1110, 0])]]),
    }
}

inventory::submit! {
    OpEntry {
        id: super::summary::OP_ID,
        build: || super::summary::summarize_function("ast", "cg", "cached", "out"),
        test_inputs: Some(|| vec![vec![
            u32s(&[0b1100, 0]),     // ast
            u32s(&[0b1010, 0]),     // cg
            u32s(&[0b0110, 0]),     // cached
            u32s(&[0b0000, 0]),     // out accumulator
        ]]),
        expected_output: Some(|| vec![vec![u32s(&[0b1110, 0])]]),
    }
}

inventory::submit! {
    OpEntry {
        id: super::loop_sum::OP_ID,
        build: || super::loop_sum::loop_summarize("cfg", "ranges", "out"),
        test_inputs: Some(|| vec![vec![
            u32s(&[10, 20, 5, 15, 0, 0, 0, 0]),   // cfg [prev_lo0, prev_hi0, prev_lo1, prev_hi1, ...]
            u32s(&[5, 25, 8, 12, 0, 0, 0, 0]),    // ranges [new_lo0, new_hi0, ...]
            u32s(&[0, 0, 0, 0, 0, 0, 0, 0]),      // out accumulator
        ]]),
        expected_output: Some(|| vec![vec![u32s(&[0, u32::MAX, 5, 15, 0, 0, 0, 0])]]),
    }
}
