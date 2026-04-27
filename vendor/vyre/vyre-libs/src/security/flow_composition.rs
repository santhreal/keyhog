use vyre::ir::Program;
use vyre_foundation::execution_plan::fusion::fuse_programs;
use vyre_primitives::bitset::and::bitset_and;
use vyre_primitives::bitset::and::cpu_ref as bitset_and_cpu_ref;
use vyre_primitives::bitset::and_not::bitset_and_not;
use vyre_primitives::bitset::and_not::cpu_ref as bitset_and_not_cpu_ref;
use vyre_primitives::bitset::any::bitset_any;
use vyre_primitives::graph::csr_forward_traverse::cpu_ref as csr_forward_cpu_ref;
use vyre_primitives::graph::csr_forward_traverse::{bitset_words, csr_forward_traverse};
use vyre_primitives::graph::program_graph::ProgramGraphShape;

use crate::region::{reparent_program_children, wrap_anonymous};
use crate::security::flows_to::FLOWS_TO_MASK;

pub(crate) fn fuse_security_flow(op_id: &'static str, parts: &[Program]) -> Program {
    let fused = fuse_programs(parts).expect("security flow composition must fuse cleanly");
    Program::wrapped(
        fused.buffers().to_vec(),
        fused.workgroup_size(),
        vec![wrap_anonymous(
            op_id,
            reparent_program_children(&fused, op_id),
        )],
    )
}

pub(crate) fn dataflow_reach_step(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    source: &[u32],
) -> Vec<u32> {
    csr_forward_cpu_ref(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        source,
        FLOWS_TO_MASK,
    )
}

pub(crate) fn any_dataflow_hit(reach: &[u32], sink: &[u32]) -> u32 {
    let hits = bitset_and_cpu_ref(reach, sink);
    u32::from(hits.iter().any(|word| *word != 0))
}

pub(crate) fn dataflow_hit_program(
    op_id: &'static str,
    shape: ProgramGraphShape,
    source_buf: &str,
    sink_buf: &str,
    reach_buf: &str,
    hits_buf: &str,
    out_scalar_buf: &str,
) -> Program {
    let words = bitset_words(shape.node_count);
    let traverse = csr_forward_traverse(shape, source_buf, reach_buf, FLOWS_TO_MASK);
    let intersect = bitset_and(reach_buf, sink_buf, hits_buf, words);
    let any = bitset_any(hits_buf, out_scalar_buf, words);
    fuse_security_flow(op_id, &[traverse, intersect, any])
}

pub(crate) fn sanitized_dataflow_hit_program(
    op_id: &'static str,
    shape: ProgramGraphShape,
    source_buf: &str,
    sink_buf: &str,
    sanitizer_buf: &str,
    clean_buf: &str,
    reach_buf: &str,
    alive_buf: &str,
    hits_buf: &str,
    out_scalar_buf: &str,
) -> Program {
    let words = bitset_words(shape.node_count);
    let pre_kill = bitset_and_not(source_buf, sanitizer_buf, clean_buf, words);
    let traverse = csr_forward_traverse(shape, clean_buf, reach_buf, FLOWS_TO_MASK);
    let post_kill = bitset_and_not(reach_buf, sanitizer_buf, alive_buf, words);
    let intersect = bitset_and(alive_buf, sink_buf, hits_buf, words);
    let any = bitset_any(hits_buf, out_scalar_buf, words);
    fuse_security_flow(op_id, &[pre_kill, traverse, post_kill, intersect, any])
}

pub(crate) fn sanitized_dataflow_hit(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    source: &[u32],
    sink: &[u32],
    sanitizer: &[u32],
) -> u32 {
    let clean = bitset_and_not_cpu_ref(source, sanitizer);
    let reach = dataflow_reach_step(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        &clean,
    );
    let alive = bitset_and_not_cpu_ref(&reach, sanitizer);
    any_dataflow_hit(&alive, sink)
}

#[cfg(test)]
pub(crate) fn linear_dataflow(node_count: u32) -> (Vec<u32>, Vec<u32>, Vec<u32>) {
    let mut offsets = vec![0u32; (node_count + 1) as usize];
    let mut targets = Vec::new();
    let mut masks = Vec::new();
    for i in 0..node_count.saturating_sub(1) {
        offsets[i as usize + 1] = offsets[i as usize] + 1;
        targets.push(i + 1);
        masks.push(vyre_primitives::predicate::edge_kind::ASSIGNMENT);
    }
    let penultimate = offsets[node_count as usize - 1];
    if let Some(last) = offsets.last_mut() {
        *last = penultimate;
    }
    (offsets, targets, masks)
}
