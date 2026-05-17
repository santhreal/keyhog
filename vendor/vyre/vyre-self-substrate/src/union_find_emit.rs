//! Union-find substrate consumer.
//!
//! The self-substrate consumes the same backend-neutral IR primitive as any
//! other caller. Concrete drivers are responsible for target emission.

use vyre_foundation::ir::Program;
use vyre_primitives::graph::union_find::union_find_program;

/// Build the union-find alias-analysis program and record that the substrate
/// requested a dataflow-fixpoint primitive.
#[must_use]
pub fn union_find_alias_program(
    parent: &str,
    edge_a: &str,
    edge_b: &str,
    node_count: u32,
    edge_count: u32,
) -> Program {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    union_find_program(parent, edge_a, edge_b, node_count, edge_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_backend_neutral_union_find_program() {
        let program = union_find_alias_program("parent", "a", "b", 16, 8);
        assert_eq!(program.buffers().len(), 3);
        assert_eq!(program.entry_op_id(), None);
    }

    #[test]
    fn substrate_program_matches_primitive_shape() {
        let substrate = union_find_alias_program("parent", "a", "b", 16, 8);
        let primitive = union_find_program("parent", "a", "b", 16, 8);
        assert_eq!(substrate.buffers(), primitive.buffers());
        assert_eq!(substrate.workgroup_size(), primitive.workgroup_size());
    }

    #[test]
    fn substrate_no_longer_emits_target_text() {
        let program = union_find_alias_program("parent", "a", "b", 16, 8);
        let dump = format!("{program:#?}");
        assert!(dump.contains("Atomic"));
        assert!(!dump.contains("ptr<storage"));
        assert!(!dump.contains("atomicCAS"));
    }
}
