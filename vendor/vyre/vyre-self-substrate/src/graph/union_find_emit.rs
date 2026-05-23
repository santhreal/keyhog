//! Union-find substrate consumer.
//!
//! The self-substrate consumes the same backend-neutral IR primitive as any
//! other caller. Concrete drivers are responsible for target emission.

use vyre_foundation::ir::Program;
use vyre_primitives::graph::union_find::{union_find_program, validate_union_find_inputs};

use crate::dispatch_buffers::{
    ceil_div_u32, decode_u32_output_exact, ensure_input_slots, write_u32_slice_le_bytes,
    write_u32_slice_or_zero_words,
};
use crate::optimizer::dispatcher::{DispatchError, OptimizerDispatcher};

/// Caller-owned GPU dispatch scratch for union-find emission.
#[derive(Debug, Default)]
pub struct UnionFindGpuScratch {
    inputs: Vec<Vec<u8>>,
}

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

/// Path-compress every entry in `parent` so each cell holds the
/// canonical root of its component. Pure reference helper used by parity
/// tests to compare partitions independent of intermediate parent
/// links.
#[cfg(any(test, feature = "cpu-parity"))]
#[must_use]
pub fn canonicalize_parent_to_roots(parent: &[u32]) -> Vec<u32> {
    let mut roots = parent.to_vec();
    for i in 0..roots.len() {
        let mut node = i as u32;
        while (node as usize) < roots.len() && roots[node as usize] != node {
            node = roots[node as usize];
        }
        roots[i] = node;
    }
    roots
}

/// Reference oracle for the union-find batch: starting from `parent_init`
/// (typically the identity vector `[0, 1, 2, ...]`), apply each
/// `(edge_a[k], edge_b[k])` union via path-compressed find. Returns
/// the final parent vector (NOT root-canonicalised — feed to
/// [`canonicalize_parent_to_roots`] for partition comparison).
#[cfg(any(test, feature = "cpu-parity"))]
#[must_use]
pub fn reference_union_find_alias(parent_init: &[u32], edge_a: &[u32], edge_b: &[u32]) -> Vec<u32> {
    assert_eq!(
        edge_a.len(),
        edge_b.len(),
        "Fix: edge_a / edge_b must have matching length; got {} vs {}.",
        edge_a.len(),
        edge_b.len()
    );
    let mut parent = parent_init.to_vec();
    fn find(parent: &mut [u32], mut x: u32) -> u32 {
        while parent[x as usize] != x {
            let next = parent[x as usize];
            parent[x as usize] = parent[next as usize];
            x = next;
        }
        x
    }
    for (&a, &b) in edge_a.iter().zip(edge_b.iter()) {
        let ra = find(&mut parent, a);
        let rb = find(&mut parent, b);
        if ra != rb {
            // Union by min — matches the GPU CAS-min contract so root
            // identifiers agree exactly modulo `canonicalize_parent_to_roots`.
            let (lo, hi) = if ra < rb { (ra, rb) } else { (rb, ra) };
            parent[hi as usize] = lo;
        }
    }
    parent
}

/// GPU dispatch wrapper for the batched union-find primitive. Builds
/// the `union_find_program`, dispatches it through `dispatcher`, and
/// returns the post-batch parent vector. The backend owns union and
/// path-compression execution; host reference helpers are compiled only
/// for parity tests.
///
/// # Errors
///
/// Propagates any [`DispatchError`] surfaced by the dispatcher.
pub fn union_find_alias_via(
    dispatcher: &dyn OptimizerDispatcher,
    parent_init: &[u32],
    edge_a: &[u32],
    edge_b: &[u32],
) -> Result<Vec<u32>, DispatchError> {
    let mut parent = Vec::new();
    union_find_alias_via_into(dispatcher, parent_init, edge_a, edge_b, &mut parent)?;
    Ok(parent)
}

/// GPU dispatch wrapper for the batched union-find primitive into caller-owned
/// output storage.
///
/// # Errors
///
/// Returns [`DispatchError`] when inputs are malformed, dispatch fails, or the
/// backend returns a malformed parent buffer.
pub fn union_find_alias_via_into(
    dispatcher: &dyn OptimizerDispatcher,
    parent_init: &[u32],
    edge_a: &[u32],
    edge_b: &[u32],
    parent_out: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    let mut scratch = UnionFindGpuScratch::default();
    union_find_alias_via_with_scratch_into(
        dispatcher,
        parent_init,
        edge_a,
        edge_b,
        &mut scratch,
        parent_out,
    )
}

/// GPU dispatch wrapper for the batched union-find primitive into caller-owned
/// dispatch and output storage.
///
/// # Errors
///
/// Returns [`DispatchError`] when inputs are malformed, dispatch fails, or the
/// backend returns a malformed parent buffer.
pub fn union_find_alias_via_with_scratch_into(
    dispatcher: &dyn OptimizerDispatcher,
    parent_init: &[u32],
    edge_a: &[u32],
    edge_b: &[u32],
    scratch: &mut UnionFindGpuScratch,
    parent_out: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    let layout = validate_union_find_inputs(parent_init, edge_a, edge_b)
        .map_err(DispatchError::BadInputs)?;
    if layout.node_count == 0 {
        parent_out.clear();
        return Ok(());
    }
    if layout.edge_count == 0 {
        parent_out.clear();
        parent_out.extend_from_slice(parent_init);
        return Ok(());
    }

    let program = union_find_alias_program(
        "parent",
        "edge_a",
        "edge_b",
        layout.node_count,
        layout.edge_count,
    );

    // The Program declares edge_a / edge_b buffers with
    // `edge_count.max(1)` elements so the lowering pipeline can still
    // emit valid bind-group descriptors when the input is empty. Pad
    // the wire bytes to match — the kernel guards reads with
    // `lt(lane, edge_count)` so the padding bytes are never read.
    ensure_input_slots(&mut scratch.inputs, 3);
    write_u32_slice_le_bytes(&mut scratch.inputs[0], parent_init);
    write_u32_slice_or_zero_words(
        &mut scratch.inputs[1],
        edge_a,
        layout.edge_storage_words,
        "union_find_alias_via edge_a",
    )?;
    write_u32_slice_or_zero_words(
        &mut scratch.inputs[2],
        edge_b,
        layout.edge_storage_words,
        "union_find_alias_via edge_b",
    )?;

    let grid_x = ceil_div_u32(layout.edge_count, 256);
    let outputs = dispatcher.dispatch(&program, &scratch.inputs, Some([grid_x, 1, 1]))?;
    if outputs.is_empty() {
        return Err(DispatchError::BackendError(format!(
            "Fix: union_find_alias_via expected at least one output buffer, got {}.",
            outputs.len()
        )));
    }
    decode_u32_output_exact(
        &outputs[0],
        layout.node_words,
        "union_find_alias_via",
        parent_out,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch_buffers::u32_slice_to_le_bytes;
    use vyre_foundation::ir::Program;

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

    struct UnionFindDispatcher;

    impl OptimizerDispatcher for UnionFindDispatcher {
        fn dispatch(
            &self,
            _program: &Program,
            inputs: &[Vec<u8>],
            grid_override: Option<[u32; 3]>,
        ) -> Result<Vec<Vec<u8>>, DispatchError> {
            assert_eq!(grid_override, Some([1, 1, 1]));
            assert_eq!(inputs.len(), 3);
            let mut parent = read_u32s(&inputs[0]);
            let edge_a = read_u32s(&inputs[1]);
            let edge_b = read_u32s(&inputs[2]);
            fn find(parent: &mut [u32], mut x: u32) -> u32 {
                while parent[x as usize] != x {
                    let next = parent[x as usize];
                    parent[x as usize] = parent[next as usize];
                    x = next;
                }
                x
            }
            for (&a, &b) in edge_a.iter().zip(edge_b.iter()) {
                if a as usize >= parent.len() || b as usize >= parent.len() {
                    continue;
                }
                let ra = find(&mut parent, a);
                let rb = find(&mut parent, b);
                if ra != rb {
                    let (lo, hi) = if ra < rb { (ra, rb) } else { (rb, ra) };
                    parent[hi as usize] = lo;
                }
            }
            Ok(vec![u32_slice_to_le_bytes(&parent)])
        }
    }

    fn read_u32s(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks_exact(std::mem::size_of::<u32>())
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect()
    }

    #[test]
    fn union_find_alias_via_dispatches_primitive() {
        let parent = vec![0, 1, 2, 3];
        let out = union_find_alias_via(&UnionFindDispatcher, &parent, &[0, 2], &[1, 3]).unwrap();

        assert_eq!(
            canonicalize_parent_to_roots(&out),
            canonicalize_parent_to_roots(&reference_union_find_alias(&parent, &[0, 2], &[1, 3]))
        );
    }

    #[test]
    fn union_find_alias_via_into_reuses_output() {
        let parent = vec![0, 1, 2, 3];
        let mut out = Vec::with_capacity(8);
        let ptr = out.as_ptr();

        union_find_alias_via_into(&UnionFindDispatcher, &parent, &[0, 2], &[1, 3], &mut out)
            .unwrap();

        assert_eq!(out.as_ptr(), ptr);
        assert_eq!(canonicalize_parent_to_roots(&out), vec![0, 0, 2, 2]);
    }

    #[test]
    fn union_find_alias_via_with_scratch_reuses_dispatch_and_output_storage() {
        let parent = vec![0, 1, 2, 3];
        let mut scratch = UnionFindGpuScratch::default();
        let mut out = Vec::with_capacity(4);

        union_find_alias_via_with_scratch_into(
            &UnionFindDispatcher,
            &parent,
            &[0, 2],
            &[1, 3],
            &mut scratch,
            &mut out,
        )
        .unwrap();

        let input_capacities = scratch.inputs.iter().map(Vec::capacity).collect::<Vec<_>>();
        let out_capacity = out.capacity();

        union_find_alias_via_with_scratch_into(
            &UnionFindDispatcher,
            &parent,
            &[0, 1],
            &[2, 3],
            &mut scratch,
            &mut out,
        )
        .unwrap();

        assert_eq!(
            scratch.inputs.iter().map(Vec::capacity).collect::<Vec<_>>(),
            input_capacities
        );
        assert_eq!(out.capacity(), out_capacity);
        assert_eq!(canonicalize_parent_to_roots(&out), vec![0, 1, 0, 1]);
    }

    #[test]
    fn union_find_alias_via_rejects_mismatched_edges() {
        let err = union_find_alias_via(&UnionFindDispatcher, &[0, 1], &[0], &[1, 0]).unwrap_err();

        assert!(matches!(err, DispatchError::BadInputs(_)));
    }

    #[test]
    fn union_find_alias_via_rejects_malformed_parent_links() {
        let err = union_find_alias_via(&UnionFindDispatcher, &[0, 9], &[0], &[1]).unwrap_err();

        assert!(matches!(err, DispatchError::BadInputs(_)));
        assert!(err.to_string().contains("parent_init[1]=9"));
    }

    #[test]
    fn union_find_alias_via_rejects_empty_parent_with_edges_before_dispatch() {
        struct NoDispatch;

        impl OptimizerDispatcher for NoDispatch {
            fn dispatch(
                &self,
                _program: &Program,
                _inputs: &[Vec<u8>],
                _grid_override: Option<[u32; 3]>,
            ) -> Result<Vec<Vec<u8>>, DispatchError> {
                panic!("Fix: invalid empty-parent union-find input must not dispatch");
            }
        }

        let err = union_find_alias_via(&NoDispatch, &[], &[0], &[0])
            .expect_err("edges against empty parent set must be rejected");
        assert!(matches!(err, DispatchError::BadInputs(_)));
        assert!(err.to_string().contains("empty parent set"));
    }

    #[test]
    fn union_find_alias_via_empty_edges_returns_parent_without_dispatch() {
        struct NoDispatch;

        impl OptimizerDispatcher for NoDispatch {
            fn dispatch(
                &self,
                _program: &Program,
                _inputs: &[Vec<u8>],
                _grid_override: Option<[u32; 3]>,
            ) -> Result<Vec<Vec<u8>>, DispatchError> {
                panic!("Fix: empty union-find edge set must not submit a zero-work GPU dispatch");
            }
        }

        let mut out = Vec::with_capacity(8);
        union_find_alias_via_into(&NoDispatch, &[0, 1, 2], &[], &[], &mut out)
            .expect("Fix: empty union-find edge set must return parent_init");
        assert_eq!(out, vec![0, 1, 2]);
    }

    #[test]
    fn release_path_does_not_export_union_find_reference_oracles() {
        let source = include_str!("union_find_emit.rs");
        let via_section = source
            .split("pub fn union_find_alias_via(")
            .nth(1)
            .expect("release union-find via function must exist")
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("tests follow release union-find functions");
        assert!(
            !via_section.contains("reference_union_find_alias")
                && !via_section.contains("canonicalize_parent_to_roots"),
            "release union-find path must not depend on host reference or canonicalization helpers"
        );
        assert!(
            source.contains("#[cfg(any(test, feature = \"cpu-parity\"))]\n#[must_use]\npub fn reference_union_find_alias"),
            "union-find host reference must be compiled only for parity tests or explicit cpu-parity harnesses"
        );
    }
}
