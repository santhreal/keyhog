//! Tier 2.5 graph primitives.
//!
//! The path IS the interface. Callers write
//! `vyre_primitives::graph::toposort::toposort(...)`; no wildcard
//! re-exports.

/// Kahn's-algorithm topological sort.
pub mod toposort;

/// GPU-resident depth-wave dispatcher for bottom-up callee-before-
/// caller computations (e.g. weir::summary's per-procedure summary
/// fixpoint with topological ordering). Composes Node::Loop +
/// Node::Barrier + a per-lane depth predicate; no new sub-op.
pub mod level_wave;

/// Reachability scan — given a source set + edge list, which nodes
/// are transitively reachable?
pub mod reachable;

/// Canonical 5-buffer ProgramGraph ABI (CSR wire format, shared by
/// every graph primitive).
pub mod program_graph;

/// One BFS step that accumulates into frontier_out and reports changes.
pub mod csr_forward_or_changed;
/// One BFS frontier step over ProgramGraph CSR.
pub mod csr_forward_traverse;
/// One persistent-BFS workgroup step with coalesced change detection.
pub mod persistent_bfs_step;

/// Reverse-direction BFS frontier step.
pub mod csr_backward_traverse;

/// One BFS step over BOTH forward + backward edges.
pub mod csr_bidirectional;

/// Dominance-frontier query for SSA phi placement.
pub mod dominator_frontier;

/// Walk parent-pointer array from a target back to the root; emit
/// the materialized path into a u32 buffer.
pub mod path_reconstruct;

/// Motif witness helpers over ProgramGraph edge constraints.
pub mod motif;

/// Forward-Backward strongly-connected components decomposition over
/// ProgramGraph CSR.
pub mod scc_decompose;

/// Exploded-supergraph builder — (CFG × fact) pairs as graph vertices
/// so IFDS/IDE reduces to `csr_forward_traverse`. Scaffold for G3.
pub mod exploded;

/// Adaptive CSR / dense bitmatrix traversal — picks representation
/// per tile based on frontier density. Scaffold for G4.
pub mod adaptive_traverse;

/// Persistent BFS — multi-step frontier expansion in a single dispatch.
pub mod persistent_bfs;

/// IR Extension interface registering Alias-solving opcodes to the compiler front-end.
pub mod alias_registry;

/// Lock-free Union-Find for subset alias resolving constraint grids.
pub mod union_find;

/// 3D sub-warp dataflow tensors
pub mod tensor_flow_forward;
