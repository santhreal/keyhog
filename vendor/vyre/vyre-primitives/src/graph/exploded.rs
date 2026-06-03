//! Exploded supergraph primitive (G3).
//!
//! # What this is
//!
//! IFDS / IDE reframes interprocedural dataflow as a reachability
//! problem on the **exploded supergraph**: each `(proc, block,
//! fact)` triple is a graph vertex, and the edges are the flow
//! functions (GEN / KILL + summary + call-to-return). Once
//! expanded, the analysis collapses to a BFS over this graph  -
//! which is the exact shape
//! [`crate::graph::csr_forward_traverse`] already handles.
//!
//! This module owns the **node encoding**  -  the bit-layout that
//! packs `(proc_id, block_id, fact_id)` into a single `u32` node id
//!  -  plus a CPU reference that builds the exploded CSR so tests in
//! `vyre-libs::dataflow::ifds_gpu` can prove the GPU kernel produces
//! byte-identical CSR output.
//!
//! # Bit layout
//!
//! ```text
//!   bits 31..20   proc_id   (12 bits  -  4096 procedures per module)
//!   bits 19..10   block_id  (10 bits  -  1024 blocks per procedure)
//!   bits 9..0     fact_id   (10 bits  -  1024 facts per workgroup;
//!                            matches FACTS_PER_WORKGROUP and the
//!                            NFA subgroup sizing)
//! ```
//!
//! This deliberately leaves no room for >4096 procedures in a
//! single module. Any real codebase that exceeds that split along
//! a module boundary first  -  doing interprocedural dataflow over
//! 10 000+ procs in one pass is a different problem that we don't
//! solve here and shouldn't pretend to.
//!
//! # Status
//!
//! Node encoding, CSR builder, and tests. The GPU Program wrapper
//! (the actual kernel that walks edges in parallel) lives in
//! `vyre-libs::dataflow::ifds_gpu` and composes this encoding with
//! `csr_forward_traverse`.

#[path = "exploded/abi.rs"]
mod abi;
#[path = "exploded/canonicalize.rs"]
mod canonicalize;
#[path = "exploded/cpu_ref.rs"]
mod cpu_ref;
#[path = "exploded/dispatch_plan.rs"]
mod dispatch_plan;
#[path = "exploded/encoding.rs"]
mod encoding;
#[path = "exploded/layout.rs"]
mod layout;
#[path = "exploded/program_ir.rs"]
mod program_ir;
#[path = "exploded/program_key.rs"]
mod program_key;
#[path = "exploded/validation.rs"]
mod validation;

#[cfg(test)]
#[path = "exploded/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "exploded/tests/dispatch_plan_tests.rs"]
mod dispatch_plan_tests;

#[cfg(test)]
#[path = "exploded/tests/rule_column_tests.rs"]
mod rule_column_tests;

#[cfg(test)]
#[path = "exploded/tests/cpu_reference_tests.rs"]
mod cpu_reference_tests;

pub use abi::*;
pub use canonicalize::*;
#[cfg(any(test, feature = "cpu-parity"))]
pub use cpu_ref::*;
pub use dispatch_plan::*;
pub use encoding::*;
pub use layout::*;
pub use program_ir::*;
#[cfg(any(test, feature = "cpu-parity"))]
pub use program_key::*;
pub use validation::*;
