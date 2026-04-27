//! Universal Cat-A op harness registry — moved into the standalone
//! `vyre-harness` crate so external wrapper libraries (e.g. `weir`,
//! `decodex`, `multimatch`) can publish into the same registry
//! without depending on the rest of `vyre-libs`. This module is a
//! thin re-export so existing call sites
//! (`vyre_libs::harness::OpEntry`, etc.) keep compiling unchanged.

pub use vyre_harness::{
    all_entries, convergence_contract, fixpoint_contract, universal_diff_candidates,
    universal_diff_exemption, ConvergenceContract, DiffCandidate, ExpectedFn, FixpointContract,
    FixpointRegistration, InputsFn, OpEntry, UniversalDiffExemption,
};
pub use vyre_harness::{
    region, reparent_program_children, tag_program, wrap, wrap_anonymous, wrap_child,
};
