//! NFA primitives — subgroup-cooperative epsilon closure and
//! step simulation.
//!
//! G1 (GPU perf innovation #1) is a 32-state-per-subgroup NFA
//! simulator where each lane holds one `u32` state-set bit and
//! epsilon closure is subgroup ballot/shuffle bitwise-or. For NFAs
//! wider than 32 states, callers tile into 32-state windows and stream
//! the transition-table slice per tile.
//!
//! This file is the subsystem entry point. The primitive kernel
//! lives in `subgroup_nfa`; the multi-string / regex scan helper
//! that composes it lives in `vyre-libs/src/matching/nfa.rs`.

/// Subgroup-cooperative NFA simulation kernel.
pub mod subgroup_nfa;
