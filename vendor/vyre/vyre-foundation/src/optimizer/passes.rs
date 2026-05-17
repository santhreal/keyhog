//! Registered reference optimizer passes.
//!
//! Layout (audit cleanup A3, 2026-04-30): passes are grouped into category
//! subdirs aligned with the Phase 4 catalog buckets so the directory scales
//! to ~250 named transforms without becoming an unreviewable flat dir:
//!
//! - `algebraic/` (Phase 4A) — const_fold, strength_reduce,
//!   canonicalize, normalize_atomics
//! - `loops/` (Phase 4B) — loop_unroll, loop_trip_zero_eliminate
//! - `memory/` (Phase 4C) — const_buffer_fold, dead_buffer_elim,
//!   read_only_load_hoist, vectorization, decode_scan_fuse
//! - `sync/` (Phase 4D) — barrier_coalesce
//! - `fusion_cse/` — fusion, fuse_cse, cse, dce
//! - `cleanup/` — empty_block_collapse, region_inline,
//!   if_constant_branch_eliminate, noop_assign_eliminate,
//!   region_promote_singleton_block, buffer_decl_sort
//! - `specialization/` (Phase 4G) — autotune
//!
//! Backend-specific lowering strategy code belongs in the concrete driver
//! crates. Foundation passes are math- and IR-structural rewrites that any
//! backend can inherit before target emission.
//!
//! Back-compat re-exports below preserve the historical `passes::<pass>`
//! path while registration itself is driven by the pass inventory.

pub mod algebraic;
pub mod cleanup;
pub mod fusion_cse;
pub mod loops;
pub mod memory;
pub mod specialization;
pub mod sync;

// ---- Back-compat re-exports (historical `passes::<pass_name>` path) -----
//
// Public re-exports keep downstream pass tests and tools on the stable
// `passes::<pass_name>` path while the scheduler discovers runnable passes
// from the inventory registry.

pub use algebraic::{canonicalize, const_fold, normalize_atomics, strength_reduce};
pub use cleanup::{
    buffer_decl_sort, empty_block_collapse, if_constant_branch_eliminate, noop_assign_eliminate,
    region_inline, region_promote_singleton_block,
};
pub use fusion_cse::{cse, dce, fuse_cse, fusion};
pub use loops::{
    loop_redundant_bound_check_elide, loop_strip_mine, loop_trip_zero_eliminate, loop_unroll,
};
pub use memory::{
    const_buffer_fold, dead_buffer_elim, decode_scan_fuse, read_only_load_hoist, vectorization,
};
pub use specialization::autotune;
pub use sync::barrier_coalesce;
