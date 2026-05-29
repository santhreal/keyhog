//! CSR frontier expansion over an in-place accumulator bitset.

#[path = "csr_forward_or_changed/layout.rs"]
mod layout;
#[path = "csr_forward_or_changed/body.rs"]
mod body;
#[path = "csr_forward_or_changed/program_serial.rs"]
mod program_serial;
#[path = "csr_forward_or_changed/program_parallel.rs"]
mod program_parallel;
#[path = "csr_forward_or_changed/batch_shared.rs"]
mod batch_shared;
#[path = "csr_forward_or_changed/program_parallel_batch.rs"]
mod program_parallel_batch;
#[path = "csr_forward_or_changed/program_parallel_batch_global.rs"]
mod program_parallel_batch_global;
#[path = "csr_forward_or_changed/cpu_ref.rs"]
mod cpu_ref;
#[path = "csr_forward_or_changed/hash.rs"]
mod hash;
#[path = "csr_forward_or_changed/launch_plan.rs"]
mod launch_plan;
#[path = "csr_forward_or_changed/validate.rs"]
mod validate;
#[path = "csr_forward_or_changed/dispatch_plan.rs"]
mod dispatch_plan;
#[path = "csr_forward_or_changed/program_dispatch.rs"]
mod program_dispatch;
#[path = "csr_forward_or_changed/plan.rs"]
mod plan;

#[cfg(feature = "inventory-registry")]
#[path = "csr_forward_or_changed/registry.rs"]
mod registry;

#[cfg(test)]
#[path = "csr_forward_or_changed/tests.rs"]
mod tests;

pub use body::{
    csr_forward_or_changed_body, csr_forward_or_changed_body_prefixed, csr_forward_or_changed_child,
    csr_forward_or_changed_child_prefixed,
};
#[cfg(any(test, feature = "cpu-parity"))]
pub use cpu_ref::{
    cpu_ref, cpu_ref_closure, cpu_ref_closure_into, cpu_ref_closure_into_with_step_hook,
};
pub use program_parallel::csr_forward_or_changed_parallel;
pub use program_parallel_batch::{
    csr_forward_or_changed_parallel_batch, try_csr_forward_or_changed_parallel_batch,
};
pub use program_parallel_batch_global::{
    csr_forward_or_changed_parallel_batch_global,
    csr_forward_or_changed_parallel_batch_global_slot,
    try_csr_forward_or_changed_parallel_batch_global_slot,
};
pub use launch_plan::CsrForwardOrChangedLaunchPlan;
pub use plan::plan_csr_forward_or_changed_launch;
pub use layout::{CsrForwardOrChangedProgramKey, CsrForwardOrChangedStaticInputKey};
pub use program_dispatch::build_csr_forward_or_changed_dispatch_program;
pub use program_serial::csr_forward_or_changed;
pub use validate::{copy_csr_forward_seed_frontier_into, validate_csr_forward_or_changed_flag};

pub(crate) use body::*;
pub(crate) use cpu_ref::*;
pub(crate) use dispatch_plan::*;
pub(crate) use hash::*;
pub(crate) use launch_plan::*;
pub(crate) use layout::*;
pub(crate) use plan::*;
pub(crate) use program_dispatch::*;
pub(crate) use program_parallel::*;
pub(crate) use program_parallel_batch::*;
pub(crate) use program_parallel_batch_global::*;
pub(crate) use program_serial::*;
pub(crate) use validate::*;
