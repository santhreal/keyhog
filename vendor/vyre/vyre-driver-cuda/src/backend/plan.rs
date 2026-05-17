//! CUDA dispatch plan assembly helpers.

use smallvec::SmallVec;
use vyre_driver::binding::BindingPlan;
use vyre_driver::LaunchPlan;

pub(crate) fn compute_ordered_output_indices(bindings: &BindingPlan) -> SmallVec<[usize; 8]> {
    let mut ordered = SmallVec::<[(usize, usize); 8]>::with_capacity(bindings.output_indices.len());
    for (binding_index, binding) in bindings.bindings.iter().enumerate() {
        if let Some(output_index) = binding.output_index {
            ordered.push((output_index, binding_index));
        }
    }
    ordered.sort_unstable_by_key(|(output_index, _)| *output_index);
    ordered
        .into_iter()
        .map(|(_, binding_index)| binding_index)
        .collect()
}

#[derive(Debug, Clone)]
pub(crate) struct CudaDispatchPlan {
    pub(crate) bindings: BindingPlan,
    pub(crate) output_binding_indices: SmallVec<[usize; 8]>,
    pub(crate) launch: LaunchPlan,
    /// Mirrors `DispatchConfig::cooperative`; validated before launch.
    pub(crate) cooperative: bool,
    /// Mirrors `DispatchConfig::fixpoint_iterations`; the host-side
    /// dispatch loop runs the kernel this many times back-to-back on
    /// the same stream so that multi-hop dataflow primitives (the
    /// `flows_to`, `dominates`, `bounded_by_comparison` BFS-on-CSR
    /// chains in surgec rule lowerings) actually converge.
    /// Single-launch kernels read `1` as the conventional default. The
    /// wgpu backend honors this same field via its persistent-pipeline
    /// fixpoint loop; the CUDA backend reached parity 2026-05-01.
    pub(crate) fixpoint_iterations: u32,
}
