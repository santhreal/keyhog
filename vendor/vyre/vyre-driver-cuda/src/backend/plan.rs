//! CUDA dispatch plan assembly helpers.

use smallvec::SmallVec;
use vyre_driver::binding::BindingPlan;
use vyre_driver::BackendError;
use vyre_driver::LaunchPlan;

use super::staging_reserve::reserve_smallvec;

pub(crate) fn compute_ordered_output_indices(
    bindings: &BindingPlan,
) -> Result<SmallVec<[usize; 8]>, BackendError> {
    let mut ordered = SmallVec::<[(usize, usize); 8]>::new();
    reserve_smallvec(
        &mut ordered,
        bindings.output_indices.len(),
        "CUDA ordered output binding scratch",
    )?;
    for (binding_index, binding) in bindings.bindings.iter().enumerate() {
        if let Some(output_index) = binding.output_index {
            ordered.push((output_index, binding_index));
        }
    }
    ordered.sort_unstable_by_key(|(output_index, _)| *output_index);
    let mut output_indices = SmallVec::<[usize; 8]>::new();
    reserve_smallvec(
        &mut output_indices,
        ordered.len(),
        "CUDA ordered output binding indices",
    )?;
    for (_, binding_index) in ordered {
        output_indices.push(binding_index);
    }
    Ok(output_indices)
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
    /// chains in consumer rule lowerings) actually converge.
    /// Single-launch kernels read `1` as the conventional default. The
    /// wgpu backend honors this same field via its persistent-pipeline
    /// fixpoint loop; the CUDA backend reached parity 2026-05-01.
    pub(crate) fixpoint_iterations: u32,
}

#[cfg(test)]
mod tests {
    #[test]
    fn ordered_output_indices_reserve_fallibly() {
        let source = include_str!("plan.rs");
        assert!(
            source.contains("use super::staging_reserve::reserve_smallvec;"),
            "Fix: CUDA dispatch-plan helpers must use the shared fallible staging reservation contract."
        );
        assert!(
            source.contains("\"CUDA ordered output binding scratch\"")
                && source.contains("\"CUDA ordered output binding indices\""),
            "Fix: CUDA output binding ordering must label both fallible scratch reservations."
        );
        assert!(
            !source.contains(concat!(
                "SmallVec::<[(usize, usize); 8]>::",
                "with_capacity"
            )) && !source.contains(concat!("SmallVec::<[usize; 8]>::", "with_capacity")),
            "Fix: CUDA output binding ordering must not allocate scratch infallibly."
        );
    }
}
