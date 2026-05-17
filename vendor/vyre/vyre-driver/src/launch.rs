//! Backend-neutral dispatch launch preparation.

use vyre_foundation::ir::Program;

use crate::binding::Binding;
use crate::program_walks::{
    dispatch_element_count_for_program, dispatch_param_words_into, infer_dispatch_grid_for_count,
};
use crate::validation::{validate_launch_geometry, LaunchGeometryLimits};
use crate::{BackendError, DispatchConfig};

/// Fully prepared launch metadata shared by concrete drivers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchPlan {
    /// Logical element count passed to the lowered kernel.
    pub element_count: u32,
    /// Effective workgroup/block shape after dispatch overrides.
    pub workgroup: [u32; 3],
    /// Effective grid shape after dispatch overrides or inference.
    pub grid: [u32; 3],
    /// Per-buffer element-count metadata uploaded as the shared params buffer.
    pub param_words: Vec<u32>,
    /// Maximum preferred alignment across all launch bindings.
    ///
    /// Concrete drivers use this to pick upload staging and device-buffer
    /// allocation paths without re-inspecting Program buffer declarations.
    pub max_binding_alignment: usize,
}

impl LaunchPlan {
    /// Empty launch plan with reusable parameter-word storage.
    #[must_use]
    pub fn new() -> Self {
        Self {
            element_count: 1,
            workgroup: [1, 1, 1],
            grid: [1, 1, 1],
            param_words: Vec::new(),
            max_binding_alignment: 1,
        }
    }

    /// Prepare dispatch geometry and parameter words from a validated binding plan.
    ///
    /// # Errors
    ///
    /// Returns when caller overrides produce zero dimensions, overflow the
    /// logical launch element count, or exceed backend-reported launch limits.
    pub fn from_bindings(
        program: &Program,
        bindings: &[Binding],
        config: &DispatchConfig,
        limits: LaunchGeometryLimits,
    ) -> Result<Self, BackendError> {
        let mut plan = Self::new();
        plan.prepare_into(program, bindings, config, limits)?;
        Ok(plan)
    }

    /// Prepare dispatch geometry and parameter words, reusing this plan's buffers.
    ///
    /// # Errors
    ///
    /// Returns when caller overrides produce zero dimensions, overflow the
    /// logical launch element count, or exceed backend-reported launch limits.
    pub fn prepare_into(
        &mut self,
        program: &Program,
        bindings: &[Binding],
        config: &DispatchConfig,
        limits: LaunchGeometryLimits,
    ) -> Result<(), BackendError> {
        let workgroup = config
            .workgroup_override
            .unwrap_or(program.workgroup_size());
        validate_launch_geometry(workgroup, [1, 1, 1], limits)?;
        let element_count = launch_element_count(program, bindings, workgroup, config, limits)?;
        let grid = match config.grid_override {
            Some(grid) => grid,
            None => {
                // Non-1D workgroups need an explicit grid_override —
                // there's no single right way to map an unknown
                // element_count across N×M (or N×M×K) thread tiles,
                // and silently picking one produces silently-wrong
                // results. Force the caller to make the choice.
                if workgroup[1] != 1 || workgroup[2] != 1 {
                    return Err(BackendError::InvalidProgram {
                        fix: format!(
                            "Fix: backend `{}` requires DispatchConfig::grid_override for non-1D workgroups. \
                             workgroup={:?} has no unambiguous default grid; set grid_override to the logical [x, y, z] you want.",
                            limits.backend, workgroup,
                        ),
                    });
                }
                infer_dispatch_grid_for_count(element_count, workgroup)?
            }
        };
        validate_launch_geometry(workgroup, grid, limits)?;
        self.element_count = element_count;
        self.workgroup = workgroup;
        self.grid = grid;
        self.max_binding_alignment = bindings
            .iter()
            .map(|binding| binding.preferred_alignment)
            .max()
            .unwrap_or(1);
        dispatch_param_words_into(bindings, element_count, &mut self.param_words);
        Ok(())
    }
}

impl Default for LaunchPlan {
    fn default() -> Self {
        Self::new()
    }
}

fn launch_element_count(
    program: &Program,
    bindings: &[Binding],
    workgroup: [u32; 3],
    config: &DispatchConfig,
    limits: LaunchGeometryLimits,
) -> Result<u32, BackendError> {
    let inferred = dispatch_element_count_for_program(program, bindings);
    let Some(grid) = config.grid_override else {
        return Ok(inferred);
    };
    if workgroup.contains(&0) || grid.contains(&0) {
        return Err(BackendError::InvalidProgram {
            fix: format!(
                "Fix: {} grid_override and workgroup dimensions must all be non-zero.",
                limits.backend
            ),
        });
    }
    grid[0]
        .checked_mul(workgroup[0])
        .filter(|count| *count != 0)
        .ok_or_else(|| BackendError::InvalidProgram {
            fix: format!(
                "Fix: {} grid_override.x * workgroup_size.x must fit in u32.",
                limits.backend
            ),
        })
}

/// Compute the shared VSA program fingerprint used by backend caches.
#[must_use]
pub fn program_vsa_fingerprint(program: &Program) -> Vec<u32> {
    program_vsa_fingerprint_words(program).to_vec()
}

/// Compute the shared VSA program fingerprint without heap allocation.
#[must_use]
pub fn program_vsa_fingerprint_words(program: &Program) -> [u32; 8] {
    let fingerprint = program.fingerprint();
    let mut words = [0_u32; 8];
    for (word, chunk) in words.iter_mut().zip(fingerprint.chunks_exact(4)) {
        *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::BindingRole;
    use vyre_foundation::ir::Program;

    #[test]
    fn launch_plan_prepare_into_reuses_param_words() {
        let program = Program::wrapped(vec![], [64, 1, 1], vec![]);
        let bindings = vec![Binding {
            name: std::sync::Arc::from("input"),
            binding: 0,
            buffer_index: 0,
            role: BindingRole::Input,
            element_size: 4,
            preferred_alignment: 64,
            element_count: 7,
            static_byte_len: Some(28),
            input_index: Some(0),
            output_index: None,
        }];
        let limits = LaunchGeometryLimits {
            backend: "test",
            max_threads_per_block: 1024,
            max_block_dim: [1024, 1024, 64],
            max_grid_dim: [u32::MAX, u32::MAX, u32::MAX],
        };
        let mut plan = LaunchPlan {
            param_words: Vec::with_capacity(8),
            ..LaunchPlan::new()
        };
        let ptr = plan.param_words.as_ptr();
        plan.prepare_into(&program, &bindings, &DispatchConfig::default(), limits)
            .unwrap();
        assert_eq!(plan.element_count, 7);
        assert_eq!(plan.grid, [1, 1, 1]);
        assert_eq!(plan.param_words, vec![7, 7]);
        assert_eq!(plan.max_binding_alignment, 64);
        assert_eq!(plan.param_words.as_ptr(), ptr);
    }
}
