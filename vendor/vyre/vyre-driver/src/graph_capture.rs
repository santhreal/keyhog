//! Backend-neutral planning for replayable graph-capture dispatch paths.
//!
//! CUDA graphs, WGPU command replay, and future persistent-dispatch recorders
//! all need the same first step: walk a [`BindingPlan`] once, classify which
//! runtime buffers require stable input storage, which require output readback
//! storage, and how many kernel pointer arguments are needed in lowered binding
//! order. This module owns that logic so backend crates do not fork planner
//! invariants while adding API-specific capture and replay code.

use crate::binding::{BindingPlan, BindingRole};
use crate::transfer_accounting::TransferAccountingPolicy;
use crate::BackendError;

const GRAPH_CAPTURE_BINDING_ACCOUNTING: TransferAccountingPolicy =
    TransferAccountingPolicy::new("graph capture binding plan", "record a smaller graph shape");

/// Capacity and safety plan for recording one replayable dispatch graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphCaptureBindingPlan {
    /// Device/storage entries needed for runtime input buffers. Input-output
    /// bindings are counted here because their input allocation is reused for
    /// output readback.
    pub input_device_capacity: usize,
    /// Device/storage entries needed for non-input runtime buffers. This is
    /// intentionally separate from [`Self::output_readback_capacity`] because
    /// an input-output binding needs output readback metadata but does not need
    /// a second device pointer.
    pub output_device_capacity: usize,
    /// Host/readback entries needed for bindings with an output view.
    pub output_readback_capacity: usize,
    /// Pointer arguments passed to the captured kernel in binding order.
    pub kernel_pointer_capacity: usize,
    /// Kernel pointer arguments plus the trailing launch-parameter pointer.
    pub kernel_argument_capacity: usize,
    /// True when a backend can replay a no-upload steady-state graph after the
    /// device inputs have been initialized once.
    pub resident_input_replay_safe: bool,
}

/// Build a backend-neutral capture plan from a lowered binding plan.
///
/// # Errors
///
/// Returns [`BackendError::InvalidProgram`] if capacity arithmetic would
/// overflow on the host.
pub fn plan_graph_capture_bindings(
    bindings: &BindingPlan,
) -> Result<GraphCaptureBindingPlan, BackendError> {
    let mut input_device_capacity = 0usize;
    let mut output_device_capacity = 0usize;
    let mut output_readback_capacity = 0usize;
    let mut kernel_pointer_capacity = 0usize;
    let mut resident_input_replay_safe = true;

    for binding in &bindings.bindings {
        if binding.role == BindingRole::Shared {
            continue;
        }

        kernel_pointer_capacity =
            graph_capture_capacity_add(kernel_pointer_capacity, 1, "kernel pointer table")?;

        if binding.input_index.is_some() {
            input_device_capacity =
                graph_capture_capacity_add(input_device_capacity, 1, "input device table")?;
        } else {
            output_device_capacity =
                graph_capture_capacity_add(output_device_capacity, 1, "output device table")?;
        }

        if binding.output_index.is_some() {
            output_readback_capacity =
                graph_capture_capacity_add(output_readback_capacity, 1, "output readback table")?;
        }

        if binding.input_index.is_some() && binding.output_index.is_some() {
            resident_input_replay_safe = false;
        }
    }

    let kernel_argument_capacity =
        graph_capture_capacity_add(kernel_pointer_capacity, 1, "kernel argument table")?;

    Ok(GraphCaptureBindingPlan {
        input_device_capacity,
        output_device_capacity,
        output_readback_capacity,
        kernel_pointer_capacity,
        kernel_argument_capacity,
        resident_input_replay_safe,
    })
}

fn graph_capture_capacity_add(lhs: usize, rhs: usize, label: &str) -> Result<usize, BackendError> {
    GRAPH_CAPTURE_BINDING_ACCOUNTING.add_usize_capacity(lhs, rhs, label)
}

#[cfg(test)]
mod tests {
    use super::{graph_capture_capacity_add, plan_graph_capture_bindings, GraphCaptureBindingPlan};
    use crate::binding::{Binding, BindingPlan, BindingRole};
    use std::sync::Arc;

    fn binding(
        name: &'static str,
        slot: u32,
        role: BindingRole,
        input_index: Option<usize>,
        output_index: Option<usize>,
    ) -> Binding {
        Binding {
            name: Arc::from(name),
            binding: slot,
            buffer_index: slot as usize,
            role,
            element_size: 4,
            preferred_alignment: 4,
            element_count: 16,
            static_byte_len: Some(64),
            input_index,
            output_index,
        }
    }

    fn plan(bindings: Vec<Binding>) -> BindingPlan {
        BindingPlan {
            bindings,
            input_indices: vec![],
            output_indices: vec![],
            shared_indices: vec![],
        }
    }

    #[test]
    fn graph_capture_binding_plan_counts_distinct_device_and_readback_tables() {
        let bindings = plan(vec![
            binding("input", 0, BindingRole::Input, Some(0), None),
            binding("shared", 1, BindingRole::Shared, None, None),
            binding("output", 2, BindingRole::Output, None, Some(0)),
            binding("state", 3, BindingRole::InputOutput, Some(1), Some(1)),
        ]);

        assert_eq!(
            plan_graph_capture_bindings(&bindings)
                .expect("Fix: graph capture planning should accept normal bindings"),
            GraphCaptureBindingPlan {
                input_device_capacity: 2,
                output_device_capacity: 1,
                output_readback_capacity: 2,
                kernel_pointer_capacity: 3,
                kernel_argument_capacity: 4,
                resident_input_replay_safe: false,
            }
        );
    }

    #[test]
    fn generated_graph_capture_binding_plan_preserves_order_independent_counts() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for case_index in 0..768usize {
            let binding_count = 1 + (next_u64(&mut state) as usize % 96);
            let mut bindings = Vec::with_capacity(binding_count);
            let mut expected_input_device_capacity = 0usize;
            let mut expected_output_device_capacity = 0usize;
            let mut expected_output_readback_capacity = 0usize;
            let mut expected_kernel_pointer_capacity = 0usize;
            let mut expected_safe = true;
            let mut next_input = 0usize;
            let mut next_output = 0usize;

            for slot in 0..binding_count {
                let role_selector = (next_u64(&mut state) % 4) as u8;
                let (role, input_index, output_index) = match role_selector {
                    0 => {
                        let index = next_input;
                        next_input += 1;
                        (BindingRole::Input, Some(index), None)
                    }
                    1 => {
                        let index = next_output;
                        next_output += 1;
                        (BindingRole::Output, None, Some(index))
                    }
                    2 => {
                        let input = next_input;
                        let output = next_output;
                        next_input += 1;
                        next_output += 1;
                        expected_safe = false;
                        (BindingRole::InputOutput, Some(input), Some(output))
                    }
                    _ => (BindingRole::Shared, None, None),
                };

                if role != BindingRole::Shared {
                    expected_kernel_pointer_capacity += 1;
                    if input_index.is_some() {
                        expected_input_device_capacity += 1;
                    } else {
                        expected_output_device_capacity += 1;
                    }
                    if output_index.is_some() {
                        expected_output_readback_capacity += 1;
                    }
                }

                bindings.push(binding(
                    "generated",
                    slot as u32,
                    role,
                    input_index,
                    output_index,
                ));
            }

            let planned = plan_graph_capture_bindings(&plan(bindings))
                .expect("Fix: generated graph capture plan should fit host capacities");
            assert_eq!(
                planned,
                GraphCaptureBindingPlan {
                    input_device_capacity: expected_input_device_capacity,
                    output_device_capacity: expected_output_device_capacity,
                    output_readback_capacity: expected_output_readback_capacity,
                    kernel_pointer_capacity: expected_kernel_pointer_capacity,
                    kernel_argument_capacity: expected_kernel_pointer_capacity + 1,
                    resident_input_replay_safe: expected_safe,
                },
                "case {case_index}"
            );
        }
    }

    #[test]
    fn graph_capture_capacity_overflow_fails_loudly() {
        let error = graph_capture_capacity_add(usize::MAX, 1, "kernel argument table")
            .expect_err("Fix: graph capture capacity overflow must not wrap");
        let message = error.to_string();
        assert!(message.contains("graph capture binding plan"));
        assert!(message.contains("kernel argument table"));
        assert!(message.contains("record a smaller graph shape"));
    }

    fn next_u64(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state
    }
}
