//! Reusable conform lenses: ways of comparing backend output to a truth
//! oracle, one primitive per semantic.
//!
//! Every parity test in the workspace ultimately does one of:
//! - *witness* — run on the CPU reference, assert equality to
//!   `expected_output`.
//! - *cpu_vs_backend* — run on both, assert byte-identity (or ULP
//!   tolerance) between them.
//! - *fixpoint* — dispatch the backend in a loop until a convergence
//!   flag clears, then compare the final state to the CPU reference.
//!
//! Before this module those loops lived duplicated across seven test
//! files with slightly different skip lists. Now each test picks a
//! lens, passes an op iterator, and the shared code does the rest.

use vyre::ir::Program;
use vyre::{BackendError, DispatchConfig, VyreBackend};
use vyre_foundation::program_caps;
use vyre_libs::harness::{FixpointContract, OpEntry, fixpoint_contract};
use vyre_reference::value::Value;

/// Outcome of running one lens against one op.
#[derive(Debug)]
pub enum LensOutcome {
    /// Lens passed — op output matched the oracle for every case.
    Pass {
        /// Number of input cases that were compared.
        cases: usize,
    },
    /// Lens skipped — op has no coverage under this lens.
    Skip {
        /// Human-readable reason.
        reason: String,
    },
    /// Lens failed — op diverged from the oracle on the referenced case.
    Fail {
        /// Zero-based case index of the first divergence.
        case_index: usize,
        /// Rendered failure detail.
        detail: String,
    },
}

impl LensOutcome {
    /// True when the lens finished without a divergence (pass or skip).
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, LensOutcome::Pass { .. } | LensOutcome::Skip { .. })
    }
}

fn run_cpu(program: &Program, inputs: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, vyre::Error> {
    let values: Vec<Value> = inputs.iter().cloned().map(Value::from).collect();
    let outputs = vyre_reference::reference_eval(program, &values)?;
    Ok(outputs.into_iter().map(|value| value.to_bytes()).collect())
}

/// CPU-only witness lens.
///
/// Executes the op's `test_inputs` through `vyre_reference::reference_eval` and
/// compares the result byte-for-byte against its declared
/// `expected_output`. The oracle lives next to the op; the lens just
/// runs it.
pub fn witness(entry: &OpEntry) -> LensOutcome {
    let Some(test_inputs) = entry.test_inputs else {
        return LensOutcome::Skip {
            reason: "no test_inputs — witness lens has nothing to run.".to_string(),
        };
    };
    let Some(expected_fn) = entry.expected_output else {
        return LensOutcome::Skip {
            reason: "no expected_output — witness lens has no oracle.".to_string(),
        };
    };

    let program = (entry.build)();
    let cases = test_inputs();
    let expected = expected_fn();
    if cases.len() != expected.len() {
        return LensOutcome::Fail {
            case_index: 0,
            detail: format!(
                "witness vector count mismatch: {} test_inputs vs {} expected_output sets.",
                cases.len(),
                expected.len()
            ),
        };
    }

    for (index, (inputs, expected_buffers)) in cases.iter().zip(expected.iter()).enumerate() {
        match run_cpu(&program, inputs) {
            Ok(outputs) => {
                if outputs != *expected_buffers {
                    return LensOutcome::Fail {
                        case_index: index,
                        detail: format!(
                            "CPU reference output diverged from declared expected_output.\nACTUAL:\n{:?}\nEXPECTED:\n{:?}\nFix: regenerate the witness via `cargo xtask trace-f32 {}` or \
                             repair the reference.",
                            outputs, expected_buffers, entry.id
                        ),
                    };
                }
            }
            Err(error) => {
                return LensOutcome::Fail {
                    case_index: index,
                    detail: format!("CPU reference failed: {error}"),
                };
            }
        }
    }

    LensOutcome::Pass { cases: cases.len() }
}

/// CPU-vs-backend byte-identity lens.
///
/// Dispatches the op on both the CPU reference and the supplied
/// backend, and asserts byte-identity (modulo the op's declared ULP
/// tolerance). Skips when the backend reports missing capabilities for
/// the program or when the op is registered with a
/// `UniversalDiffExemption`. Fixpoint ops are routed to [`fixpoint`]
/// instead.
pub fn cpu_vs_backend(entry: &OpEntry, backend: &dyn VyreBackend) -> LensOutcome {
    if let Some(reason) = vyre_libs::harness::universal_diff_exemption(entry.id) {
        return LensOutcome::Skip {
            reason: format!("exempt: {reason}"),
        };
    }
    if fixpoint_contract(entry.id).is_some() {
        return LensOutcome::Skip {
            reason: "fixpoint op — dispatch once is not the truth oracle; use `fixpoint` lens."
                .to_string(),
        };
    }
    let Some(test_inputs) = entry.test_inputs else {
        return LensOutcome::Skip {
            reason: "no test_inputs — byte-identity lens has nothing to run.".to_string(),
        };
    };

    let program = (entry.build)();
    let required = program_caps::scan(&program);
    if let Err(missing) = program_caps::check_backend_capabilities(
        backend.id(),
        backend.supports_subgroup_ops(),
        backend.supports_f16(),
        backend.supports_bf16(),
        backend.supports_indirect_dispatch(),
        true,
        backend.max_workgroup_size(),
        &required,
    ) {
        return LensOutcome::Skip {
            reason: missing.to_string(),
        };
    }

    let cases = test_inputs();
    for (index, inputs) in cases.iter().enumerate() {
        let cpu = match run_cpu(&program, inputs) {
            Ok(outputs) => outputs,
            Err(error) => {
                return LensOutcome::Fail {
                    case_index: index,
                    detail: format!("CPU reference failed: {error}"),
                };
            }
        };
        let gpu = match backend.dispatch(&program, inputs, &DispatchConfig::default()) {
            Ok(outputs) => outputs,
            Err(error) => {
                return LensOutcome::Fail {
                    case_index: index,
                    detail: format!("backend `{}` dispatch failed: {error}", backend.id()),
                };
            }
        };
        if cpu != gpu {
            return LensOutcome::Fail {
                case_index: index,
                detail: format!(
                    "backend `{}` diverged from CPU reference on case {index}.",
                    backend.id()
                ),
            };
        }
    }

    LensOutcome::Pass { cases: cases.len() }
}

/// Fixpoint lens: dispatch the op repeatedly until its convergence flag
/// clears, then compare the final state to the CPU reference.
///
/// The contract comes from [`fixpoint_contract`] (`converged_flag_buffer`,
/// `max_iterations`). Each dispatch: zero the flag, run the program,
/// read the flag's first word; if zero, the op has converged. The CPU
/// reference is expected to reach the same final state after iterating
/// under the same loop.
pub fn fixpoint(entry: &OpEntry, backend: &dyn VyreBackend) -> LensOutcome {
    let Some(contract) = fixpoint_contract(entry.id) else {
        return LensOutcome::Skip {
            reason: "no FixpointContract registered for this op.".to_string(),
        };
    };
    let Some(test_inputs) = entry.test_inputs else {
        return LensOutcome::Skip {
            reason: "no test_inputs — fixpoint lens has nothing to run.".to_string(),
        };
    };

    let program = (entry.build)();
    let required = program_caps::scan(&program);
    if let Err(missing) = program_caps::check_backend_capabilities(
        backend.id(),
        backend.supports_subgroup_ops(),
        backend.supports_f16(),
        backend.supports_bf16(),
        backend.supports_indirect_dispatch(),
        true,
        backend.max_workgroup_size(),
        &required,
    ) {
        return LensOutcome::Skip {
            reason: missing.to_string(),
        };
    }

    let Some(flag_index) = index_of_buffer(&program, contract.converged_flag_buffer) else {
        return LensOutcome::Fail {
            case_index: 0,
            detail: format!(
                "program does not declare buffer `{}` named by FixpointContract.",
                contract.converged_flag_buffer
            ),
        };
    };

    let cases = test_inputs();
    for (index, inputs) in cases.iter().enumerate() {
        let cpu_final = match cpu_fixpoint(&program, inputs, flag_index, contract) {
            Ok(outputs) => outputs,
            Err(LoopError::Reference(error)) => {
                return LensOutcome::Fail {
                    case_index: index,
                    detail: format!("CPU reference failed inside fixpoint loop: {error}"),
                };
            }
            Err(LoopError::DidNotConverge) => {
                return LensOutcome::Fail {
                    case_index: index,
                    detail: format!(
                        "CPU reference did not converge in {} iterations. \
                         Fix: raise the FixpointContract max_iterations or shrink the fixture.",
                        contract.max_iterations
                    ),
                };
            }
            Err(LoopError::Backend(error)) => {
                return LensOutcome::Fail {
                    case_index: index,
                    detail: format!("backend failed inside fixpoint loop: {error}"),
                };
            }
        };
        let gpu_final = match gpu_fixpoint(backend, &program, inputs, flag_index, contract) {
            Ok(outputs) => outputs,
            Err(LoopError::Reference(error)) => {
                return LensOutcome::Fail {
                    case_index: index,
                    detail: format!("CPU reference failed inside fixpoint loop: {error}"),
                };
            }
            Err(LoopError::DidNotConverge) => {
                return LensOutcome::Fail {
                    case_index: index,
                    detail: format!(
                        "backend `{}` did not converge in {} iterations.",
                        backend.id(),
                        contract.max_iterations
                    ),
                };
            }
            Err(LoopError::Backend(error)) => {
                return LensOutcome::Fail {
                    case_index: index,
                    detail: format!(
                        "backend `{}` fixpoint dispatch failed: {error}",
                        backend.id()
                    ),
                };
            }
        };
        if cpu_final != gpu_final {
            return LensOutcome::Fail {
                case_index: index,
                detail: format!(
                    "backend `{}` final state diverged from CPU reference after fixpoint loop.",
                    backend.id()
                ),
            };
        }
    }

    LensOutcome::Pass { cases: cases.len() }
}

#[derive(Debug)]
enum LoopError {
    Reference(vyre::Error),
    Backend(BackendError),
    DidNotConverge,
}

fn cpu_fixpoint(
    program: &Program,
    initial_inputs: &[Vec<u8>],
    flag_index: usize,
    contract: &FixpointContract,
) -> Result<Vec<Vec<u8>>, LoopError> {
    let mut state: Vec<Vec<u8>> = initial_inputs.to_vec();
    for _ in 0..contract.max_iterations {
        // Zero the convergence flag buffer (first u32) before the step.
        if let Some(buffer) = state.get_mut(flag_index) {
            if buffer.len() >= 4 {
                buffer[0..4].copy_from_slice(&0u32.to_le_bytes());
            }
        }
        let outputs = run_cpu(program, &state).map_err(LoopError::Reference)?;
        // `vyre_reference::reference_eval` returns the RW buffers in the same
        // declaration order as the inputs. Merge the RW outputs back
        // into `state` by index.
        merge_rw(&mut state, &outputs, program);
        if flag_word(&state, flag_index) == 0 {
            return Ok(state);
        }
    }
    Err(LoopError::DidNotConverge)
}

fn gpu_fixpoint(
    backend: &dyn VyreBackend,
    program: &Program,
    initial_inputs: &[Vec<u8>],
    flag_index: usize,
    contract: &FixpointContract,
) -> Result<Vec<Vec<u8>>, LoopError> {
    let mut state: Vec<Vec<u8>> = initial_inputs.to_vec();
    for _ in 0..contract.max_iterations {
        if let Some(buffer) = state.get_mut(flag_index) {
            if buffer.len() >= 4 {
                buffer[0..4].copy_from_slice(&0u32.to_le_bytes());
            }
        }
        let outputs = backend
            .dispatch(program, &state, &DispatchConfig::default())
            .map_err(LoopError::Backend)?;
        merge_rw(&mut state, &outputs, program);
        if flag_word(&state, flag_index) == 0 {
            return Ok(state);
        }
    }
    Err(LoopError::DidNotConverge)
}

fn merge_rw(state: &mut [Vec<u8>], outputs: &[Vec<u8>], program: &Program) {
    // `vyre_reference::reference_eval` (and `backend.dispatch`) return only the
    // ReadWrite buffers in declaration order. Walk the declarations in
    // the same order and splice each RW output back into the
    // corresponding slot in `state`.
    let mut out_iter = outputs.iter();
    for (slot, decl) in state.iter_mut().zip(program.buffers.iter()) {
        if matches!(decl.access(), vyre::ir::BufferAccess::ReadWrite) {
            if let Some(next) = out_iter.next() {
                *slot = next.clone();
            }
        }
    }
}

fn flag_word(state: &[Vec<u8>], flag_index: usize) -> u32 {
    state
        .get(flag_index)
        .filter(|buffer| buffer.len() >= 4)
        .map(|buffer| u32::from_le_bytes(buffer[0..4].try_into().expect("4-byte prefix")))
        .unwrap_or(0)
}

fn index_of_buffer(program: &Program, name: &str) -> Option<usize> {
    program.buffers.iter().position(|decl| decl.name() == name)
}
