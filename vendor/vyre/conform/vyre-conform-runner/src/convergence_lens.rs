//! CPU↔GPU convergence lens for fixpoint ops.
//!
//! Drives a transfer program and a `bitset_fixpoint` program in a loop
//! until the changed flag clears.

use vyre::ir::{BufferAccess, Program};
use vyre::{DispatchConfig, VyreBackend};
use vyre_reference::value::Value;

/// Error from the convergence loop.
#[derive(Debug)]
pub enum ConvergenceError {
    /// Backend or reference dispatch failed.
    Dispatch(String),
    /// Did not converge within the iteration budget.
    DidNotConverge {
        /// Max iterations that were attempted.
        max_iterations: u32,
    },
    /// The program's buffer layout is incompatible with the fixpoint
    /// convergence protocol.
    IncompatibleLayout(String),
}

impl std::fmt::Display for ConvergenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConvergenceError::Dispatch(msg) => write!(f, "dispatch failed: {msg}"),
            ConvergenceError::DidNotConverge { max_iterations } => {
                write!(f, "did not converge in {max_iterations} iterations")
            }
            ConvergenceError::IncompatibleLayout(msg) => {
                write!(f, "incompatible fixpoint layout: {msg}")
            }
        }
    }
}

impl std::error::Error for ConvergenceError {}

/// Run a backend through a fixpoint convergence loop.
///
/// The program is dispatched repeatedly; after each dispatch a
/// `bitset_fixpoint` pass checks whether `current` and `next`
/// differ. If they do, the buffers are swapped and the loop
/// continues. Returns the final RW outputs of `program`.
pub fn run_fixpoint_to_convergence(
    backend: &dyn VyreBackend,
    program: &Program,
    inputs: &[Vec<u8>],
    max_iterations: u32,
) -> Result<Vec<Vec<u8>>, ConvergenceError> {
    let (current_name, next_name, words) = infer_fixpoint_buffers(program)?;
    let changed_name = "fp_changed";
    let bitset_program = vyre_primitives::fixpoint::bitset_fixpoint::bitset_fixpoint(
        current_name,
        next_name,
        changed_name,
        words,
    );

    let mut state: Vec<Vec<u8>> = inputs.to_vec();
    let mut changed_buf = vec![0u8; 4];

    let current_idx = index_of_buffer(program, current_name).ok_or_else(|| {
        ConvergenceError::IncompatibleLayout(format!(
            "buffer `{current_name}` not found in program"
        ))
    })?;
    let next_idx = index_of_buffer(program, next_name).ok_or_else(|| {
        ConvergenceError::IncompatibleLayout(format!("buffer `{next_name}` not found in program"))
    })?;

    for _ in 0..max_iterations {
        let transfer_outputs = backend
            .dispatch(program, &state, &DispatchConfig::default())
            .map_err(|e| ConvergenceError::Dispatch(e.to_string()))?;
        merge_rw(&mut state, &transfer_outputs, program);

        let bitset_inputs = vec![
            state[current_idx].clone(),
            state[next_idx].clone(),
            changed_buf.clone(),
        ];
        let bitset_outputs = backend
            .dispatch(&bitset_program, &bitset_inputs, &DispatchConfig::default())
            .map_err(|e| ConvergenceError::Dispatch(e.to_string()))?;

        changed_buf = bitset_outputs
            .into_iter()
            .next()
            .unwrap_or_else(|| vec![0u8; 4]);
        if flag_word(&changed_buf) == 0 {
            return Ok(extract_rw(program, &state));
        }

        state.swap(current_idx, next_idx);
    }

    Err(ConvergenceError::DidNotConverge { max_iterations })
}

/// CPU-side fixpoint driver using `vyre_reference`.
pub fn run_cpu_fixpoint_to_convergence(
    program: &Program,
    inputs: &[Vec<u8>],
    max_iterations: u32,
) -> Result<Vec<Vec<u8>>, ConvergenceError> {
    let (current_name, next_name, words) = infer_fixpoint_buffers(program)?;
    let changed_name = "fp_changed";
    let bitset_program = vyre_primitives::fixpoint::bitset_fixpoint::bitset_fixpoint(
        current_name,
        next_name,
        changed_name,
        words,
    );

    let mut state: Vec<Vec<u8>> = inputs.to_vec();
    let mut changed_buf = vec![0u8; 4];

    let current_idx = index_of_buffer(program, current_name).ok_or_else(|| {
        ConvergenceError::IncompatibleLayout(format!(
            "buffer `{current_name}` not found in program"
        ))
    })?;
    let next_idx = index_of_buffer(program, next_name).ok_or_else(|| {
        ConvergenceError::IncompatibleLayout(format!("buffer `{next_name}` not found in program"))
    })?;

    for _ in 0..max_iterations {
        let transfer_outputs =
            run_cpu(program, &state).map_err(|e| ConvergenceError::Dispatch(e.to_string()))?;
        merge_rw(&mut state, &transfer_outputs, program);

        let bitset_values: Vec<Value> = vec![
            Value::from(state[current_idx].clone()),
            Value::from(state[next_idx].clone()),
            Value::from(changed_buf.clone()),
        ];
        let bitset_outputs = vyre_reference::reference_eval(&bitset_program, &bitset_values)
            .map_err(|e| ConvergenceError::Dispatch(e.to_string()))?;
        changed_buf = bitset_outputs
            .into_iter()
            .next()
            .map(|v| v.to_bytes())
            .unwrap_or_else(|| vec![0u8; 4]);

        if flag_word(&changed_buf) == 0 {
            return Ok(extract_rw(program, &state));
        }

        state.swap(current_idx, next_idx);
    }

    Err(ConvergenceError::DidNotConverge { max_iterations })
}

fn run_cpu(program: &Program, inputs: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, vyre::Error> {
    let values: Vec<Value> = inputs.iter().cloned().map(Value::from).collect();
    let outputs = vyre_reference::reference_eval(program, &values)?;
    Ok(outputs.into_iter().map(|value| value.to_bytes()).collect())
}

fn infer_fixpoint_buffers(program: &Program) -> Result<(&str, &str, u32), ConvergenceError> {
    let ro_buffers: Vec<_> = program
        .buffers()
        .iter()
        .filter(|d| d.access() == BufferAccess::ReadOnly)
        .collect();
    let rw_buffers: Vec<_> = program
        .buffers()
        .iter()
        .filter(|d| d.access() == BufferAccess::ReadWrite)
        .collect();

    let current = ro_buffers
        .last()
        .ok_or_else(|| {
            ConvergenceError::IncompatibleLayout(
                "no ReadOnly buffer found for fixpoint current".to_string(),
            )
        })?
        .name();
    let next = rw_buffers
        .last()
        .ok_or_else(|| {
            ConvergenceError::IncompatibleLayout(
                "no ReadWrite buffer found for fixpoint next".to_string(),
            )
        })?
        .name();

    let current_count = ro_buffers.last().unwrap().count();
    let next_count = rw_buffers.last().unwrap().count();

    if current_count != next_count {
        return Err(ConvergenceError::IncompatibleLayout(format!(
            "fixpoint buffers `{current}` (count={current_count}) and `{next}` (count={next_count}) must match",
        )));
    }

    Ok((current, next, current_count))
}

fn merge_rw(state: &mut [Vec<u8>], outputs: &[Vec<u8>], program: &Program) {
    let mut out_iter = outputs.iter();
    for (slot, decl) in state.iter_mut().zip(program.buffers().iter()) {
        if decl.access() == BufferAccess::ReadWrite {
            if let Some(next) = out_iter.next() {
                *slot = next.clone();
            }
        }
    }
}

fn extract_rw(program: &Program, state: &[Vec<u8>]) -> Vec<Vec<u8>> {
    program
        .buffers()
        .iter()
        .zip(state.iter())
        .filter_map(|(decl, buf)| {
            if decl.access() == BufferAccess::ReadWrite {
                Some(buf.clone())
            } else {
                None
            }
        })
        .collect()
}

fn flag_word(buffer: &[u8]) -> u32 {
    buffer
        .get(0..4)
        .map(|b| u32::from_le_bytes(b.try_into().expect("4-byte prefix")))
        .unwrap_or(0)
}

fn index_of_buffer(program: &Program, name: &str) -> Option<usize> {
    program
        .buffers()
        .iter()
        .position(|decl| decl.name() == name)
}
