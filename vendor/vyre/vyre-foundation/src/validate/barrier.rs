//! Barrier placement validation.
//!
//! Workgroup barriers in GPU shaders must only appear in uniform control
//! flow: every thread in the workgroup must reach the barrier or none
//! must reach it. This module checks that barrier nodes are not placed
//! inside divergent branches, catching a class of bugs that would
//! otherwise deadlock or produce undefined behavior on the GPU.

use crate::validate::{err, ValidationError};

/// Ensure a barrier is not placed inside divergent control flow.
///
/// A barrier inside an `If` or `Loop` whose condition is not uniform
/// across the workgroup is illegal in vyre. This function appends a
/// validation error when `divergent` is `true`.
///
/// # Examples
///
/// `check_barrier` is `pub(crate)`; it's exercised indirectly through
/// [`crate::validate::validate::validate`] when a program contains a
/// `Node::Barrier` inside a divergent `Node::If`. See the unit tests on
/// [`crate::validate::validate::validate`] for a runnable example.
///
/// # Errors
///
/// Appends a `ValidationError` with code `V010` when `divergent` is
/// `true`.
#[inline]
pub(crate) fn check_barrier(divergent: bool, errors: &mut Vec<ValidationError>) {
    if divergent {
        errors.push(err(
            "V010: barrier may be reached by only part of a workgroup. Fix: move the barrier to uniform control flow."
                .to_string(),
        ));
    }
}
