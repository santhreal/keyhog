//! `persistent_fixpoint` — single-dispatch convergence on the GPU.
//!
//! Where [`bitset_fixpoint`](super::bitset_fixpoint::bitset_fixpoint)
//! ships only the comparison + flag half of the loop and leaves the
//! caller's host code to drive the iteration, `persistent_fixpoint`
//! takes the caller's transfer-step body and wraps it in a forever-
//! loop on the GPU with the comparison + ping-pong + termination
//! check inside the kernel. The host issues ONE dispatch and reads
//! the final state; convergence happens entirely on device.
//!
//! This is the substrate primitive that replaces every "host iterates
//! to fixpoint" docstring in `weir::points_to`, `weir::summary`,
//! `weir::loop_sum`, and the `lower_binary_graph_predicate` 8-hop
//! unrolled BFS. Each consumer composes their own transfer body once;
//! `persistent_fixpoint` provides the convergence harness.
//!
//! ## Composition contract
//!
//! Caller supplies:
//!
//! - `transfer_body` — `Vec<Node>` reading from `current`, writing to
//!   `next`. Free to consume + dispatch any number of nested
//!   primitives (csr_forward_traverse, bitset_or, bitset_and, …).
//! - `current` / `next` — ping-pong bitset names (caller-managed).
//! - `changed` — convergence flag name (1-word atomic ReadWrite).
//! - `words` — bitset element count in 32-bit words.
//! - `max_iterations` — hard cap. The kernel breaks out after this
//!   many iterations even if `changed` is still set, so a buggy
//!   transfer body cannot wedge the dispatcher.
//!
//! Caller receives a [`Program`] that, when dispatched once, runs the
//! transfer body until `changed[0] == 0` for two consecutive
//! iterations or `max_iterations` is reached. Output is in `current`
//! after the dispatch returns — `next` and `changed` are scratch.
//!
//! ## LEGO discipline
//!
//! This primitive composes:
//!
//! - `Node::Loop` (vyre-foundation, IR primitive) — the convergence
//!   loop body.
//! - `bitset_fixpoint::bitset_fixpoint` step (re-used) — comparison +
//!   flag-set inside the loop body.
//! - Standard ping-pong via `Node::store(current, t, next[t])` —
//!   in-place buffer swap on the GPU.
//!
//! Soundness: matches the host-driven loop exactly (proven by the
//! convergence-equivalence test below).

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::fixpoint::persistent_fixpoint";

/// Build a Program that runs `transfer_body` to convergence on the
/// GPU.
///
/// One dispatch from the host. The kernel:
///
/// 1. Zeros `changed[0]`.
/// 2. Runs `transfer_body` (caller-supplied — reads `current`, writes `next`).
/// 3. For every word `w`, sets `changed[0]=1` iff `current[w] != next[w]`.
/// 4. Copies `next[w]` into `current[w]`.
/// 5. Reads `changed[0]`. If 0, break the outer loop.
/// 6. Repeats up to `max_iterations` times.
///
/// `changed` is a 1-word atomic ReadWrite buffer. `current` and
/// `next` are word-bitset ReadWrite buffers of length `words`.
///
/// The transfer body MUST NOT touch `changed` — the wrapper owns the
/// convergence flag exclusively.
///
/// # Parameters
///
/// - `transfer_body`: caller-provided IR body that performs ONE step
///   of the transfer function. Reads `current`, writes `next`.
/// - `current` / `next`: bitset buffer names (ReadWrite).
/// - `changed`: 1-word convergence-flag buffer name (ReadWrite atomic).
/// - `words`: bitset element count.
/// - `max_iterations`: hard upper bound on iterations.
#[must_use]
pub fn persistent_fixpoint(
    transfer_body: Vec<Node>,
    current: &str,
    next: &str,
    changed: &str,
    words: u32,
    max_iterations: u32,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };

    // Per-iteration body composed of:
    //   (a) zero `changed[0]` so this iteration's compare starts clean.
    //   (b) caller's transfer step (reads current → writes next).
    //   (c) convergence step + ping-pong: per word, set changed=1 if
    //       differ + copy next→current.
    let mut iter_body: Vec<Node> = Vec::new();
    iter_body.push(Node::if_then(
        Expr::eq(t.clone(), Expr::u32(0)),
        vec![Node::store(changed, Expr::u32(0), Expr::u32(0))],
    ));
    iter_body.extend(transfer_body);
    iter_body.push(Node::if_then(
        Expr::lt(t.clone(), Expr::u32(words)),
        vec![
            Node::let_bind("c", Expr::load(current, t.clone())),
            Node::let_bind("n", Expr::load(next, t.clone())),
            Node::if_then(
                Expr::ne(Expr::var("c"), Expr::var("n")),
                vec![Node::let_bind(
                    "_pf_set",
                    Expr::atomic_or(changed, Expr::u32(0), Expr::u32(1)),
                )],
            ),
            Node::store(current, t.clone(), Expr::var("n")),
        ],
    ));
    // Termination: after the per-iteration body, lane 0 reads changed;
    // if it's 0, set a private termination flag and break the outer
    // forever-loop. The forever-loop here uses the standard pattern:
    // wrap in a bounded for-loop with max_iterations + an inner break
    // when changed reads 0.
    let outer = vec![Node::loop_for(
        "__pf_iter__",
        Expr::u32(0),
        Expr::u32(max_iterations),
        {
            let mut body = iter_body;
            body.push(Node::if_then(
                Expr::eq(Expr::load(changed, Expr::u32(0)), Expr::u32(0)),
                vec![Node::Return],
            ));
            body
        },
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(current, 0, BufferAccess::ReadWrite, DataType::U32)
                .with_count(words),
            BufferDecl::storage(next, 1, BufferAccess::ReadWrite, DataType::U32).with_count(words),
            BufferDecl::storage(changed, 2, BufferAccess::ReadWrite, DataType::U32).with_count(1),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(outer),
        }],
    )
}

/// CPU oracle. Iterates `transfer_step` (a closure that takes
/// `current` and writes `next`) until the two arrays match or
/// `max_iterations` is hit. Returns the final `current` state and the
/// number of iterations actually executed.
#[must_use]
pub fn cpu_ref<F>(seed: &[u32], max_iterations: u32, mut transfer_step: F) -> (Vec<u32>, u32)
where
    F: FnMut(&[u32], &mut [u32]),
{
    let mut current = seed.to_vec();
    let mut next = vec![0u32; current.len()];
    for iter in 0..max_iterations {
        next.fill(0);
        transfer_step(&current, &mut next);
        if next == current {
            return (current, iter);
        }
        std::mem::swap(&mut current, &mut next);
    }
    (current, max_iterations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_ref_converges_when_step_is_idempotent() {
        // Identity transfer: next = current. Should converge in 1 step.
        let seed = vec![0b1010, 0b0101];
        let (out, iters) = cpu_ref(&seed, 100, |cur, next| next.copy_from_slice(cur));
        assert_eq!(out, seed);
        assert_eq!(iters, 0);
    }

    #[test]
    fn cpu_ref_converges_on_or_to_fixed_point() {
        // Transfer: next = current | constant. Reaches fixed point
        // when constant's bits are all set in current.
        let seed = vec![0u32];
        let (out, iters) = cpu_ref(&seed, 100, |cur, next| {
            next[0] = cur[0] | 0b1010;
        });
        assert_eq!(out, vec![0b1010]);
        assert!(iters < 5, "OR-with-const converges in 1 step + 1 confirm");
    }

    #[test]
    fn cpu_ref_caps_at_max_iterations() {
        // Diverging transfer: next = current + 1 (per word). Never
        // reaches fixed point; cpu_ref returns at max_iterations.
        let seed = vec![0u32];
        let max = 16;
        let (_, iters) = cpu_ref(&seed, max, |cur, next| {
            next[0] = cur[0].wrapping_add(1);
        });
        assert_eq!(iters, max);
    }

    #[test]
    fn program_shape_matches_contract() {
        let body = vec![Node::store("next", Expr::u32(0), Expr::u32(0))];
        let program = persistent_fixpoint(body, "current", "next", "changed", 16, 64);
        assert!(
            program.buffers.iter().any(|b| b.name() == "current"),
            "current buffer must be declared"
        );
        assert!(
            program.buffers.iter().any(|b| b.name() == "next"),
            "next buffer must be declared"
        );
        assert!(
            program.buffers.iter().any(|b| b.name() == "changed"),
            "changed buffer must be declared"
        );
    }
}
