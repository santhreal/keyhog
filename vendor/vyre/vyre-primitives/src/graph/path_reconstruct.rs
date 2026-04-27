//! `path_reconstruct` — walk a parent-pointer array back from a
//! target node, emitting the materialized path into an output
//! buffer.
//!
//! Given:
//! - `parent`: u32 buffer where `parent[v] == u` means `u → v` is
//!   the chosen predecessor edge (and `parent[root] == root` marks
//!   termination).
//! - `target`: u32 buffer whose slot 0 names the node to walk back
//!   from.
//!
//! Emits `path_out[0..len]` = `[target, parent[target], parent[parent[target]], …, root]`
//! and writes the path length into `path_len[0]`. Bounded by
//! `max_depth` so a corrupt parent array cannot hang the GPU.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::graph::path_reconstruct";

/// Build the IR `Program` for path reconstruction.
#[must_use]
///
/// # Panics
///
/// Panics if `max_depth == 0`. AUDIT_2026-04-24 F-PR-03: a zero-
/// `max_depth` program emits a zero-count `path_out` buffer, which
/// some GPU backends reject at pipeline creation and others silently
/// accept as a 1-slot allocation — either way the caller never gets
/// a meaningful witness back. Fail loud at build time instead.
pub fn path_reconstruct(
    parent: &str,
    target: &str,
    path_out: &str,
    path_len: &str,
    max_depth: u32,
) -> Program {
    assert!(
        max_depth >= 1,
        "Fix: path_reconstruct max_depth must be >= 1 — a zero-depth walk cannot \
         emit a witness, and produces a zero-count BufferDecl that some GPU \
         backends reject at pipeline creation"
    );
    // Single-threaded walk (invocation 0 owns the chain). The work
    // is O(path_length) which is typically small (stack trace length,
    // tiny CFG path), so parallelism is not meaningful here.
    //
    // AUDIT_2026-04-24 F-PR-01: two divergences from cpu_ref fixed
    // here.
    //   (1) Prior code overloaded `len` as both the path-length
    //       counter and the loop-termination signal (setting
    //       `len = max_depth` on root-hit), so the stored
    //       `path_len[0]` reported `max_depth` instead of the true
    //       path length whenever a root was reached before the cap.
    //       Now uses a separate `done` flag; `len` stays truthful.
    //   (2) Prior code left `path_out[len..max_depth]` uninitialized
    //       while cpu_ref explicitly pads that tail with zeros, so
    //       harness byte-compare diverged unless the dispatcher
    //       zeroed the buffer between runs. IR now writes 0 into
    //       the unused tail slots on early termination.
    let body = vec![
        Node::let_bind("current", Expr::load(target, Expr::u32(0))),
        Node::let_bind("len", Expr::u32(0)),
        Node::let_bind("done", Expr::u32(0)),
        Node::loop_for(
            "step",
            Expr::u32(0),
            Expr::u32(max_depth),
            vec![Node::if_then(
                Expr::eq(Expr::var("done"), Expr::u32(0)),
                vec![
                    Node::store(path_out, Expr::var("len"), Expr::var("current")),
                    Node::assign("len", Expr::add(Expr::var("len"), Expr::u32(1))),
                    Node::let_bind(
                        "next",
                        Expr::select(
                            Expr::lt(Expr::var("current"), Expr::buf_len(parent)),
                            Expr::load(parent, Expr::var("current")),
                            Expr::var("current"),
                        ),
                    ),
                    Node::if_then(
                        Expr::eq(Expr::var("next"), Expr::var("current")),
                        vec![Node::assign("done", Expr::u32(1))],
                    ),
                    Node::assign("current", Expr::var("next")),
                ],
            )],
        ),
        // Zero-fill path_out[len..max_depth] so harness byte-compare
        // matches cpu_ref tail-padding convention.
        Node::loop_for(
            "pad",
            Expr::var("len"),
            Expr::u32(max_depth),
            vec![Node::store(path_out, Expr::var("pad"), Expr::u32(0))],
        ),
        Node::store(path_len, Expr::u32(0), Expr::var("len")),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(parent, 0, BufferAccess::ReadOnly, DataType::U32),
            BufferDecl::storage(target, 1, BufferAccess::ReadOnly, DataType::U32).with_count(1),
            BufferDecl::storage(path_out, 2, BufferAccess::ReadWrite, DataType::U32)
                .with_count(max_depth),
            BufferDecl::storage(path_len, 3, BufferAccess::ReadWrite, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(
                Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
                body,
            )]),
        }],
    )
}

/// CPU reference: walks parent pointers up to `max_depth`, writing
/// the materialized path into `scratch` and returning its length.
/// Early-terminates when a node's parent points at itself (root
/// convention).
///
/// # Performance
///
/// Callers doing many reconstructions (e.g. one per node in a deep
/// call graph) should pre-allocate a single `Vec<u32>` with capacity
/// `node_count` and reuse it across calls to avoid an allocation per
/// walk.
#[must_use]
pub fn cpu_ref(parent: &[u32], target: u32, max_depth: u32, scratch: &mut Vec<u32>) -> u32 {
    scratch.clear();
    let mut current = target;
    let mut len = 0u32;
    let cap = max_depth as usize;
    while (len as usize) < cap {
        scratch.push(current);
        len += 1;
        let next = parent.get(current as usize).copied().unwrap_or(current);
        if next == current {
            break;
        }
        current = next;
    }
    while scratch.len() < cap {
        scratch.push(0);
    }
    len
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || path_reconstruct("parent", "target", "path_out", "path_len", 4),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // parent: [0, 0, 1, 2]  (0 is root; 1→0, 2→1, 3→2)
            // target = 3
            // expected path = [3, 2, 1, 0], len = 4
            vec![vec![
                to_bytes(&[0, 0, 1, 2]),
                to_bytes(&[3]),
                to_bytes(&[0, 0, 0, 0]),
                to_bytes(&[0]),
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[3, 2, 1, 0]),
                to_bytes(&[4]),
            ]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_parent_chain_to_root() {
        let mut scratch = Vec::with_capacity(4);
        let len = cpu_ref(&[0, 0, 1, 2], 3, 4, &mut scratch);
        assert_eq!(len, 4);
        assert_eq!(&scratch[0..4], &[3, 2, 1, 0]);
    }

    #[test]
    fn terminates_on_max_depth() {
        // Cycle: 0 → 1 → 0. Without max_depth we'd loop forever.
        // AUDIT_2026-04-24 F-PR-02: also assert path contents so a
        // silent buffer corruption cannot slip past the test.
        let mut scratch = Vec::with_capacity(8);
        let len = cpu_ref(&[1, 0], 0, 8, &mut scratch);
        assert_eq!(len, 8);
        assert_eq!(&scratch[..], &[0, 1, 0, 1, 0, 1, 0, 1]);
    }

    #[test]
    fn tail_is_zero_padded_when_root_reached_before_cap() {
        // AUDIT_2026-04-24 F-PR-01: cpu_ref must zero-fill the tail
        // beyond the materialized path so harness byte-compare with
        // the IR builder stays stable.
        let mut scratch = Vec::with_capacity(8);
        let len = cpu_ref(&[0, 0, 1, 2], 3, 8, &mut scratch);
        assert_eq!(len, 4);
        assert_eq!(&scratch[..4], &[3, 2, 1, 0]);
        assert_eq!(&scratch[4..], &[0, 0, 0, 0]);
    }
}
