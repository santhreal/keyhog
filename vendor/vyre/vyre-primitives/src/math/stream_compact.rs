//! Stream compaction over prefix-scan offsets.
//!
//! The primitive consumes a payload buffer, a 0/1 liveness flag buffer,
//! and an exclusive prefix-scan of those flags. Each live lane writes
//! `payloads[i]` into `compacted[offsets[i]]`; `live_count[0]` receives
//! the final survivor count.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::math::stream_compact";

/// Build a stream-compaction Program.
///
/// `flags` must contain `0` for dead lanes and `1` for live lanes.
/// `offsets` must be the exclusive prefix sum of `flags`.
///
/// # Panics
///
/// Panics if `count == 0`; a zero-lane compaction has no final lane from
/// which to derive `live_count[0]`.
#[must_use]
pub fn stream_compact(
    payloads: &str,
    flags: &str,
    offsets: &str,
    compacted: &str,
    live_count: &str,
    count: u32,
) -> Program {
    assert!(
        count > 0,
        "Fix: stream_compact requires count > 0 so live_count can be derived from the final lane."
    );
    let t = Expr::InvocationId { axis: 0 };

    let body = vec![
        Node::let_bind("flag", Expr::load(flags, t.clone())),
        Node::let_bind("offset", Expr::load(offsets, t.clone())),
        Node::if_then(
            Expr::ne(Expr::var("flag"), Expr::u32(0)),
            vec![Node::store(
                compacted,
                Expr::var("offset"),
                Expr::load(payloads, t.clone()),
            )],
        ),
        Node::if_then(
            Expr::eq(t.clone(), Expr::u32(count - 1)),
            vec![Node::store(
                live_count,
                Expr::u32(0),
                Expr::add(Expr::var("offset"), Expr::var("flag")),
            )],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(payloads, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(count),
            BufferDecl::storage(flags, 1, BufferAccess::ReadOnly, DataType::U32).with_count(count),
            BufferDecl::storage(offsets, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(count),
            BufferDecl::storage(compacted, 3, BufferAccess::ReadWrite, DataType::U32)
                .with_count(count),
            BufferDecl::storage(live_count, 4, BufferAccess::ReadWrite, DataType::U32)
                .with_count(1),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(Expr::lt(t, Expr::u32(count)), body)]),
        }],
    )
}

/// CPU reference for stream compaction.
#[must_use]
pub fn cpu_ref(payloads: &[u32], flags: &[u32]) -> (Vec<u32>, u32) {
    assert_eq!(
        payloads.len(),
        flags.len(),
        "Fix: stream_compact payload and flag lengths must match."
    );
    let live = flags.iter().filter(|&&flag| flag != 0).count();
    let mut compacted = Vec::with_capacity(live);
    for (&payload, &flag) in payloads.iter().zip(flags.iter()) {
        if flag != 0 {
            compacted.push(payload);
        }
    }
    (compacted, live as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_ref_compacts_live_lanes_in_order() {
        let (compacted, live_count) = cpu_ref(&[10, 20, 30, 40, 50], &[0, 1, 1, 0, 1]);
        assert_eq!(compacted, vec![20, 30, 50]);
        assert_eq!(live_count, 3);
    }

    #[test]
    fn program_has_bounded_buffers_and_live_count() {
        let p = stream_compact("payloads", "flags", "offsets", "out", "live", 64);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|buffer| buffer.name()).collect();
        assert_eq!(names, vec!["payloads", "flags", "offsets", "out", "live"]);
        assert_eq!(p.buffers[3].count(), 64);
        assert_eq!(p.buffers[4].count(), 1);
    }

    #[test]
    #[should_panic(expected = "count > 0")]
    fn zero_count_panics() {
        let _ = stream_compact("payloads", "flags", "offsets", "out", "live", 0);
    }
}
