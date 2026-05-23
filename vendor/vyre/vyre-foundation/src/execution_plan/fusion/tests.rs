use super::fuse::{fuse_programs, fuse_programs_vec};
use super::FusionError;
use crate::ir::{BufferAccess, BufferDecl, DataType, Node, Program};

#[test]
fn empty_batch_yields_empty_program() {
    let fused = fuse_programs(&[]).unwrap();
    assert!(fused.is_explicit_noop());
}

#[test]
fn single_program_passthrough() {
    let p = Program::wrapped(
        vec![BufferDecl::read("x", 0, DataType::U32)],
        [64, 1, 1],
        vec![Node::let_bind(
            "a",
            crate::ir::Expr::load("x", crate::ir::Expr::u32(0)),
        )],
    );
    let fused = fuse_programs(&[p.clone()]).unwrap();
    assert_eq!(fused.entry().len(), p.entry().len());
}

#[test]
fn single_program_vec_moves_without_clone() {
    let p = Program::wrapped(
        vec![BufferDecl::read("x", 0, DataType::U32)],
        [64, 1, 1],
        vec![Node::let_bind(
            "a",
            crate::ir::Expr::load("x", crate::ir::Expr::u32(0)),
        )],
    );
    let entry_len = p.entry().len();
    let fused = fuse_programs_vec(vec![p]).unwrap();
    assert_eq!(fused.entry().len(), entry_len);
}

#[test]
fn barrier_inserted_for_read_then_atomic() {
    let reader = Program::wrapped(
        vec![BufferDecl::read("state", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::let_bind(
            "snap",
            crate::ir::Expr::load("state", crate::ir::Expr::u32(0)),
        )],
    );
    let writer = Program::wrapped(
        vec![BufferDecl::read_write("state", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::let_bind(
            "old",
            crate::ir::Expr::atomic_add("state", crate::ir::Expr::u32(0), crate::ir::Expr::u32(1)),
        )],
    );

    let fused = fuse_programs(&[reader, writer]).unwrap();

    // The combined entry should have a Barrier between the two arms.
    // Because the top-level entry contains non-Region nodes (Barrier),
    // Program::wrapped inserts a root Region.  We need to look inside it.
    let body = match fused.entry() {
        [Node::Region { body, .. }] => body.as_ref(),
        entry => panic!("Fix: fused entry must be wrapped in a root Region, got {entry:?}"),
    };
    let barrier_positions: Vec<usize> = body
        .iter()
        .enumerate()
        .filter(|(_, n)| matches!(n, Node::Barrier { .. }))
        .map(|(i, _)| i)
        .collect();
    assert!(
        !barrier_positions.is_empty(),
        "Fix: fusion must insert Node::Barrier between a read arm and an atomic-write arm"
    );
}

#[test]
fn divergent_invocation_gated_writer_upgrades_barrier_to_grid_sync() {
    let writer = Program::wrapped(
        vec![BufferDecl::read_write("state", 0, DataType::U32).with_count(1)],
        [128, 1, 1],
        vec![Node::if_then(
            crate::ir::Expr::eq(crate::ir::Expr::gid_x(), crate::ir::Expr::u32(0)),
            vec![Node::store(
                "state",
                crate::ir::Expr::u32(0),
                crate::ir::Expr::u32(7),
            )],
        )],
    );
    let reader = Program::wrapped(
        vec![BufferDecl::read("state", 0, DataType::U32).with_count(1)],
        [128, 1, 1],
        vec![Node::let_bind(
            "snap",
            crate::ir::Expr::load("state", crate::ir::Expr::u32(0)),
        )],
    );

    let fused = fuse_programs(&[writer, reader]).unwrap();
    let body = match fused.entry() {
        [Node::Region { body, .. }] => body.as_ref(),
        entry => panic!("Fix: fused entry must be wrapped in a root Region, got {entry:?}"),
    };
    let has_grid_sync = body.iter().any(|node| {
        matches!(
            node,
            Node::Barrier {
                ordering: crate::memory_model::MemoryOrdering::GridSync,
                ..
            }
        )
    });
    assert!(
        has_grid_sync,
        "Fix: invocation-gated cross-arm writes must use GridSync, not a workgroup-only barrier"
    );
}

#[test]
fn uniform_cross_arm_writer_uses_workgroup_barrier() {
    let writer = Program::wrapped(
        vec![BufferDecl::read_write("state", 0, DataType::U32).with_count(1)],
        [128, 1, 1],
        vec![Node::store(
            "state",
            crate::ir::Expr::u32(0),
            crate::ir::Expr::u32(7),
        )],
    );
    let reader = Program::wrapped(
        vec![BufferDecl::read("state", 0, DataType::U32).with_count(1)],
        [128, 1, 1],
        vec![Node::let_bind(
            "snap",
            crate::ir::Expr::load("state", crate::ir::Expr::u32(0)),
        )],
    );

    let fused = fuse_programs(&[writer, reader]).unwrap();
    let body = match fused.entry() {
        [Node::Region { body, .. }] => body.as_ref(),
        entry => panic!("Fix: fused entry must be wrapped in a root Region, got {entry:?}"),
    };
    let has_workgroup_barrier = body.iter().any(|node| {
        matches!(
            node,
            Node::Barrier {
                ordering: crate::memory_model::MemoryOrdering::SeqCst,
                ..
            }
        )
    });
    let has_grid_sync = body.iter().any(|node| {
        matches!(
            node,
            Node::Barrier {
                ordering: crate::memory_model::MemoryOrdering::GridSync,
                ..
            }
        )
    });

    assert!(
        has_workgroup_barrier,
        "Fix: uniform cross-arm writes must still get a workgroup memory barrier"
    );
    assert!(
        !has_grid_sync,
        "Fix: fusion must not force a global kernel split for uniform cross-arm writes"
    );
}

#[test]
fn self_composing_parser_rejected() {
    let parser = Program::wrapped(
        vec![BufferDecl::read("in", 0, DataType::U32)],
        [1, 1, 1],
        vec![Node::Return],
    )
    .with_entry_op_id("vyre-libs::parsing::test_parser")
    .with_non_composable_with_self(true);

    let result = fuse_programs(&[parser.clone(), parser]);
    assert!(
        matches!(result, Err(FusionError::SelfAliasing(_))),
        "Fix: fusing two copies of a non-composable parser must fail"
    );
}

#[test]
fn duplicate_buffer_dedup_upgrades_access() {
    let a = Program::wrapped(
        vec![BufferDecl::read("x", 0, DataType::U32)],
        [1, 1, 1],
        vec![Node::Return],
    );
    let b = Program::wrapped(
        vec![BufferDecl::read_write("x", 0, DataType::U32)],
        [1, 1, 1],
        vec![Node::Return],
    );

    let fused = fuse_programs(&[a, b]).unwrap();
    assert_eq!(fused.buffers().len(), 1);
    assert_eq!(fused.buffers()[0].access(), BufferAccess::ReadWrite);
}

#[test]
fn multi_arm_regions_flatten_into_one_executable_body() {
    let a = Program::wrapped(
        vec![BufferDecl::output("a_out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::store(
            "a_out",
            crate::ir::Expr::u32(0),
            crate::ir::Expr::u32(1),
        )],
    );
    let b = Program::wrapped(
        vec![BufferDecl::output("b_out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::store(
            "b_out",
            crate::ir::Expr::u32(0),
            crate::ir::Expr::u32(2),
        )],
    );

    let fused = fuse_programs(&[a, b]).unwrap();
    let body = match fused.entry() {
        [Node::Region { body, .. }] => body.as_ref(),
        entry => panic!("Fix: fused multi-arm programs must have one root Region, got {entry:?}"),
    };
    let stores = body.iter().map(count_stores).sum::<usize>();
    assert_eq!(
        stores, 2,
        "Fix: fusion must flatten top-level arm Regions into executable arm blocks"
    );
}

fn count_stores(node: &Node) -> usize {
    match node {
        Node::Store { .. } => 1,
        Node::Block(nodes) => nodes.iter().map(count_stores).sum(),
        Node::Region { body, .. } => body.iter().map(count_stores).sum(),
        Node::If {
            then, otherwise, ..
        } => then.iter().chain(otherwise.iter()).map(count_stores).sum(),
        Node::Loop { body, .. } => body.iter().map(count_stores).sum(),
        _ => 0,
    }
}
