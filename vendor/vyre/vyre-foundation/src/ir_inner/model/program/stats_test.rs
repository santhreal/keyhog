use super::{Program, ProgramStats};
use crate::ir::{BufferAccess, BufferDecl, DataType, Expr, Node};

#[test]
fn stats_matches_old_multi_walk_empty() {
    let program = Program::empty();
    let stats = program.stats();
    assert_eq!(
        *stats,
        ProgramStats {
            node_count: 1, // root region
            region_count: 1,
            call_count: 0,
            opaque_count: 0,
            top_level_regions: 1,
            static_storage_bytes: 0,
            capability_bits: 0,
        }
    );
}

#[test]
fn stats_matches_old_multi_walk_single_store() {
    let program = Program::wrapped(
        vec![BufferDecl::storage("out", 0, BufferAccess::ReadWrite, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::store("out", Expr::u32(0), Expr::u32(7)), Node::Return],
    );
    let stats = program.stats();
    assert_eq!(
        *stats,
        ProgramStats {
            node_count: 3, // Region + Store + Return
            region_count: 1,
            call_count: 0,
            opaque_count: 0,
            top_level_regions: 1,
            static_storage_bytes: 4,
            capability_bits: 0,
        }
    );
}

#[test]
fn stats_matches_old_multi_walk_batch() {
    let program = Program::wrapped(
        vec![BufferDecl::storage("out", 0, BufferAccess::ReadWrite, DataType::U32).with_count(4)],
        [1, 1, 1],
        vec![
            Node::store("out", Expr::u32(0), Expr::u32(1)),
            Node::store("out", Expr::u32(1), Expr::u32(2)),
            Node::store("out", Expr::u32(2), Expr::u32(3)),
            Node::Return,
        ],
    );
    let stats = program.stats();
    assert_eq!(
        *stats,
        ProgramStats {
            node_count: 5, // Region + 3 Store + Return
            region_count: 1,
            call_count: 0,
            opaque_count: 0,
            top_level_regions: 1,
            static_storage_bytes: 16,
            capability_bits: 0,
        }
    );
}

#[test]
fn stats_matches_old_multi_walk_region_chain() {
    #[allow(deprecated)]
    let program = Program::new(
        vec![],
        [1, 1, 1],
        vec![
            Node::Region {
                generator: "a".into(),
                source_region: None,
                body: std::sync::Arc::new(vec![]),
            },
            Node::Region {
                generator: "b".into(),
                source_region: None,
                body: std::sync::Arc::new(vec![]),
            },
        ],
    );
    let stats = program.stats();
    assert_eq!(
        *stats,
        ProgramStats {
            node_count: 2, // two top-level regions
            region_count: 2,
            call_count: 0,
            opaque_count: 0,
            top_level_regions: 2,
            static_storage_bytes: 0,
            capability_bits: 0,
        }
    );
}

#[test]
fn stats_matches_old_multi_walk_recursive() {
    let program = Program::wrapped(
        vec![BufferDecl::storage("out", 0, BufferAccess::ReadWrite, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::loop_for(
            "i",
            Expr::u32(0),
            Expr::u32(10),
            vec![Node::let_bind("x", Expr::call("foo", vec![Expr::u32(1)]))],
        )],
    );
    let stats = program.stats();
    assert_eq!(
        *stats,
        ProgramStats {
            node_count: 3, // Region + Loop + Let
            region_count: 1,
            call_count: 1,
            opaque_count: 0,
            top_level_regions: 1,
            static_storage_bytes: 4,
            capability_bits: 0,
        }
    );
}

#[test]
fn stats_cache_hit_returns_same_reference() {
    let program = Program::empty();
    let s1 = program.stats();
    let s2 = program.stats();
    assert!(
        std::ptr::eq(s1, s2),
        "Fix: repeated stats() calls must return cached reference"
    );
}
