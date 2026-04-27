//! Region-inline pass.
//!
//! `Node::Region { body, .. }` is a debug-wrapper produced by
//! `vyre-libs` Category-A compositions. The generator/source_region
//! fields are informational; the body IR is no different from the
//! surrounding program. This pass flattens each Region into its body
//! when doing so does not cross a threshold (default: 64 nodes),
//! letting the CSE/DCE passes see compositions as one program instead
//! of a tree of black boxes.
//!
//! Keeping the threshold prevents 100-op compositions from inlining
//! and hiding the Region boundary in backtraces.

use crate::ir_inner::model::node::Node;
use crate::ir_inner::model::program::Program;
use rustc_hash::FxHashMap;
use std::cell::RefCell;

/// Default node-count threshold. Regions whose bodies count ≤ this many
/// nodes inline; larger Regions stay wrapped so tracing spans and
/// conform certificates remain meaningful. A caller can override via
/// [`run_with_threshold`].
pub const DEFAULT_INLINE_THRESHOLD: usize = 64;

thread_local! {
    /// Thread-local scratch pool for [`Vec<Node>`] buffers used during
    /// inlining. Each entry is an empty vec that retains its capacity
    /// so repeated region-inline calls reuse heap storage instead of
    /// allocating per inlined region.
    static SCRATCH_POOL: RefCell<Vec<Vec<Node>>> = const { RefCell::new(Vec::new()) };
}

/// Grab a cleared vec with at least `min_capacity` from the scratch
/// pool, or allocate a fresh one if nothing in the pool is large
/// enough.
fn take_scratch(min_capacity: usize) -> Vec<Node> {
    SCRATCH_POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        if let Some(idx) = pool.iter().position(|v| v.capacity() >= min_capacity) {
            let mut v = pool.swap_remove(idx);
            v.clear();
            v
        } else {
            Vec::with_capacity(min_capacity)
        }
    })
}

/// Return an empty vec to the scratch pool so its capacity can be
/// reused by a later inline pass.
fn return_scratch(mut v: Vec<Node>) {
    v.clear();
    SCRATCH_POOL.with(|pool| {
        if let Ok(mut pool) = pool.try_borrow_mut() {
            pool.push(v);
        }
    });
}

/// Run the pass with the default threshold.
#[must_use]
#[inline]
pub fn run(program: Program) -> Program {
    run_with_threshold(program, DEFAULT_INLINE_THRESHOLD)
}

/// Run the pass with an explicit inline threshold.
#[must_use]
pub fn run_with_threshold(program: Program, threshold: usize) -> Program {
    let mut region_counts = FxHashMap::default();
    let mut entry = Vec::with_capacity(program.entry().len());
    inline_nodes_into(
        program.entry().to_vec(),
        threshold,
        &mut region_counts,
        &mut entry,
    );
    program.with_rewritten_entry(entry)
}

/// Recursively inline regions, writing the transformed nodes into `out`.
///
/// Inlined regions append directly into `out`, avoiding an
/// intermediate allocation.  Non-inlined constructs (kept Regions,
/// Blocks, Loops, Ifs) borrow a temporary buffer from the thread-local
/// scratch pool, pre-sized with [`Vec::with_capacity`] based on the
/// respective body length.
fn inline_nodes_into(
    nodes: Vec<Node>,
    threshold: usize,
    region_counts: &mut FxHashMap<usize, usize>,
    out: &mut Vec<Node>,
) {
    for node in nodes {
        match node {
            Node::Region {
                body,
                generator,
                source_region,
            } => {
                let count = count_nodes(&body, region_counts);
                // VYRE_IR_HOTSPOTS CRIT: `(*body).clone()` cloned the
                // whole inner Vec<Node> unconditionally. try_unwrap
                // first so a uniquely-owned Arc yields the inner Vec
                // without copying; fall back to clone only when
                // another owner still holds the Arc.
                let body_vec = match std::sync::Arc::try_unwrap(body) {
                    Ok(v) => v,
                    Err(arc) => (*arc).clone(),
                };
                if count <= threshold {
                    // Flatten directly into `out` — no intermediate vec.
                    inline_nodes_into(body_vec, threshold, region_counts, out);
                } else {
                    let mut new_body = take_scratch(body_vec.len());
                    inline_nodes_into(body_vec, threshold, region_counts, &mut new_body);
                    out.push(Node::Region {
                        generator,
                        source_region,
                        body: std::sync::Arc::new(std::mem::take(&mut new_body)),
                    });
                    return_scratch(new_body);
                }
            }
            Node::Block(children) => {
                let mut new_children = take_scratch(children.len());
                inline_nodes_into(children, threshold, region_counts, &mut new_children);
                out.push(Node::Block(std::mem::take(&mut new_children)));
                return_scratch(new_children);
            }
            Node::Loop {
                var,
                from,
                to,
                body,
            } => {
                let mut new_body = take_scratch(body.len());
                inline_nodes_into(body, threshold, region_counts, &mut new_body);
                out.push(Node::Loop {
                    var,
                    from,
                    to,
                    body: std::mem::take(&mut new_body),
                });
                return_scratch(new_body);
            }
            Node::If {
                cond,
                then,
                otherwise,
            } => {
                let mut new_then = take_scratch(then.len());
                let mut new_otherwise = take_scratch(otherwise.len());
                inline_nodes_into(then, threshold, region_counts, &mut new_then);
                inline_nodes_into(otherwise, threshold, region_counts, &mut new_otherwise);
                out.push(Node::If {
                    cond,
                    then: std::mem::take(&mut new_then),
                    otherwise: std::mem::take(&mut new_otherwise),
                });
                return_scratch(new_then);
                return_scratch(new_otherwise);
            }
            other => out.push(other),
        }
    }
}

fn count_nodes(nodes: &[Node], region_counts: &mut FxHashMap<usize, usize>) -> usize {
    nodes
        .iter()
        .map(|n| match n {
            Node::Block(children) => 1 + count_nodes(children, region_counts),
            Node::Loop { body, .. } => 1 + count_nodes(body, region_counts),
            Node::If {
                then, otherwise, ..
            } => 1 + count_nodes(then, region_counts) + count_nodes(otherwise, region_counts),
            Node::Region { body, .. } => {
                let key = std::sync::Arc::as_ptr(body) as usize;
                if let Some(count) = region_counts.get(&key) {
                    1 + *count
                } else {
                    let count = count_nodes(body, region_counts);
                    region_counts.insert(key, count);
                    1 + count
                }
            }
            _ => 1,
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BufferDecl, DataType, Expr, Program};

    #[test]
    fn small_region_inlines() {
        let body = vec![Node::store("out", Expr::u32(0), Expr::u32(42))];
        let region = Node::Region {
            generator: "test".into(),
            source_region: None,
            body: std::sync::Arc::new(body),
        };
        let prog = Program::wrapped(
            vec![BufferDecl::read_write("out", 0, DataType::U32)],
            [1, 1, 1],
            vec![region],
        );
        let optimized = run(prog);
        assert!(
            !matches!(&optimized.entry()[0], Node::Region { .. }),
            "small Region must inline"
        );
        assert!(matches!(&optimized.entry()[0], Node::Store { .. }));
    }

    #[test]
    fn large_region_stays_wrapped() {
        let body: Vec<Node> = (0..100)
            .map(|i| Node::store("out", Expr::u32(i), Expr::u32(i)))
            .collect();
        let region = Node::Region {
            generator: "test".into(),
            source_region: None,
            body: std::sync::Arc::new(body),
        };
        let prog = Program::wrapped(
            vec![BufferDecl::read_write("out", 0, DataType::U32)],
            [1, 1, 1],
            vec![region],
        );
        let optimized = run_with_threshold(prog, 64);
        assert!(
            matches!(&optimized.entry()[0], Node::Region { .. }),
            "large Region must stay wrapped"
        );
    }

    #[test]
    fn nested_small_regions_all_inline() {
        let inner = Node::Region {
            generator: "inner".into(),
            source_region: None,
            body: std::sync::Arc::new(vec![Node::store("out", Expr::u32(0), Expr::u32(1))]),
        };
        let outer = Node::Region {
            generator: "outer".into(),
            source_region: None,
            body: std::sync::Arc::new(vec![inner]),
        };
        let prog = Program::wrapped(
            vec![BufferDecl::read_write("out", 0, DataType::U32)],
            [1, 1, 1],
            vec![outer],
        );
        let optimized = run(prog);
        // Both Regions inlined — only the Store remains.
        assert_eq!(optimized.entry().len(), 1);
        assert!(matches!(&optimized.entry()[0], Node::Store { .. }));
    }

    #[test]
    fn regions_inside_loops_also_inline() {
        let region = Node::Region {
            generator: "inner".into(),
            source_region: None,
            body: std::sync::Arc::new(vec![Node::store("out", Expr::var("i"), Expr::u32(1))]),
        };
        let loop_node = Node::loop_for("i", Expr::u32(0), Expr::u32(4), vec![region]);
        let prog = Program::wrapped(
            vec![BufferDecl::read_write("out", 0, DataType::U32)],
            [1, 1, 1],
            vec![loop_node],
        );
        let optimized = run(prog);
        let Node::Loop { body, .. } = &optimized.entry()[0] else {
            panic!("expected Loop");
        };
        assert_eq!(body.len(), 1);
        assert!(
            matches!(&body[0], Node::Store { .. }),
            "Region inside Loop must inline to just the Store"
        );
    }
}
