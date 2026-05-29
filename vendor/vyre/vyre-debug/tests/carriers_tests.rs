//! Test: carriers tests.
use std::collections::BTreeMap;
use vyre_debug::fixtures::loop_carry_smoke;
use vyre_debug::{carrier_summary, find_uncarriered_assigns};
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

#[test]
fn find_uncarriered_assigns_smoke_program_returns_empty() {
    let p = loop_carry_smoke();
    let desc = vyre_lower::lower(&p).unwrap();
    let uncarriered = find_uncarriered_assigns(&p, &desc);
    assert!(uncarriered.is_empty());
}

#[test]
fn find_uncarriered_assigns_flags_a_loop_with_no_carrier() {
    let p = Program::wrapped(
        vec![BufferDecl::storage("out", 0, BufferAccess::ReadWrite, DataType::U32).with_count(16)],
        [64, 1, 1],
        vec![
            Node::let_bind("x", Expr::u32(0)),
            Node::loop_for(
                "i",
                Expr::u32(0),
                Expr::u32(10),
                vec![Node::assign("x", Expr::add(Expr::var("x"), Expr::u32(1)))],
            ),
        ],
    );
    let mut desc = vyre_lower::lower(&p).unwrap();

    // Manually strip LoopCarrier from the descriptor.
    // `LoopCarrierFinal` was consolidated into `LoopCarrier` upstream;
    // the strip set is now just the two remaining variants.
    fn strip_carriers(body: &mut vyre_lower::KernelBody) {
        body.ops.retain(|op| {
            !matches!(
                op.kind,
                vyre_lower::KernelOpKind::LoopCarrier { .. }
                    | vyre_lower::KernelOpKind::LoopCarrierEnd { .. }
            )
        });
        for child in &mut body.child_bodies {
            strip_carriers(child);
        }
    }
    strip_carriers(&mut desc.body);

    let uncarriered = find_uncarriered_assigns(&p, &desc);
    assert_eq!(uncarriered.len(), 1);
    assert_eq!(uncarriered[0].name, "x");
    assert!(!uncarriered[0].has_carrier_op);
}

#[test]
fn carrier_summary_counts_match_descriptor_walk() {
    let p = vyre_libs::parsing::c::lex::lexer::c11_lexer("hs", "tt", "ts", "tl", "tc", 4);
    let desc = vyre_lower::lower(&p).unwrap();
    let summary = carrier_summary(&desc);

    let mut reads = BTreeMap::new();
    let mut writes = BTreeMap::new();
    // `LoopCarrierFinal` was consolidated into `LoopCarrier` upstream
    //  -  the descriptor walk no longer has a "final" variant to count.
    // `summary.carrier_finals` is preserved as a serde-stable empty
    // map for backward-compat with any consumer that read the field.
    let finals: BTreeMap<String, usize> = BTreeMap::new();
    fn walk_body(
        body: &vyre_lower::KernelBody,
        r: &mut BTreeMap<String, usize>,
        w: &mut BTreeMap<String, usize>,
    ) {
        for op in &body.ops {
            if let vyre_lower::KernelOpKind::LoopCarrier { name, .. } = &op.kind {
                *r.entry(name.to_string()).or_insert(0) += 1;
            }
            if let vyre_lower::KernelOpKind::LoopCarrierEnd { name, .. } = &op.kind {
                *w.entry(name.to_string()).or_insert(0) += 1;
            }
        }
        for child in &body.child_bodies {
            walk_body(child, r, w);
        }
    }
    walk_body(&desc.body, &mut reads, &mut writes);
    assert_eq!(summary.carrier_reads, reads);
    assert_eq!(summary.carrier_writes, writes);
    assert_eq!(summary.carrier_finals, finals);
}

#[test]
fn carrier_summary_includes_function_locals() {
    let p = vyre_libs::parsing::c::lex::lexer::c11_lexer("hs", "tt", "ts", "tl", "tc", 4);
    let desc = vyre_lower::lower(&p).unwrap();
    let summary = carrier_summary(&desc);
    assert!(
        summary
            .function_locals
            .contains(&"vyre_named_carry_tok_idx".to_string())
            || summary.function_locals.contains(&"tok_idx".to_string())
            || summary
                .function_locals
                .contains(&"tok_idx_carry".to_string()),
        "Could not find expected local, got: {:?}",
        summary.function_locals
    );
}
