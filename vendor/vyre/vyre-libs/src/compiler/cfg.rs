use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// SIMT Control Flow Graph (CFG) & Goto Resolver.
///
/// Linux-kernel C uses `goto` pervasively for error unwind. This pass
/// walks the flat SSA node array, registers every `label:` site into
/// a lock-free open-addressing hash table (`goto_labels_*`), and
/// resolves every `goto target;` site against that table to a CFG
/// edge written into `out_cfg_blocks`.
///
/// The hash insert / lookup use linear probing on a 4096-slot table
/// with `AtomicCompareExchange` for first-writer-wins registration
/// and a bounded linear scan for lookup. No external primitive
/// dependency — the kernel is self-contained.
///
/// Opcode sentinels (ASCII tag bytes): `0x4C41424C` = "LABL" (label
/// definition), `0x474F544F` = "GOTO" (goto site).
#[must_use]
pub fn c11_build_cfg_and_gotos(
    ssa_nodes: &str,
    out_cfg_blocks: &str,
    goto_labels: &str,
    num_ssa: Expr,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    const TABLE_CAP: u32 = 4096;
    const EMPTY_SLOT: u32 = 0xFFFF_FFFF;

    // Shared-across-branches: a bounded linear-probe body that
    // scans up to `TABLE_CAP` slots starting at `start_slot`.
    let hash_slot = |key: Expr| -> Expr {
        // Fibonacci hash, capped to TABLE_CAP.
        Expr::bitand(
            Expr::mul(key, Expr::u32(2_654_435_769)),
            Expr::u32(TABLE_CAP - 1),
        )
    };

    let loop_body = vec![
        Node::let_bind("opcode", Expr::load(ssa_nodes, t.clone())),
        // 1. Label definition: register `label_hash -> ssa_index` in the
        //    open-addressing hash table. Linear probe with atomic CAS
        //    keyed on EMPTY_SLOT so only the first writer wins.
        Node::if_then(
            Expr::eq(Expr::var("opcode"), Expr::u32(0x4C41424C)),
            vec![
                Node::let_bind(
                    "label_hash",
                    Expr::load(ssa_nodes, Expr::add(t.clone(), Expr::u32(1))),
                ),
                Node::let_bind("slot", hash_slot(Expr::var("label_hash"))),
                Node::let_bind("inserted", Expr::u32(0)),
                Node::loop_for(
                    "probe",
                    Expr::u32(0),
                    Expr::u32(TABLE_CAP),
                    vec![Node::if_then(
                        Expr::eq(Expr::var("inserted"), Expr::u32(0)),
                        vec![
                            Node::let_bind(
                                "prev",
                                Expr::atomic_compare_exchange(
                                    "goto_labels_keys",
                                    Expr::var("slot"),
                                    Expr::u32(EMPTY_SLOT),
                                    Expr::var("label_hash"),
                                ),
                            ),
                            Node::if_then(
                                Expr::eq(Expr::var("prev"), Expr::u32(EMPTY_SLOT)),
                                vec![
                                    Node::store("goto_labels_vals", Expr::var("slot"), t.clone()),
                                    Node::assign("inserted", Expr::u32(1)),
                                ],
                            ),
                            Node::assign(
                                "slot",
                                Expr::bitand(
                                    Expr::add(Expr::var("slot"), Expr::u32(1)),
                                    Expr::u32(TABLE_CAP - 1),
                                ),
                            ),
                        ],
                    )],
                ),
            ],
        ),
        // 2. Goto site: look up `target_hash` in the same table, write
        //    the resolved SSA index (or EMPTY_SLOT on miss) into
        //    `out_cfg_blocks[t]`.
        Node::if_then(
            Expr::eq(Expr::var("opcode"), Expr::u32(0x474F544F)),
            vec![
                Node::let_bind(
                    "target_hash",
                    Expr::load(ssa_nodes, Expr::add(t.clone(), Expr::u32(1))),
                ),
                Node::let_bind("lk_slot", hash_slot(Expr::var("target_hash"))),
                Node::let_bind("resolved", Expr::u32(EMPTY_SLOT)),
                Node::loop_for(
                    "probe",
                    Expr::u32(0),
                    Expr::u32(TABLE_CAP),
                    vec![
                        Node::let_bind("k", Expr::load("goto_labels_keys", Expr::var("lk_slot"))),
                        Node::if_then(
                            Expr::eq(Expr::var("k"), Expr::var("target_hash")),
                            vec![Node::assign(
                                "resolved",
                                Expr::load("goto_labels_vals", Expr::var("lk_slot")),
                            )],
                        ),
                        Node::assign(
                            "lk_slot",
                            Expr::bitand(
                                Expr::add(Expr::var("lk_slot"), Expr::u32(1)),
                                Expr::u32(TABLE_CAP - 1),
                            ),
                        ),
                    ],
                ),
                Node::store(out_cfg_blocks, t.clone(), Expr::var("resolved")),
            ],
        ),
    ];

    let n_ssa = match &num_ssa {
        Expr::LitU32(n) => *n,
        _ => 1,
    };
    Program::wrapped(
        vec![
            BufferDecl::storage(ssa_nodes, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n_ssa),
            BufferDecl::storage(out_cfg_blocks, 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(n_ssa),
            BufferDecl::storage(goto_labels, 2, BufferAccess::ReadWrite, DataType::U32)
                .with_count(n_ssa),
            BufferDecl::storage(
                "goto_labels_keys",
                3,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(TABLE_CAP),
            BufferDecl::storage(
                "goto_labels_vals",
                4,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(TABLE_CAP),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(
            "vyre-libs::parsing::c11_build_cfg_and_gotos",
            vec![Node::if_then(Expr::lt(t.clone(), num_ssa), loop_body)],
        )],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::parsing::c11_build_cfg_and_gotos",
        build: || c11_build_cfg_and_gotos("ssa", "cfg", "labels", Expr::u32(4)),
        // 4-slot fixture: every SSA node is a plain sequence (opcode
        // neither LABL 0x4C41424C nor GOTO 0x474F544F). Label insert
        // and goto lookup stay quiescent; cfg + keys + vals stay at
        // their zero init. All-zero witness.
        test_inputs: Some(|| vec![vec![
            vec![0u8; 4 * 4],
            vec![0u8; 4 * 4],
            vec![0u8; 4 * 4],
            vec![0u8; 4 * 4096],
            vec![0u8; 4 * 4096],
        ]]),
        expected_output: Some(|| vec![vec![
            vec![0u8; 4 * 4],
            vec![0u8; 4 * 4],
            vec![0u8; 4 * 4096],
            vec![0u8; 4 * 4096],
        ]]),
    }
}
