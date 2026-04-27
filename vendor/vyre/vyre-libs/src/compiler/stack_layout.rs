use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// GPU SIMT Stack Layout Generator (Prologue/Epilogue Spiller)
///
/// When variables cannot fit into the physical 16 registers of x86_64, they "spill".
/// This module generates precise Main Memory stack offsets relative to `%rbp` (base pointer)
/// and emits `push`/`pop` sequences using SIMT inclusive scan prefix offsets.
#[must_use]
pub fn opt_stack_layout_generation(
    physical_registers: &str,
    out_spill_offsets: &str,
    num_regs: Expr,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };

    let loop_body = vec![
        Node::let_bind("reg_bound", Expr::load(physical_registers, t.clone())),
        // Emulate spill checking: if virtual node couldn't bind to 0-15
        Node::if_then(
            Expr::ge(Expr::var("reg_bound"), Expr::u32(16)),
            vec![
                // Calculate physical `-0x08(%rbp)`, `-0x10(%rbp)` stack offsets locally.
                // Uses atomic add to claim block on the global stack frame boundary.
                Node::let_bind(
                    "stack_offset",
                    Expr::atomic_add("tmp_stack_frame_size", Expr::u32(0), Expr::u32(8)),
                ),
                Node::store(out_spill_offsets, t.clone(), Expr::var("stack_offset")),
            ],
        ),
    ];

    let reg_count = match &num_regs {
        Expr::LitU32(n) => *n,
        _ => 1,
    };
    Program::wrapped(
        vec![
            BufferDecl::storage(physical_registers, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(reg_count),
            BufferDecl::storage(out_spill_offsets, 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(reg_count),
            // Atomics require ReadWrite storage, not workgroup memory —
            // the reference interpreter enforces this explicitly.
            BufferDecl::storage(
                "tmp_stack_frame_size",
                2,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(1),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(
            "vyre-libs::parsing::opt_stack_layout_generation",
            vec![Node::if_then(Expr::lt(t.clone(), num_regs), loop_body)],
        )],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::parsing::opt_stack_layout_generation",
        build: || opt_stack_layout_generation("regs", "spills", Expr::u32(4)),
        // 4 virtual registers: two sit in the 0..=15 physical window,
        // two spill (reg_bound = 20, 30). Each spill claims an 8-byte
        // stack slot via atomic_add on a workgroup-scoped counter.
        // The reference interpreter runs one lane at a time in
        // monotonic invocation order, so spill_offsets[1] = 0 and
        // spill_offsets[3] = 8.
        test_inputs: Some(|| {
            let regs: [u32; 4] = [3, 20, 7, 30];
            let bytes = regs
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<u8>>();
            // regs (ReadOnly), out_spill_offsets (ReadWrite),
            // tmp_stack_frame_size (ReadWrite, 1 slot).
            vec![vec![bytes, vec![0u8; 4 * 4], vec![0u8; 4]]]
        }),
        expected_output: Some(|| {
            let spills: [u32; 4] = [0, 0, 0, 8];
            let frame_size: [u32; 1] = [16];
            let to_bytes = |s: &[u32]| s.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&spills), to_bytes(&frame_size)]]
        }),
    }
}
