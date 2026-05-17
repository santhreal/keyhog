use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program, UnOp};

pub(crate) const WORKGROUP_SIZE: u32 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AtomicReduceKind {
    Sum,
    Min,
    Max,
    PopcountSum,
}

impl AtomicReduceKind {
    fn identity(self) -> u32 {
        match self {
            Self::Sum | Self::Max | Self::PopcountSum => 0,
            Self::Min => u32::MAX,
        }
    }

    fn value(self, input: &str, index: Expr) -> Expr {
        let loaded = Expr::load(input, index);
        match self {
            Self::PopcountSum => Expr::UnOp {
                op: UnOp::Popcount,
                operand: Box::new(loaded),
            },
            Self::Sum | Self::Min | Self::Max => loaded,
        }
    }

    fn atomic(self, out: &str, value: Expr) -> Expr {
        match self {
            Self::Sum | Self::PopcountSum => Expr::atomic_add(out, Expr::u32(0), value),
            Self::Min => Expr::atomic_min(out, Expr::u32(0), value),
            Self::Max => Expr::atomic_max(out, Expr::u32(0), value),
        }
    }
}

pub(crate) fn atomic_reduce_u32(
    input: &str,
    out: &str,
    count: u32,
    kind: AtomicReduceKind,
    op_id: &'static str,
) -> Program {
    let lane = Expr::InvocationId { axis: 0 };
    let chunk_count = Expr::div(
        Expr::add(Expr::u32(count), Expr::u32(WORKGROUP_SIZE - 1)),
        Expr::u32(WORKGROUP_SIZE),
    );

    let body = vec![
        Node::if_then(
            Expr::eq(lane.clone(), Expr::u32(0)),
            vec![Node::store(out, Expr::u32(0), Expr::u32(kind.identity()))],
        ),
        Node::Barrier {
            ordering: vyre_foundation::MemoryOrdering::SeqCst,
        },
        Node::loop_for(
            "chunk",
            Expr::u32(0),
            chunk_count,
            vec![
                Node::let_bind(
                    "i",
                    Expr::add(
                        Expr::mul(Expr::var("chunk"), Expr::u32(WORKGROUP_SIZE)),
                        lane.clone(),
                    ),
                ),
                Node::if_then(
                    Expr::lt(Expr::var("i"), Expr::u32(count)),
                    vec![Node::let_bind(
                        "_",
                        kind.atomic(out, kind.value(input, Expr::var("i"))),
                    )],
                ),
            ],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::U32).with_count(count),
            BufferDecl::storage(out, 1, BufferAccess::ReadWrite, DataType::U32).with_count(1),
        ],
        [WORKGROUP_SIZE, 1, 1],
        vec![Node::Region {
            generator: Ident::from(op_id),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}
