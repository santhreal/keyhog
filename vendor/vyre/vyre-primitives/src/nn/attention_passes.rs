//! Reusable attention passes built from the shared `dot_partial` primitive.

use std::sync::Arc;
use vyre_foundation::ir::model::expr::{GeneratorRef, Ident};
use vyre_foundation::ir::{BinOp, BufferAccess, BufferDecl, DataType, Expr, Node, Program, UnOp};

use crate::math::dot_partial::{dot_partial, OP_ID as DOT_PARTIAL_OP_ID};

/// Stable op id for the max-score pass.
pub const ATTENTION_MAX_PASS_OP_ID: &str = "vyre-primitives::nn::attention_max_pass";
/// Stable op id for the normalization-sum pass.
pub const ATTENTION_SUM_PASS_OP_ID: &str = "vyre-primitives::nn::attention_sum_pass";
/// Stable op id for the weighted-value write pass.
pub const ATTENTION_WRITE_PASS_OP_ID: &str = "vyre-primitives::nn::attention_write_pass";

/// Emit the attention max-reduction pass for one query row `i`.
#[must_use]
pub fn attention_max_pass(q: &str, k: &str, d: u32, s: u32, scale_expr: Expr) -> Vec<Node> {
    let parent = GeneratorRef {
        name: ATTENTION_MAX_PASS_OP_ID.to_string(),
    };
    vec![Node::loop_for(
        "j",
        Expr::u32(0),
        Expr::u32(s),
        vec![Node::Region {
            generator: Ident::from(DOT_PARTIAL_OP_ID),
            source_region: Some(parent),
            body: Arc::new(vec![
                Node::let_bind("dot_val", Expr::f32(0.0)),
                dot_partial(
                    q,
                    k,
                    "dot_val",
                    Expr::mul(Expr::var("i"), Expr::u32(d)),
                    Expr::mul(Expr::var("j"), Expr::u32(d)),
                    d,
                ),
                Node::let_bind("score", Expr::mul(Expr::var("dot_val"), scale_expr)),
                Node::assign(
                    "max_val",
                    Expr::select(
                        Expr::BinOp {
                            op: BinOp::Gt,
                            left: Box::new(Expr::var("score")),
                            right: Box::new(Expr::var("max_val")),
                        },
                        Expr::var("score"),
                        Expr::var("max_val"),
                    ),
                ),
            ]),
        }],
    )]
}

/// Standalone max-score pass for query row 0.
#[must_use]
pub fn attention_max_pass_program(q: &str, k: &str, out: &str, s: u32, d: u32) -> Program {
    let scale_expr = Expr::f32(1.0f32 / (d as f32).sqrt());
    Program::wrapped(
        vec![
            BufferDecl::storage(q, 0, BufferAccess::ReadOnly, DataType::F32).with_count(d),
            BufferDecl::storage(k, 1, BufferAccess::ReadOnly, DataType::F32)
                .with_count(s.saturating_mul(d)),
            BufferDecl::storage(out, 2, BufferAccess::ReadWrite, DataType::F32).with_count(1),
        ],
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(ATTENTION_MAX_PASS_OP_ID),
            source_region: None,
            body: Arc::new(vec![
                Node::let_bind("i", Expr::u32(0)),
                Node::let_bind("max_val", Expr::f32(f32::MIN)),
                Node::Block(attention_max_pass(q, k, d, s, scale_expr)),
                Node::store(out, Expr::u32(0), Expr::var("max_val")),
            ]),
        }],
    )
}

/// Emit the attention normalization-sum pass for one query row `i`.
#[must_use]
pub fn attention_sum_pass(q: &str, k: &str, d: u32, s: u32, scale_expr: Expr) -> Vec<Node> {
    let parent = GeneratorRef {
        name: ATTENTION_SUM_PASS_OP_ID.to_string(),
    };
    vec![Node::loop_for(
        "j",
        Expr::u32(0),
        Expr::u32(s),
        vec![Node::Region {
            generator: Ident::from(DOT_PARTIAL_OP_ID),
            source_region: Some(parent),
            body: Arc::new(vec![
                Node::let_bind("dot_val", Expr::f32(0.0)),
                dot_partial(
                    q,
                    k,
                    "dot_val",
                    Expr::mul(Expr::var("i"), Expr::u32(d)),
                    Expr::mul(Expr::var("j"), Expr::u32(d)),
                    d,
                ),
                Node::let_bind("score", Expr::mul(Expr::var("dot_val"), scale_expr)),
                Node::assign(
                    "sum_val",
                    Expr::add(
                        Expr::var("sum_val"),
                        Expr::UnOp {
                            op: UnOp::Exp,
                            operand: Box::new(Expr::BinOp {
                                op: BinOp::Sub,
                                left: Box::new(Expr::var("score")),
                                right: Box::new(Expr::var("max_val")),
                            }),
                        },
                    ),
                ),
            ]),
        }],
    )]
}

/// Standalone normalization-sum pass for query row 0.
#[must_use]
pub fn attention_sum_pass_program(
    q: &str,
    k: &str,
    max_in: &str,
    out: &str,
    s: u32,
    d: u32,
) -> Program {
    let scale_expr = Expr::f32(1.0f32 / (d as f32).sqrt());
    Program::wrapped(
        vec![
            BufferDecl::storage(q, 0, BufferAccess::ReadOnly, DataType::F32).with_count(d),
            BufferDecl::storage(k, 1, BufferAccess::ReadOnly, DataType::F32)
                .with_count(s.saturating_mul(d)),
            BufferDecl::storage(max_in, 2, BufferAccess::ReadOnly, DataType::F32).with_count(1),
            BufferDecl::storage(out, 3, BufferAccess::ReadWrite, DataType::F32).with_count(1),
        ],
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(ATTENTION_SUM_PASS_OP_ID),
            source_region: None,
            body: Arc::new(vec![
                Node::let_bind("i", Expr::u32(0)),
                Node::let_bind("max_val", Expr::load(max_in, Expr::u32(0))),
                Node::let_bind("sum_val", Expr::f32(0.0)),
                Node::Block(attention_sum_pass(q, k, d, s, scale_expr)),
                Node::store(out, Expr::u32(0), Expr::var("sum_val")),
            ]),
        }],
    )
}

/// Emit the attention weighted-value write pass for one query row `i`.
#[must_use]
pub fn attention_write_pass(
    q: &str,
    k: &str,
    v: &str,
    d: u32,
    s: u32,
    scale_expr: Expr,
    out: &str,
) -> Vec<Node> {
    let parent = GeneratorRef {
        name: ATTENTION_WRITE_PASS_OP_ID.to_string(),
    };
    vec![Node::loop_for(
        "t",
        Expr::u32(0),
        Expr::u32(d),
        vec![
            Node::let_bind("accum", Expr::f32(0.0)),
            Node::loop_for(
                "j",
                Expr::u32(0),
                Expr::u32(s),
                vec![Node::Region {
                    generator: Ident::from(DOT_PARTIAL_OP_ID),
                    source_region: Some(parent),
                    body: Arc::new(vec![
                        Node::let_bind("dot_val", Expr::f32(0.0)),
                        dot_partial(
                            q,
                            k,
                            "dot_val",
                            Expr::mul(Expr::var("i"), Expr::u32(d)),
                            Expr::mul(Expr::var("j"), Expr::u32(d)),
                            d,
                        ),
                        Node::let_bind("score", Expr::mul(Expr::var("dot_val"), scale_expr)),
                        Node::let_bind(
                            "weight",
                            Expr::BinOp {
                                op: BinOp::Div,
                                left: Box::new(Expr::UnOp {
                                    op: UnOp::Exp,
                                    operand: Box::new(Expr::BinOp {
                                        op: BinOp::Sub,
                                        left: Box::new(Expr::var("score")),
                                        right: Box::new(Expr::var("max_val")),
                                    }),
                                }),
                                right: Box::new(Expr::var("sum_val")),
                            },
                        ),
                        Node::assign(
                            "accum",
                            Expr::add(
                                Expr::var("accum"),
                                Expr::mul(
                                    Expr::var("weight"),
                                    Expr::load(
                                        v,
                                        Expr::add(
                                            Expr::mul(Expr::var("j"), Expr::u32(d)),
                                            Expr::var("t"),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ]),
                }],
            ),
            Node::Store {
                buffer: out.into(),
                index: Expr::add(Expr::mul(Expr::var("i"), Expr::u32(d)), Expr::var("t")),
                value: Expr::var("accum"),
            },
        ],
    )]
}

/// Buffer names and dimensions for a standalone weighted-value write pass.
pub struct AttentionWritePassProgramSpec<'a> {
    /// Query buffer.
    pub q: &'a str,
    /// Key buffer.
    pub k: &'a str,
    /// Value buffer.
    pub v: &'a str,
    /// Single-element max-score input buffer.
    pub max_in: &'a str,
    /// Single-element normalization-sum input buffer.
    pub sum_in: &'a str,
    /// Output buffer.
    pub out: &'a str,
    /// Sequence length.
    pub s: u32,
    /// Head dimension.
    pub d: u32,
}

/// Standalone weighted-value write pass for query row 0.
#[must_use]
pub fn attention_write_pass_program(spec: AttentionWritePassProgramSpec<'_>) -> Program {
    let AttentionWritePassProgramSpec {
        q,
        k,
        v,
        max_in,
        sum_in,
        out,
        s,
        d,
    } = spec;
    let scale_expr = Expr::f32(1.0f32 / (d as f32).sqrt());
    let elements = s.saturating_mul(d);
    Program::wrapped(
        vec![
            BufferDecl::storage(q, 0, BufferAccess::ReadOnly, DataType::F32).with_count(d),
            BufferDecl::storage(k, 1, BufferAccess::ReadOnly, DataType::F32).with_count(elements),
            BufferDecl::storage(v, 2, BufferAccess::ReadOnly, DataType::F32).with_count(elements),
            BufferDecl::storage(max_in, 3, BufferAccess::ReadOnly, DataType::F32).with_count(1),
            BufferDecl::storage(sum_in, 4, BufferAccess::ReadOnly, DataType::F32).with_count(1),
            BufferDecl::storage(out, 5, BufferAccess::ReadWrite, DataType::F32).with_count(d),
        ],
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(ATTENTION_WRITE_PASS_OP_ID),
            source_region: None,
            body: Arc::new(vec![
                Node::let_bind("i", Expr::u32(0)),
                Node::let_bind("max_val", Expr::load(max_in, Expr::u32(0))),
                Node::let_bind("sum_val", Expr::load(sum_in, Expr::u32(0))),
                Node::Block(attention_write_pass(q, k, v, d, s, scale_expr, out)),
            ]),
        }],
    )
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        ATTENTION_MAX_PASS_OP_ID,
        || attention_max_pass_program("q", "k", "out", 2, 2),
        Some(|| {
            let to_f32_bytes =
                |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_f32_bytes(&[1.0, 0.0]),
                to_f32_bytes(&[1.0, 0.0, 2.0, 0.0]),
                vec![0u8; 4],
            ]]
        }),
        Some(|| {
            let to_f32_bytes =
                |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            let scale = 1.0f32 / 2.0f32.sqrt();
            vec![vec![to_f32_bytes(&[2.0 * scale])]]
        }),
    )
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        ATTENTION_SUM_PASS_OP_ID,
        || attention_sum_pass_program("q", "k", "max", "out", 2, 2),
        Some(|| {
            let to_f32_bytes =
                |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            let scale = 1.0f32 / 2.0f32.sqrt();
            vec![vec![
                to_f32_bytes(&[1.0, 0.0]),
                to_f32_bytes(&[1.0, 0.0, 2.0, 0.0]),
                to_f32_bytes(&[2.0 * scale]),
                vec![0u8; 4],
            ]]
        }),
        Some(|| {
            let to_f32_bytes =
                |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            let scale = 1.0f32 / 2.0f32.sqrt();
            let sum = ((1.0 * scale) - (2.0 * scale)).exp() + 1.0;
            vec![vec![to_f32_bytes(&[sum])]]
        }),
    )
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        ATTENTION_WRITE_PASS_OP_ID,
        || {
            attention_write_pass_program(AttentionWritePassProgramSpec {
                q: "q",
                k: "k",
                v: "v",
                max_in: "max",
                sum_in: "sum",
                out: "out",
                s: 2,
                d: 2,
            })
        },
        Some(|| {
            let to_f32_bytes =
                |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            let scale = 1.0f32 / 2.0f32.sqrt();
            let sum = ((1.0 * scale) - (2.0 * scale)).exp() + 1.0;
            vec![vec![
                to_f32_bytes(&[1.0, 0.0]),
                to_f32_bytes(&[1.0, 0.0, 2.0, 0.0]),
                to_f32_bytes(&[10.0, 20.0, 30.0, 40.0]),
                to_f32_bytes(&[2.0 * scale]),
                to_f32_bytes(&[sum]),
                vec![0u8; 8],
            ]]
        }),
        Some(|| {
            let to_f32_bytes =
                |w: &[f32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            let scale = 1.0f32 / 2.0f32.sqrt();
            let w0 = ((1.0 * scale) - (2.0 * scale)).exp();
            let sum = w0 + 1.0;
            let out0 = (w0 / sum) * 10.0 + (1.0 / sum) * 30.0;
            let out1 = (w0 / sum) * 20.0 + (1.0 / sum) * 40.0;
            vec![vec![to_f32_bytes(&[out0, out1])]]
        }),
    )
}
