//! Scaled dot-product attention — `softmax(Q·Kᵀ / √d) · V`.
//!
//! Category-A composition. Inputs are laid out as contiguous F32 row-
//! major matrices in separate buffers. Shape is encoded statically in
//! the Program — (seq_len `s`, head_dim `d`). Produces one scores row
//! per query token into `output` (also `s * d` F32 elements).
//!
//! The default builder maps one invocation to one query row. The
//! scalar row-loop reference remains available through [`attention_reference`].

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program, UnOp};
use vyre_foundation::ir::model::expr::GeneratorRef;
use vyre_primitives::nn::attention_passes::{
    attention_max_pass, attention_sum_pass, attention_write_pass, ATTENTION_MAX_PASS_OP_ID,
    ATTENTION_SUM_PASS_OP_ID, ATTENTION_WRITE_PASS_OP_ID,
};

use crate::builder::{check_tensors, BuildOptions};
use crate::region::{wrap, wrap_child};
use crate::tensor_ref::{TensorRef, TensorRefError};

const OP_ID: &str = "vyre-libs::nn::attention";
const REFERENCE_OP_ID: &str = "vyre-libs::nn::attention_reference";

fn finite_or(value: Expr, replacement: Expr) -> Expr {
    Expr::select(Expr::is_finite(value.clone()), value, replacement)
}

fn bounded_exp_arg(value: Expr) -> Expr {
    let value_is_nan = Expr::is_nan(value.clone());
    let finite = finite_or(value.clone(), Expr::f32(-80.0));
    let upper_bounded = Expr::select(
        Expr::gt(finite.clone(), Expr::f32(0.0)),
        Expr::f32(0.0),
        finite,
    );
    let clamped = Expr::select(
        Expr::lt(upper_bounded.clone(), Expr::f32(-80.0)),
        Expr::f32(-80.0),
        upper_bounded,
    );
    Expr::select(value_is_nan, value, clamped)
}

fn positive_denominator(value: Expr) -> Expr {
    let repaired = Expr::select(
        Expr::and(
            Expr::is_finite(value.clone()),
            Expr::gt(value.clone(), Expr::f32(f32::MIN_POSITIVE)),
        ),
        value.clone(),
        Expr::f32(f32::MIN_POSITIVE),
    );
    Expr::select(Expr::is_nan(value.clone()), value, repaired)
}

fn flush_tiny(value: Expr) -> Expr {
    Expr::select(
        Expr::le(Expr::abs(value.clone()), Expr::f32(f32::MIN_POSITIVE)),
        Expr::f32(0.0),
        value,
    )
}

fn attention_score_nodes(q: &str, k: &str, d: u32, scale_expr: Expr) -> Vec<Node> {
    vec![
        Node::let_bind("dot_val", Expr::f32(0.0)),
        Node::loop_for(
            "k_idx",
            Expr::u32(0),
            Expr::u32(d),
            vec![Node::assign(
                "dot_val",
                Expr::add(
                    Expr::var("dot_val"),
                    Expr::mul(
                        Expr::load(
                            q,
                            Expr::add(
                                Expr::mul(Expr::var("row"), Expr::u32(d)),
                                Expr::var("k_idx"),
                            ),
                        ),
                        Expr::load(
                            k,
                            Expr::add(Expr::mul(Expr::var("j"), Expr::u32(d)), Expr::var("k_idx")),
                        ),
                    ),
                ),
            )],
        ),
        Node::let_bind("score", Expr::mul(Expr::var("dot_val"), scale_expr)),
    ]
}

/// Typed Cat-A builder for scaled dot-product attention.
#[derive(Debug, Clone)]
pub struct Attention {
    q: TensorRef,
    k: TensorRef,
    v: TensorRef,
    out: TensorRef,
    options: BuildOptions,
}

impl Attention {
    /// Start a builder. Every tensor must be `[s, d]` F32.
    #[must_use]
    pub fn new(q: TensorRef, k: TensorRef, v: TensorRef, out: TensorRef) -> Self {
        Self {
            q,
            k,
            v,
            out,
            options: BuildOptions::default(),
        }
    }

    /// Override workgroup size.
    #[must_use]
    pub fn with_workgroup_size(mut self, size: [u32; 3]) -> Self {
        self.options = self.options.with_workgroup_size(size);
        self
    }

    /// Override region generator name.
    #[must_use]
    pub fn with_region_generator(mut self, name: &'static str) -> Self {
        self.options = self.options.with_region_generator(name);
        self
    }

    /// Stamp the region metadata with a tenant id.
    #[must_use]
    pub fn with_tenant_id(mut self, tenant_id: u32) -> Self {
        self.options = self.options.with_tenant_id(tenant_id);
        self
    }

    /// Validate + materialize the Program.
    ///
    /// # Errors
    ///
    /// Surfaces the standard [`TensorRefError`] set. All four tensors
    /// must share the same `[s, d]` shape; a divergence reports the
    /// first mismatch against `q`'s shape.
    pub fn build(self) -> Result<Program, TensorRefError> {
        check_tensors(
            OP_ID,
            &[
                (&self.q, DataType::F32),
                (&self.k, DataType::F32),
                (&self.v, DataType::F32),
                (&self.out, DataType::F32),
            ],
        )?;
        for t in [&self.k, &self.v, &self.out] {
            if t.shape != self.q.shape {
                return Err(TensorRefError::ShapeMismatch {
                    name: t.name.as_str().to_string(),
                    found: t.shape.to_vec(),
                    expected: self.q.shape.to_vec(),
                    op: OP_ID,
                });
            }
        }
        if self.q.shape.len() != 2 {
            return Err(TensorRefError::ShapeMismatch {
                name: self.q.name.as_str().to_string(),
                found: self.q.shape.to_vec(),
                expected: vec![0, 0],
                op: OP_ID,
            });
        }
        let s = self.q.shape[0];
        let d = self.q.shape[1];
        // V7-CORR-013: reject d=0 so the host-side `1.0 / (d as f32).sqrt()`
        // doesn't produce +Inf and poison every subsequent score. Reject
        // s=0 for symmetry (zero query rows = empty output, not a bug but
        // an explicit contract violation).
        if d == 0 || s == 0 {
            return Err(TensorRefError::ShapeMismatch {
                name: self.q.name.as_str().to_string(),
                found: self.q.shape.to_vec(),
                expected: vec![1, 1],
                op: OP_ID,
            });
        }
        let _elements = s
            .checked_mul(d)
            .ok_or_else(|| TensorRefError::ElementCountOverflow {
                name: self.out.name.as_str().to_string(),
                shape: self.out.shape.to_vec(),
            })?;
        let tile = self.options.workgroup_size.unwrap_or([256, 1, 1])[0].max(1);
        let blocks_per_row = d.div_ceil(tile);
        s.checked_mul(blocks_per_row)
            .and_then(|groups| groups.checked_mul(tile))
            .ok_or_else(|| TensorRefError::ElementCountOverflow {
                name: self.out.name.as_str().to_string(),
                shape: vec![s, blocks_per_row, tile],
            })?;
        let program = attention_program(
            self.q.name_str(),
            self.k.name_str(),
            self.v.name_str(),
            self.out.name_str(),
            s,
            d,
            self.options.workgroup_size.unwrap_or([256, 1, 1]),
            self.options.region_generator.unwrap_or(OP_ID),
        )?;
        Ok(program)
    }
}

/// Build a Program that computes scaled dot-product attention. Back-
/// compat wrapper around [`Attention`]; invalid inputs lower to a trap.
#[must_use]
pub fn attention(q: &str, k: &str, v: &str, out: &str, s: u32, d: u32) -> Program {
    Attention::new(
        TensorRef::f32_2d(q, s, d),
        TensorRef::f32_2d(k, s, d),
        TensorRef::f32_2d(v, s, d),
        TensorRef::f32_2d(out, s, d),
    )
    .build()
    .unwrap_or_else(|err| {
        crate::builder::invalid_output_program(
            OP_ID,
            out,
            DataType::F32,
            format!("Fix: attention build failed: {err}"),
        )
    })
}

/// Build the scalar row-loop attention correctness reference.
#[must_use]
pub fn attention_reference(q: &str, k: &str, v: &str, out: &str, s: u32, d: u32) -> Program {
    try_attention_reference(q, k, v, out, s, d).unwrap_or_else(|error| {
        crate::builder::invalid_output_program(
            REFERENCE_OP_ID,
            out,
            DataType::F32,
            format!("Fix: attention_reference build failed: {error}"),
        )
    })
}

/// Fallible scalar row-loop attention correctness reference builder.
///
/// # Errors
///
/// Returns [`TensorRefError`] when the matrix shape is empty or overflows
/// `u32` element counts.
pub fn try_attention_reference(
    q: &str,
    k: &str,
    v: &str,
    out: &str,
    s: u32,
    d: u32,
) -> Result<Program, TensorRefError> {
    if s == 0 || d == 0 {
        return Err(TensorRefError::ShapeMismatch {
            name: q.to_string(),
            found: vec![s, d],
            expected: vec![1, 1],
            op: REFERENCE_OP_ID,
        });
    }
    s.checked_mul(d)
        .ok_or_else(|| TensorRefError::ElementCountOverflow {
            name: out.to_string(),
            shape: vec![s, d],
        })?;
    attention_reference_program(q, k, v, out, s, d, [1, 1, 1], REFERENCE_OP_ID)
}

#[allow(clippy::too_many_arguments)]
fn attention_program(
    q: &str,
    k: &str,
    v: &str,
    out: &str,
    s: u32,
    d: u32,
    workgroup: [u32; 3],
    generator: &'static str,
) -> Result<Program, TensorRefError> {
    let scale = 1.0f32 / (d as f32).sqrt();
    let scale_expr = Expr::f32(scale);
    let elements = s
        .checked_mul(d)
        .ok_or_else(|| TensorRefError::ElementCountOverflow {
            name: out.to_string(),
            shape: vec![s, d],
        })?;
    let tile = workgroup[0].max(1);
    let scratch_count = tile.max(2);
    let blocks_per_row = d.div_ceil(tile);
    let total_groups =
        s.checked_mul(blocks_per_row)
            .ok_or_else(|| TensorRefError::ElementCountOverflow {
                name: out.to_string(),
                shape: vec![s, blocks_per_row],
            })?;
    let padded_output_count =
        total_groups
            .checked_mul(tile)
            .ok_or_else(|| TensorRefError::ElementCountOverflow {
                name: out.to_string(),
                shape: vec![total_groups, tile],
            })?;
    let parent = GeneratorRef {
        name: generator.to_string(),
    };

    let mut body = vec![
        Node::let_bind("group", Expr::WorkgroupId { axis: 0 }),
        Node::let_bind("lane", Expr::LocalId { axis: 0 }),
        Node::let_bind(
            "row",
            Expr::div(Expr::var("group"), Expr::u32(blocks_per_row)),
        ),
        Node::let_bind(
            "dim_base",
            Expr::mul(
                Expr::rem(Expr::var("group"), Expr::u32(blocks_per_row)),
                Expr::u32(tile),
            ),
        ),
        Node::let_bind("dim", Expr::add(Expr::var("dim_base"), Expr::var("lane"))),
        wrap_child(
            ATTENTION_MAX_PASS_OP_ID,
            parent.clone(),
            vec![Node::if_then(Expr::eq(Expr::var("lane"), Expr::u32(0)), {
                let mut scalar_row = vec![Node::let_bind("max_val", Expr::f32(f32::MIN))];
                scalar_row.push(Node::loop_for("j", Expr::u32(0), Expr::u32(s), {
                    let mut score = attention_score_nodes(q, k, d, scale_expr.clone());
                    score.push(Node::assign(
                        "max_val",
                        Expr::select(
                            Expr::is_nan(Expr::var("score")),
                            Expr::var("score"),
                            Expr::select(
                                Expr::gt(Expr::var("score"), Expr::var("max_val")),
                                Expr::var("score"),
                                Expr::var("max_val"),
                            ),
                        ),
                    ));
                    score
                }));
                scalar_row.push(Node::store(
                    "attention_scratch",
                    Expr::u32(0),
                    Expr::var("max_val"),
                ));
                scalar_row
            })],
        ),
        wrap_child(
            ATTENTION_SUM_PASS_OP_ID,
            parent.clone(),
            vec![Node::if_then(Expr::eq(Expr::var("lane"), Expr::u32(0)), {
                let mut scalar_row = vec![Node::let_bind("sum_val", Expr::f32(0.0))];
                scalar_row.push(Node::loop_for("j", Expr::u32(0), Expr::u32(s), {
                    let mut score = attention_score_nodes(q, k, d, scale_expr.clone());
                    score.push(Node::assign(
                        "sum_val",
                        Expr::add(
                            Expr::var("sum_val"),
                            Expr::UnOp {
                                op: UnOp::Exp,
                                operand: Box::new(bounded_exp_arg(Expr::sub(
                                    Expr::var("score"),
                                    Expr::load("attention_scratch", Expr::u32(0)),
                                ))),
                            },
                        ),
                    ));
                    score
                }));
                scalar_row.push(Node::store(
                    "attention_scratch",
                    Expr::u32(1),
                    Expr::var("sum_val"),
                ));
                scalar_row
            })],
        ),
        Node::barrier(),
    ];
    body.extend([
        Node::let_bind("max_val", Expr::load("attention_scratch", Expr::u32(0))),
        Node::let_bind(
            "denom",
            positive_denominator(Expr::load("attention_scratch", Expr::u32(1))),
        ),
        wrap_child(
            ATTENTION_WRITE_PASS_OP_ID,
            parent,
            vec![Node::if_then(
                Expr::and(
                    Expr::lt(Expr::var("row"), Expr::u32(s)),
                    Expr::lt(Expr::var("dim"), Expr::u32(d)),
                ),
                {
                    let mut output_lane = vec![Node::let_bind("accum", Expr::f32(0.0))];
                    output_lane.push(Node::loop_for("j", Expr::u32(0), Expr::u32(s), {
                        let mut score = attention_score_nodes(q, k, d, scale_expr);
                        score.extend([
                            Node::let_bind(
                                "weight",
                                Expr::div(
                                    Expr::UnOp {
                                        op: UnOp::Exp,
                                        operand: Box::new(bounded_exp_arg(Expr::sub(
                                            Expr::var("score"),
                                            Expr::var("max_val"),
                                        ))),
                                    },
                                    Expr::var("denom"),
                                ),
                            ),
                            Node::let_bind(
                                "value",
                                Expr::load(
                                    v,
                                    Expr::add(
                                        Expr::mul(Expr::var("j"), Expr::u32(d)),
                                        Expr::var("dim"),
                                    ),
                                ),
                            ),
                            Node::assign(
                                "accum",
                                Expr::add(
                                    Expr::var("accum"),
                                    Expr::mul(Expr::var("weight"), Expr::var("value")),
                                ),
                            ),
                        ]);
                        score
                    }));
                    output_lane.push(Node::store(
                        out,
                        Expr::add(Expr::mul(Expr::var("row"), Expr::u32(d)), Expr::var("dim")),
                        flush_tiny(Expr::var("accum")),
                    ));
                    output_lane
                },
            )],
        ),
    ]);

    let body = vec![Node::if_then(
        Expr::lt(Expr::WorkgroupId { axis: 0 }, Expr::u32(total_groups)),
        body,
    )];

    Ok(Program::wrapped(
        vec![
            BufferDecl::storage(q, 0, BufferAccess::ReadOnly, DataType::F32).with_count(elements),
            BufferDecl::storage(k, 1, BufferAccess::ReadOnly, DataType::F32).with_count(elements),
            BufferDecl::storage(v, 2, BufferAccess::ReadOnly, DataType::F32).with_count(elements),
            BufferDecl::workgroup("attention_scratch", scratch_count, DataType::F32),
            BufferDecl::output(out, 3, DataType::F32)
                .with_count(padded_output_count)
                .with_output_byte_range(0..(elements as usize * core::mem::size_of::<f32>())),
        ],
        workgroup,
        vec![wrap(generator, body, None)],
    ))
}

#[allow(clippy::too_many_arguments)]
fn attention_reference_program(
    q: &str,
    k: &str,
    v: &str,
    out: &str,
    s: u32,
    d: u32,
    workgroup: [u32; 3],
    generator: &'static str,
) -> Result<Program, TensorRefError> {
    let scale = 1.0f32 / (d as f32).sqrt();
    let scale_expr = Expr::f32(scale);
    let parent = GeneratorRef {
        name: generator.to_string(),
    };

    // Per row i (query token):
    // 1) scores[j] = scale * dot(Q[i,:], K[j,:]) for j in 0..s
    // 2) max = max(scores)
    // 3) sum = Σ exp(scores[j] - max)
    // 4) out[i, t] = Σ_j (exp(scores[j] - max)/sum) * V[j, t]
    //
    // We elide the intermediate scores buffer by recomputing exp/sum
    // and the final weighted sum in separate passes — Cat-A shape.

    // Outer loop over query tokens. Uses a sentinel max from the
    // first score — initialize with a very negative number so the
    // first score wins the max-reduction.
    let per_row_body = vec![
        // target builder rejects Infinity literals in compute entry points; the
        // finite floor preserves max-reduction semantics for any finite score.
        Node::let_bind("max_val", Expr::f32(f32::MIN)),
        wrap_child(
            ATTENTION_MAX_PASS_OP_ID,
            parent.clone(),
            attention_max_pass(q, k, d, s, scale_expr.clone()),
        ),
        Node::let_bind("sum_val", Expr::f32(0.0)),
        wrap_child(
            ATTENTION_SUM_PASS_OP_ID,
            parent.clone(),
            attention_sum_pass(q, k, d, s, scale_expr.clone()),
        ),
        Node::let_bind(
            "denom",
            Expr::select(
                Expr::and(
                    Expr::is_finite(Expr::var("sum_val")),
                    Expr::gt(Expr::var("sum_val"), Expr::f32(f32::MIN_POSITIVE)),
                ),
                Expr::var("sum_val"),
                Expr::f32(f32::MIN_POSITIVE),
            ),
        ),
        wrap_child(
            ATTENTION_WRITE_PASS_OP_ID,
            parent.clone(),
            attention_write_pass(q, k, v, d, s, scale_expr, out),
        ),
    ];

    let outer_loop = Node::loop_for("i", Expr::u32(0), Expr::u32(s), per_row_body);

    let elements = s
        .checked_mul(d)
        .ok_or_else(|| TensorRefError::ElementCountOverflow {
            name: out.to_string(),
            shape: vec![s, d],
        })?;

    Ok(Program::wrapped(
        vec![
            BufferDecl::storage(q, 0, BufferAccess::ReadOnly, DataType::F32).with_count(elements),
            BufferDecl::storage(k, 1, BufferAccess::ReadOnly, DataType::F32).with_count(elements),
            BufferDecl::storage(v, 2, BufferAccess::ReadOnly, DataType::F32).with_count(elements),
            BufferDecl::output(out, 3, DataType::F32).with_count(elements),
        ],
        workgroup,
        vec![wrap(generator, vec![outer_loop], None)],
    ))
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::nn::attention",
        build: || attention("q", "k", "v", "out", 2, 4),
        test_inputs: Some(|| {
            let q = [0.5f32, -1.0, 1.5, 0.25, -0.75, 0.5, 1.0, -0.5];
            let k = [1.0f32, 0.25, -0.5, 1.5, 0.75, -1.25, 0.5, 0.5];
            let v = [2.0f32, -1.0, 0.5, 1.25, -0.25, 0.75, 1.5, -0.5];
            vec![vec![
                q.iter().flat_map(|value| value.to_le_bytes()).collect(),
                k.iter().flat_map(|value| value.to_le_bytes()).collect(),
                v.iter().flat_map(|value| value.to_le_bytes()).collect(),
                vec![0u8; 512 * core::mem::size_of::<f32>()],
            ]]
        }),
        expected_output: Some(|| vec![
            vec![
                vec![0x46, 0x9b, 0x68, 0x3e, 0x82, 0xfc, 0xc1, 0x3e, 0xee, 0xda, 0xa4, 0x3f, 0x02, 0xf9, 0x03, 0xbe,
                     0x9c, 0xb5, 0x1d, 0x3f, 0x90, 0x79, 0x9c, 0x3d, 0x33, 0xbb, 0x8e, 0x3f, 0x38, 0xc3, 0x31, 0x3e, ],
            ],
        ]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_reference::value::Value;

    fn f32_bytes(values: &[f32]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect()
    }

    fn decode_f32(bytes: &[u8]) -> Vec<f32> {
        bytes
            .chunks_exact(4)
            .map(|chunk| f32::from_le_bytes(chunk.try_into().unwrap()))
            .collect()
    }

    #[test]
    fn parallel_attention_matches_scalar_reference() {
        let s = 5_u32;
        let d = 7_u32;
        let elements = (s * d) as usize;
        let q = (0..elements)
            .map(|i| ((i as f32) * 0.13).sin() - 0.5)
            .collect::<Vec<_>>();
        let k = (0..elements)
            .map(|i| ((i as f32) * 0.07).cos() + 0.25)
            .collect::<Vec<_>>();
        let v = (0..elements)
            .map(|i| ((i as f32) * 0.19).sin() * 2.0)
            .collect::<Vec<_>>();
        let run = |program: Program| {
            let out_bytes = program
                .buffers()
                .iter()
                .find(|buffer| buffer.name() == "out")
                .map(|buffer| buffer.count() as usize * core::mem::size_of::<f32>())
                .expect("Fix: attention fixture must declare the output buffer.");
            let outputs = vyre_reference::reference_eval(
                &program,
                &[
                    Value::from(f32_bytes(&q)),
                    Value::from(f32_bytes(&k)),
                    Value::from(f32_bytes(&v)),
                    Value::from(vec![0u8; out_bytes]),
                ],
            )
            .expect("Fix: attention program must execute in the reference interpreter.");
            decode_f32(&outputs[0].to_bytes())
        };
        let actual = run(attention("q", "k", "v", "out", s, d));
        let expected = run(attention_reference("q", "k", "v", "out", s, d));
        assert_eq!(
            actual.len(),
            expected.len(),
            "Fix: attention output_byte_range must trim padded dispatch storage to the logical tensor length."
        );
        for (idx, (lhs, rhs)) in actual.iter().zip(expected.iter()).enumerate() {
            assert!(
                (lhs - rhs).abs() <= 1.0e-5,
                "attention mismatch at lane {idx}: parallel={lhs:?} reference={rhs:?}"
            );
        }
    }

    #[test]
    fn attention_builders_reject_overflow_without_panic() {
        let err = Attention::new(
            TensorRef::f32_2d("q", u32::MAX, 2),
            TensorRef::f32_2d("k", u32::MAX, 2),
            TensorRef::f32_2d("v", u32::MAX, 2),
            TensorRef::f32_2d("out", u32::MAX, 2),
        )
        .build()
        .expect_err("overflowing attention shape must return TensorRefError");
        assert!(matches!(err, TensorRefError::ElementCountOverflow { .. }));

        assert!(matches!(
            try_attention_reference("q", "k", "v", "out", u32::MAX, 2),
            Err(TensorRefError::ElementCountOverflow { .. })
        ));
    }

    #[test]
    fn attention_zero_sequence_length_rejected() {
        let err = Attention::new(
            TensorRef::f32_2d("q", 0, 4),
            TensorRef::f32_2d("k", 0, 4),
            TensorRef::f32_2d("v", 0, 4),
            TensorRef::f32_2d("out", 0, 4),
        )
        .build()
        .unwrap_err();
        assert!(matches!(err, TensorRefError::ShapeMismatch { .. }));
    }

    #[test]
    fn attention_single_token_passes_v_through() {
        let s = 1u32;
        let d = 4u32;
        let q = [1.0f32, 2.0, 3.0, 4.0];
        let k = [0.5f32, 1.5, 2.5, 3.5];
        let v = [10.0f32, 20.0, 30.0, 40.0];
        let program = attention("q", "k", "v", "out", s, d);
        let out_bytes = program
            .buffers()
            .iter()
            .find(|b| b.name() == "out")
            .map(|b| b.count() as usize * core::mem::size_of::<f32>())
            .expect("output buffer present");
        let outputs = vyre_reference::reference_eval(
            &program,
            &[
                Value::from(f32_bytes(&q)),
                Value::from(f32_bytes(&k)),
                Value::from(f32_bytes(&v)),
                Value::from(vec![0u8; out_bytes]),
            ],
        )
        .expect("Fix: attention single token must execute");
        let out = decode_f32(&outputs[0].to_bytes());
        for (i, (&a, &e)) in out.iter().zip(v.iter()).enumerate() {
            assert!(
                (a - e).abs() <= 1.0e-4,
                "attention single token mismatch at {i}: {a} != {e}"
            );
        }
    }

    #[test]
    fn attention_nan_in_q_does_not_silently_produce_finite_output() {
        // The attention implementation uses finite_or to replace NaN scores with f32::MIN.
        // This test documents that NaN in Q is silently suppressed rather than propagated.
        let s = 2u32;
        let d = 2u32;
        let mut q = [1.0f32, 0.0, 0.0, 1.0];
        q[0] = f32::NAN;
        let k = [1.0f32, 0.0, 0.0, 1.0];
        let v = [10.0f32, 20.0, 30.0, 40.0];
        let program = attention("q", "k", "v", "out", s, d);
        let out_bytes = program
            .buffers()
            .iter()
            .find(|b| b.name() == "out")
            .map(|b| b.count() as usize * core::mem::size_of::<f32>())
            .expect("output buffer present");
        let outputs = vyre_reference::reference_eval(
            &program,
            &[
                Value::from(f32_bytes(&q)),
                Value::from(f32_bytes(&k)),
                Value::from(f32_bytes(&v)),
                Value::from(vec![0u8; out_bytes]),
            ],
        )
        .expect("Fix: attention must not panic on NaN in Q");
        let out = decode_f32(&outputs[0].to_bytes());
        assert!(
            out.iter().any(|v| v.is_nan()),
            "attention must propagate NaN in Q instead of silently producing finite output {:?}",
            out
        );
    }

    #[test]
    fn attention_nan_in_v_does_not_silently_produce_finite_output() {
        // The attention implementation uses finite_or to replace NaN in V with 0.0.
        let s = 2u32;
        let d = 2u32;
        let q = [1.0f32, 0.0, 0.0, 1.0];
        let k = [1.0f32, 0.0, 0.0, 1.0];
        let mut v = [10.0f32, 20.0, 30.0, 40.0];
        v[0] = f32::NAN;
        let program = attention("q", "k", "v", "out", s, d);
        let out_bytes = program
            .buffers()
            .iter()
            .find(|b| b.name() == "out")
            .map(|b| b.count() as usize * core::mem::size_of::<f32>())
            .expect("output buffer present");
        let outputs = vyre_reference::reference_eval(
            &program,
            &[
                Value::from(f32_bytes(&q)),
                Value::from(f32_bytes(&k)),
                Value::from(f32_bytes(&v)),
                Value::from(vec![0u8; out_bytes]),
            ],
        )
        .expect("Fix: attention must not panic on NaN in V");
        let out = decode_f32(&outputs[0].to_bytes());
        assert!(
            out.iter().any(|v| v.is_nan()),
            "attention must propagate NaN in V instead of silently producing finite output {:?}",
            out
        );
    }
}
