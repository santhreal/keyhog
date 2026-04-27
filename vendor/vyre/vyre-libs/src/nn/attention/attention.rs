//! Scaled dot-product attention — `softmax(Q·Kᵀ / √d) · V`.
//!
//! Category-A composition. Inputs are laid out as contiguous F32 row-
//! major matrices in separate buffers. Shape is encoded statically in
//! the Program — (seq_len `s`, head_dim `d`). Produces one scores row
//! per query token into `output` (also `s * d` F32 elements).
//!
//! This is the correctness reference for Flash-Attention-shaped tiled
//! variants; the inner structure mirrors `softmax` and a row-wise
//! matmul so `region_inline` flattens the entire composition for
//! optimizer visibility.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};
use vyre_foundation::ir::model::expr::GeneratorRef;
use vyre_primitives::nn::attention_passes::{
    attention_max_pass, attention_sum_pass, attention_write_pass, ATTENTION_MAX_PASS_OP_ID,
    ATTENTION_SUM_PASS_OP_ID, ATTENTION_WRITE_PASS_OP_ID,
};

use crate::builder::{check_tensors, BuildOptions};
use crate::region::{wrap, wrap_anonymous, wrap_child};
use crate::tensor_ref::{TensorRef, TensorRefError};

const OP_ID: &str = "vyre-libs::nn::attention";

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
        let program = attention_program(
            self.q.name_str(),
            self.k.name_str(),
            self.v.name_str(),
            self.out.name_str(),
            s,
            d,
            self.options.workgroup_size.unwrap_or([1, 1, 1]),
            self.options.region_generator.unwrap_or(OP_ID),
        );
        Ok(program)
    }
}

/// Build a Program that computes scaled dot-product attention. Back-
/// compat wrapper around [`Attention`]; panics on contract violation.
#[must_use]
pub fn attention(q: &str, k: &str, v: &str, out: &str, s: u32, d: u32) -> Program {
    Attention::new(
        TensorRef::f32_2d(q, s, d),
        TensorRef::f32_2d(k, s, d),
        TensorRef::f32_2d(v, s, d),
        TensorRef::f32_2d(out, s, d),
    )
    .build()
    .unwrap_or_else(|err| panic!("Fix: attention build failed: {err}"))
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
) -> Program {
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
        // Naga rejects Infinity literals in compute entry points; the
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
        wrap_child(
            ATTENTION_WRITE_PASS_OP_ID,
            parent.clone(),
            attention_write_pass(q, k, v, d, s, scale_expr, out),
        ),
    ];

    let outer_loop = Node::loop_for("i", Expr::u32(0), Expr::u32(s), per_row_body);

    let elements = s
        .checked_mul(d)
        .expect("attention: s*d overflows u32 — reduce the seq_len × head_dim product");

    Program::wrapped(
        vec![
            BufferDecl::storage(q, 0, BufferAccess::ReadOnly, DataType::F32).with_count(elements),
            BufferDecl::storage(k, 1, BufferAccess::ReadOnly, DataType::F32).with_count(elements),
            BufferDecl::storage(v, 2, BufferAccess::ReadOnly, DataType::F32).with_count(elements),
            BufferDecl::output(out, 3, DataType::F32).with_count(elements),
        ],
        workgroup,
        vec![wrap(generator, vec![outer_loop], None)],
    )
}

// Preserve wrap_anonymous import in case future builder overloads
// want the anonymous generator path.
const _: fn(&'static str, Vec<Node>) -> Node = wrap_anonymous;

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
                vec![0u8; q.len() * core::mem::size_of::<f32>()],
            ]]
        }),
        expected_output: Some(|| vec![
            vec![
                vec![0x46, 0x9b, 0x68, 0x3e, 0x82, 0xfc, 0xc1, 0x3e, 0xee, 0xda, 0xa4, 0x3f, 0x02, 0xf9, 0x03, 0xbe,
                     0x9a, 0xb5, 0x1d, 0x3f, 0x94, 0x79, 0x9c, 0x3d, 0x33, 0xbb, 0x8e, 0x3f, 0x36, 0xc3, 0x31, 0x3e, ],
            ],
        ]),
    }
}
