//! Matrix multiplication — row-major 2D `u32` multiply with atomic
//! accumulation into an output matrix.
//!
//! Category A composition. Wraps the inner loop in a `Node::Region`
//! so the optimizer treats it as opaque unless an inline pass
//! explicitly unrolls.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::builder::{check_tensors, BuildOptions};
use crate::region::{wrap, wrap_anonymous};
use crate::tensor_ref::{TensorRef, TensorRefError};

const OP_ID: &str = "vyre-libs::math::matmul";
const OP_ID_BIAS: &str = "vyre-libs::math::matmul_bias";

/// Typed Cat-A builder for [`matmul`].
#[derive(Debug, Clone)]
pub struct Matmul {
    a: TensorRef,
    b: TensorRef,
    out: TensorRef,
    options: BuildOptions,
}

impl Matmul {
    /// Start a builder. Shapes must be `a: [m, k]`, `b: [k, n]`,
    /// `out: [m, n]` with matching `k` dim.
    #[must_use]
    pub fn new(a: TensorRef, b: TensorRef, out: TensorRef) -> Self {
        Self {
            a,
            b,
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

    /// Stamp tenant id.
    #[must_use]
    pub fn with_tenant_id(mut self, tenant_id: u32) -> Self {
        self.options = self.options.with_tenant_id(tenant_id);
        self
    }

    /// Validate + materialize.
    ///
    /// # Errors
    ///
    /// Standard [`TensorRefError`] set plus shape-coherence checks:
    /// `a.shape[1] == b.shape[0]` (shared k dim),
    /// `out.shape == [a.shape[0], b.shape[1]]`.
    pub fn build(self) -> Result<Program, TensorRefError> {
        check_tensors(
            OP_ID,
            &[
                (&self.a, DataType::U32),
                (&self.b, DataType::U32),
                (&self.out, DataType::U32),
            ],
        )?;
        if self.a.shape.len() != 2 || self.b.shape.len() != 2 || self.out.shape.len() != 2 {
            return Err(TensorRefError::ShapeMismatch {
                name: "a/b/out".into(),
                found: vec![],
                expected: vec![0, 0],
                op: OP_ID,
            });
        }
        let m = self.a.shape[0];
        let k = self.a.shape[1];
        let n = self.b.shape[1];
        if self.b.shape[0] != k {
            return Err(TensorRefError::ShapeMismatch {
                name: self.b.name.as_str().to_string(),
                found: self.b.shape.to_vec(),
                expected: vec![k, n],
                op: OP_ID,
            });
        }
        if self.out.shape.as_ref() != [m, n] {
            return Err(TensorRefError::ShapeMismatch {
                name: self.out.name.as_str().to_string(),
                found: self.out.shape.to_vec(),
                expected: vec![m, n],
                op: OP_ID,
            });
        }

        let body = matmul_body(
            self.a.name_str(),
            self.b.name_str(),
            self.out.name_str(),
            k,
            n,
        );
        let a_count = m.checked_mul(k).expect("matmul: m*k overflows u32");
        let b_count = k.checked_mul(n).expect("matmul: k*n overflows u32");
        let out_count = m.checked_mul(n).expect("matmul: m*n overflows u32");
        let workgroup = linear_workgroup(self.options.workgroup_size.unwrap_or([256, 1, 1]));
        let generator = self.options.region_generator.unwrap_or(OP_ID);

        Ok(Program::wrapped(
            vec![
                BufferDecl::storage(self.a.name_str(), 0, BufferAccess::ReadOnly, DataType::U32)
                    .with_count(a_count),
                BufferDecl::storage(self.b.name_str(), 1, BufferAccess::ReadOnly, DataType::U32)
                    .with_count(b_count),
                BufferDecl::output(self.out.name_str(), 2, DataType::U32).with_count(out_count),
            ],
            workgroup,
            vec![wrap(generator, body, None)],
        ))
    }
}

/// Typed Cat-A builder for [`matmul_bias`].
#[derive(Debug, Clone)]
pub struct MatmulBias {
    a: TensorRef,
    b: TensorRef,
    bias: TensorRef,
    out: TensorRef,
    options: BuildOptions,
}

impl MatmulBias {
    /// Start a builder. Shapes must be `a: [m, k]`, `b: [k, n]`,
    /// `bias: [n]`, `out: [m, n]` with matching `k` and `n` dims.
    #[must_use]
    pub fn new(a: TensorRef, b: TensorRef, bias: TensorRef, out: TensorRef) -> Self {
        Self {
            a,
            b,
            bias,
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

    /// Stamp tenant id.
    #[must_use]
    pub fn with_tenant_id(mut self, tenant_id: u32) -> Self {
        self.options = self.options.with_tenant_id(tenant_id);
        self
    }

    /// Validate + materialize.
    ///
    /// # Errors
    ///
    /// Standard [`TensorRefError`] set plus shape-coherence checks:
    /// `a.shape[1] == b.shape[0]` (shared k dim),
    /// `bias.shape == [n]`,
    /// `out.shape == [a.shape[0], b.shape[1]]`.
    pub fn build(self) -> Result<Program, TensorRefError> {
        check_tensors(
            OP_ID_BIAS,
            &[
                (&self.a, DataType::U32),
                (&self.b, DataType::U32),
                (&self.bias, DataType::U32),
                (&self.out, DataType::U32),
            ],
        )?;
        if self.a.shape.len() != 2
            || self.b.shape.len() != 2
            || self.bias.shape.len() != 1
            || self.out.shape.len() != 2
        {
            return Err(TensorRefError::ShapeMismatch {
                name: "a/b/bias/out".into(),
                found: vec![],
                expected: vec![0, 0],
                op: OP_ID_BIAS,
            });
        }
        let m = self.a.shape[0];
        let k = self.a.shape[1];
        let n = self.b.shape[1];
        if self.b.shape[0] != k {
            return Err(TensorRefError::ShapeMismatch {
                name: self.b.name.as_str().to_string(),
                found: self.b.shape.to_vec(),
                expected: vec![k, n],
                op: OP_ID_BIAS,
            });
        }
        if self.bias.shape[0] != n {
            return Err(TensorRefError::ShapeMismatch {
                name: self.bias.name.as_str().to_string(),
                found: self.bias.shape.to_vec(),
                expected: vec![n],
                op: OP_ID_BIAS,
            });
        }
        if self.out.shape.as_ref() != [m, n] {
            return Err(TensorRefError::ShapeMismatch {
                name: self.out.name.as_str().to_string(),
                found: self.out.shape.to_vec(),
                expected: vec![m, n],
                op: OP_ID_BIAS,
            });
        }

        let body = matmul_bias_body(
            self.a.name_str(),
            self.b.name_str(),
            self.bias.name_str(),
            self.out.name_str(),
            k,
            n,
        );
        let a_count = m.checked_mul(k).expect("matmul_bias: m*k overflows u32");
        let b_count = k.checked_mul(n).expect("matmul_bias: k*n overflows u32");
        let bias_count = n;
        let out_count = m.checked_mul(n).expect("matmul_bias: m*n overflows u32");
        let workgroup = linear_workgroup(self.options.workgroup_size.unwrap_or([256, 1, 1]));
        let generator = self.options.region_generator.unwrap_or(OP_ID_BIAS);

        Ok(Program::wrapped(
            vec![
                BufferDecl::storage(self.a.name_str(), 0, BufferAccess::ReadOnly, DataType::U32)
                    .with_count(a_count),
                BufferDecl::storage(self.b.name_str(), 1, BufferAccess::ReadOnly, DataType::U32)
                    .with_count(b_count),
                BufferDecl::storage(
                    self.bias.name_str(),
                    2,
                    BufferAccess::ReadOnly,
                    DataType::U32,
                )
                .with_count(bias_count),
                BufferDecl::output(self.out.name_str(), 3, DataType::U32).with_count(out_count),
            ],
            workgroup,
            vec![wrap(generator, body, None)],
        ))
    }
}

const _: fn(&'static str, Vec<Node>) -> Node = wrap_anonymous;

/// Build a Program that computes `out = a @ b` where `a` is `m x k`,
/// `b` is `k x n`, and `out` is `m x n`. The caller supplies buffer
/// names + dimensions via buffer `count()` on the BufferDecls.
///
/// Each invocation computes one `out[i, j]` by iterating the `k`
/// dimension in a local loop. Workgroup size is `[256, 1, 1]` because
/// the non-tiled kernel maps row-major output cells onto a 1-D dispatch.
/// Callers with known-large matrices should use
/// `vyre-libs::math::matmul_tiled`.
#[must_use]
pub fn matmul(a: &str, b: &str, out: &str, m: u32, k: u32, n: u32) -> Program {
    Matmul::new(
        TensorRef::u32_2d(a, m, k),
        TensorRef::u32_2d(b, k, n),
        TensorRef::u32_2d(out, m, n),
    )
    .build()
    .unwrap_or_else(|err| panic!("Fix: matmul build failed: {err}"))
}

/// Build a Program that computes `out[i, j] = sum_k a[i, k] * b[k, j] + bias[j]`.
#[must_use]
pub fn matmul_bias(a: &str, b: &str, bias: &str, out: &str, m: u32, k: u32, n: u32) -> Program {
    MatmulBias::new(
        TensorRef::u32_2d(a, m, k),
        TensorRef::u32_2d(b, k, n),
        TensorRef::u32_1d(bias, n),
        TensorRef::u32_2d(out, m, n),
    )
    .build()
    .unwrap_or_else(|err| panic!("Fix: matmul_bias build failed: {err}"))
}

fn matmul_body(a: &str, b: &str, out: &str, k: u32, n: u32) -> Vec<Node> {
    // One invocation computes one row-major output slot. Keeping the
    // kernel 1-D makes dispatch geometry backend-neutral: generic wgpu
    // and the reference interpreter can derive the grid from output
    // length without separately knowing matrix rows/cols.
    let idx = Expr::var("idx");
    let row = Expr::var("row");
    let col = Expr::var("col");
    vec![
        Node::let_bind("idx", Expr::InvocationId { axis: 0 }),
        Node::let_bind("row", Expr::div(idx.clone(), Expr::u32(n))),
        Node::let_bind("col", Expr::rem(idx.clone(), Expr::u32(n))),
        Node::if_then(
            Expr::lt(idx.clone(), Expr::buf_len(out)),
            vec![
                Node::let_bind("acc", Expr::u32(0)),
                Node::loop_for(
                    "kk",
                    Expr::u32(0),
                    Expr::u32(k),
                    vec![Node::assign(
                        "acc",
                        Expr::add(
                            Expr::var("acc"),
                            Expr::mul(
                                Expr::load(
                                    a,
                                    Expr::add(
                                        Expr::mul(row.clone(), Expr::u32(k)),
                                        Expr::var("kk"),
                                    ),
                                ),
                                Expr::load(
                                    b,
                                    Expr::add(
                                        Expr::mul(Expr::var("kk"), Expr::u32(n)),
                                        col.clone(),
                                    ),
                                ),
                            ),
                        ),
                    )],
                ),
                Node::Store {
                    buffer: out.into(),
                    index: idx,
                    value: Expr::var("acc"),
                },
            ],
        ),
    ]
}

fn matmul_bias_body(a: &str, b: &str, bias: &str, out: &str, k: u32, n: u32) -> Vec<Node> {
    // One invocation computes one row-major output slot; see
    // `matmul_body` for the dispatch-geometry rationale.
    let idx = Expr::var("idx");
    let row = Expr::var("row");
    let col = Expr::var("col");
    vec![
        Node::let_bind("idx", Expr::InvocationId { axis: 0 }),
        Node::let_bind("row", Expr::div(idx.clone(), Expr::u32(n))),
        Node::let_bind("col", Expr::rem(idx.clone(), Expr::u32(n))),
        Node::if_then(
            Expr::lt(idx.clone(), Expr::buf_len(out)),
            vec![
                Node::let_bind("acc", Expr::u32(0)),
                Node::loop_for(
                    "kk",
                    Expr::u32(0),
                    Expr::u32(k),
                    vec![Node::assign(
                        "acc",
                        Expr::add(
                            Expr::var("acc"),
                            Expr::mul(
                                Expr::load(
                                    a,
                                    Expr::add(
                                        Expr::mul(row.clone(), Expr::u32(k)),
                                        Expr::var("kk"),
                                    ),
                                ),
                                Expr::load(
                                    b,
                                    Expr::add(
                                        Expr::mul(Expr::var("kk"), Expr::u32(n)),
                                        col.clone(),
                                    ),
                                ),
                            ),
                        ),
                    )],
                ),
                Node::Store {
                    buffer: out.into(),
                    index: idx,
                    value: Expr::add(Expr::var("acc"), Expr::load(bias, col)),
                },
            ],
        ),
    ]
}

fn linear_workgroup(size: [u32; 3]) -> [u32; 3] {
    [
        size[0]
            .max(1)
            .saturating_mul(size[1].max(1))
            .saturating_mul(size[2].max(1)),
        1,
        1,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_reference::value::Value;

    fn decode_u32_words(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("chunk must be aligned")))
            .collect()
    }

    fn next_u32(state: &mut u32) -> u32 {
        *state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *state
    }

    fn random_vec(size: usize, state: &mut u32) -> Vec<u32> {
        (0..size).map(|_| next_u32(state)).collect()
    }

    fn run_u32_output(program: &Program, inputs: Vec<Vec<u32>>, out_bytes: usize) -> Vec<u32> {
        let packed_inputs = inputs
            .into_iter()
            .map(|bytes| {
                Value::from(
                    bytes
                        .iter()
                        .flat_map(|v| v.to_le_bytes())
                        .collect::<Vec<u8>>(),
                )
            })
            .collect::<Vec<_>>();
        let outputs =
            vyre_reference::reference_eval(program, &packed_inputs).expect("program must execute");
        let bytes = outputs[0].to_bytes();
        let mut result = decode_u32_words(&bytes);
        assert_eq!(result.len(), out_bytes);
        result.truncate(out_bytes);
        result
    }

    #[test]
    fn matmul_bias_matches_matmul_plus_bias_on_reference_sizes() {
        let sizes = [
            (4u32, 4u32, 4u32),
            (16, 16, 16),
            (32, 64, 32),
            (64, 32, 32),
            (128, 64, 64),
        ];

        for &(m, k, n) in &sizes {
            let mut seed = m ^ (k << 8) ^ (n << 16);
            let a = random_vec((m * k) as usize, &mut seed);
            let b = random_vec((k * n) as usize, &mut seed);
            let bias = random_vec(n as usize, &mut seed);
            let out_len = (m * n) as usize;

            let fused = matmul_bias("a", "b", "bias", "out_fused", m, k, n);
            let fused_out = run_u32_output(
                &fused,
                vec![a.clone(), b.clone(), bias.clone(), vec![0u32; out_len]],
                out_len,
            );

            let plain = matmul("a", "b", "out_plain", m, k, n);
            let plain_out = run_u32_output(
                &plain,
                vec![a.clone(), b.clone(), vec![0u32; out_len]],
                out_len,
            );

            let expected: Vec<u32> = plain_out
                .iter()
                .zip(bias.iter().copied().cycle())
                .map(|(value, b)| value.wrapping_add(b))
                .collect();

            assert_eq!(
                fused_out, expected,
                "fused matmul_bias diverged for shape ({m}, {k}, {n})"
            );
        }
    }
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::math::matmul",
        build: || matmul("a", "b", "out", 4, 4, 4),
        test_inputs: Some(|| {
            let a: Vec<u32> = (0..16).collect();
            let b: Vec<u32> = (0..16).map(|i| i + 1).collect();
            let u32_bytes = |words: &[u32]| words.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                u32_bytes(&a),
                u32_bytes(&b),
                vec![0u8; 4 * 4 * 4],
            ]]
        }),
        expected_output: Some(|| {
            // 4x4 matmul over u32: a[i,j] = i*4+j, b[i,j] = i*4+j+1.
            // out[i,j] = Σ_k a[i,k] * b[k,j]. Computed row-major.
            let a: Vec<u32> = (0..16).collect();
            let b: Vec<u32> = (0..16).map(|i| i + 1).collect();
            let mut out = Vec::with_capacity(16);
            for i in 0..4 {
                for j in 0..4 {
                    let mut acc: u32 = 0;
                    for k in 0..4 {
                        acc = acc.wrapping_add(a[i * 4 + k].wrapping_mul(b[k * 4 + j]));
                    }
                    out.push(acc);
                }
            }
            let bytes = out.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![bytes]]
        }),
    }
}
