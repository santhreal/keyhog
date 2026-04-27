//! Tiled matrix multiplication with per-tile k-unrolling.
//!
//! Category-A composition. Computes `out = a @ b` where `a` is `m × k`,
//! `b` is `k × n`, `out` is `m × n`. Unlike the one-thread-per-output
//! `matmul`, this version shards the k dimension by a compile-time
//! tile width: each invocation still owns one `out[i, j]` but walks
//! the k axis in chunks of `tile` so the optimizer can unroll and
//! exploit register reuse.
//!
//! A shared-memory tile cooperation version lands with
//! `DataType::Shared`; until that ships, this keeps the Cat-A
//! correctness shape + gives the optimizer a tile-aware structural
//! hint.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::builder::{check_tensors, BuildOptions};
use crate::region::{wrap, wrap_anonymous};
use crate::tensor_ref::{TensorRef, TensorRefError};

const OP_ID: &str = "vyre-libs::math::matmul_tiled";

/// Typed Cat-A builder for [`matmul_tiled`].
#[derive(Debug, Clone)]
pub struct MatmulTiled {
    a: TensorRef,
    b: TensorRef,
    out: TensorRef,
    tile: u32,
    options: BuildOptions,
}

impl MatmulTiled {
    /// Start a builder. `tile` splits the k axis for register-reuse.
    #[must_use]
    pub fn new(a: TensorRef, b: TensorRef, out: TensorRef, tile: u32) -> Self {
        Self {
            a,
            b,
            out,
            tile,
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
    /// Same shape-coherence + name-uniqueness errors as [`super::Matmul`].
    pub fn build(self) -> Result<Program, TensorRefError> {
        check_tensors(
            OP_ID,
            &[
                (&self.a, DataType::U32),
                (&self.b, DataType::U32),
                (&self.out, DataType::U32),
            ],
        )?;
        assert!(self.tile > 0, "matmul_tiled tile width must be > 0");
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
        let program = matmul_tiled_program(
            self.a.name_str(),
            self.b.name_str(),
            self.out.name_str(),
            m,
            k,
            n,
            self.tile,
            self.options.workgroup_size.unwrap_or([16, 16, 1]),
            self.options.region_generator.unwrap_or(OP_ID),
        );
        Ok(program)
    }
}

const _: fn(&'static str, Vec<Node>) -> Node = wrap_anonymous;

/// Back-compat wrapper; panics on contract violation.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn matmul_tiled(a: &str, b: &str, out: &str, m: u32, k: u32, n: u32, tile: u32) -> Program {
    MatmulTiled::new(
        TensorRef::u32_2d(a, m, k),
        TensorRef::u32_2d(b, k, n),
        TensorRef::u32_2d(out, m, n),
        tile,
    )
    .build()
    .unwrap_or_else(|err| panic!("Fix: matmul_tiled build failed: {err}"))
}

#[allow(clippy::too_many_arguments)]
fn matmul_tiled_program(
    a: &str,
    b: &str,
    out: &str,
    m: u32,
    k: u32,
    n: u32,
    tile: u32,
    workgroup: [u32; 3],
    generator: &'static str,
) -> Program {
    assert!(tile > 0, "matmul_tiled tile width must be > 0");
    let tile_count = k.div_ceil(tile);
    let a_count = m.checked_mul(k).expect("matmul_tiled: m*k overflows u32");
    let b_count = k.checked_mul(n).expect("matmul_tiled: k*n overflows u32");
    let out_count = m.checked_mul(n).expect("matmul_tiled: m*n overflows u32");

    let body = vec![
        Node::let_bind("row", Expr::InvocationId { axis: 1 }),
        Node::let_bind("col", Expr::InvocationId { axis: 0 }),
        Node::let_bind(
            "out_index",
            Expr::add(Expr::mul(Expr::var("row"), Expr::u32(n)), Expr::var("col")),
        ),
        // V7-CORR-004: guard BOTH `col < n` and `out_index < buf_len(out)`.
        // Without the `col < n` check, an overshoot workgroup with
        // (row=0, col>=n) passes the index check, computes a wrong dot
        // product, and races with (row=1, col=col-n) for the same slot.
        Node::if_then(
            Expr::and(
                Expr::lt(Expr::var("col"), Expr::u32(n)),
                Expr::lt(Expr::var("out_index"), Expr::buf_len(out)),
            ),
            vec![
                Node::let_bind("acc", Expr::u32(0)),
                Node::loop_for(
                    "tile_idx",
                    Expr::u32(0),
                    Expr::u32(tile_count),
                    vec![
                        Node::let_bind(
                            "tile_base",
                            Expr::mul(Expr::var("tile_idx"), Expr::u32(tile)),
                        ),
                        Node::loop_for(
                            "tile_k",
                            Expr::u32(0),
                            Expr::u32(tile),
                            vec![
                                Node::let_bind(
                                    "kk",
                                    Expr::add(Expr::var("tile_base"), Expr::var("tile_k")),
                                ),
                                // Guard the partial tile at the tail end
                                // of k (when k is not a multiple of tile).
                                Node::if_then(
                                    Expr::lt(Expr::var("kk"), Expr::u32(k)),
                                    vec![Node::assign(
                                        "acc",
                                        Expr::add(
                                            Expr::var("acc"),
                                            Expr::mul(
                                                Expr::load(
                                                    a,
                                                    Expr::add(
                                                        Expr::mul(Expr::var("row"), Expr::u32(k)),
                                                        Expr::var("kk"),
                                                    ),
                                                ),
                                                Expr::load(
                                                    b,
                                                    Expr::add(
                                                        Expr::mul(Expr::var("kk"), Expr::u32(n)),
                                                        Expr::var("col"),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    )],
                                ),
                            ],
                        ),
                    ],
                ),
                Node::Store {
                    buffer: out.into(),
                    index: Expr::var("out_index"),
                    value: Expr::var("acc"),
                },
            ],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(a, 0, BufferAccess::ReadOnly, DataType::U32).with_count(a_count),
            BufferDecl::storage(b, 1, BufferAccess::ReadOnly, DataType::U32).with_count(b_count),
            BufferDecl::output(out, 2, DataType::U32).with_count(out_count),
        ],
        workgroup,
        vec![wrap(generator, body, None)],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::math::matmul_tiled",
        build: || matmul_tiled("a", "b", "out", 2, 2, 2, 2),
        // V7-TEST-001: deterministic fixture — 2x2 * 2x2 = 2x2.
        //   A = [[1, 2], [3, 4]], B = [[5, 6], [7, 8]]
        //   out[row*2+col] = sum_k A[row*2+k] * B[k*2+col]
        //   out[0] = 1*5 + 2*7 = 19
        //   out[1] = 1*6 + 2*8 = 22
        //   out[2] = 3*5 + 4*7 = 43
        //   out[3] = 3*6 + 4*8 = 50
        test_inputs: Some(|| {
            let u32_bytes = |w: &[u32]| w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                u32_bytes(&[1, 2, 3, 4]),
                u32_bytes(&[5, 6, 7, 8]),
                vec![0u8; 4 * 4],
            ]]
        }),
        expected_output: Some(|| {
            let u32_bytes = |w: &[u32]| w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![u32_bytes(&[19, 22, 43, 50])]]
        }),
    }
}
