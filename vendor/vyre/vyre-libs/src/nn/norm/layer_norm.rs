//! Layer normalization — `y_i = (x_i - mean(x)) / sqrt(var(x) + eps)`.
//!
//! Category-A composition over `BinOp::Sub/Div/Mul/Add`, `UnOp::Sqrt`.
//! Two sequential reductions (mean then variance) plus a pointwise
//! write, same three-pass shape as `softmax`. Tiled-parallel variant
//! lands with `nn::attention`; this module is the correctness oracle.
//!
//! ## API surface
//!
//! - [`LayerNorm`] — typed builder with [`TensorRef`]-accepting
//!   inputs and contract checks at [`LayerNorm::build`] time.
//! - [`layer_norm`] — back-compat free function.
//!
//! Both paths emit byte-identical IR.

use vyre::ir::{BinOp, BufferAccess, BufferDecl, DataType, Expr, Node, Program, UnOp};

use crate::builder::{check_tensors, BuildOptions};
use crate::region::wrap;
use crate::tensor_ref::{TensorRef, TensorRefError};

const OP_ID: &str = "vyre-libs::nn::layer_norm";

/// Typed Cat-A builder for [`layer_norm`].
#[derive(Debug, Clone)]
pub struct LayerNorm {
    input: TensorRef,
    output: TensorRef,
    eps: f32,
    options: BuildOptions,
}

impl LayerNorm {
    /// Start a builder. `eps` is the numerical-stability constant
    /// added under the sqrt to guard against zero variance.
    #[must_use]
    pub fn new(input: TensorRef, output: TensorRef, eps: f32) -> Self {
        Self {
            input,
            output,
            eps,
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
    /// Surfaces the standard [`TensorRefError`] set (dtype, shape,
    /// name-collision, overflow).
    pub fn build(self) -> Result<Program, TensorRefError> {
        check_tensors(
            OP_ID,
            &[(&self.input, DataType::F32), (&self.output, DataType::F32)],
        )?;
        if self.input.shape != self.output.shape {
            return Err(TensorRefError::ShapeMismatch {
                name: self.output.name.as_str().to_string(),
                found: self.output.shape.to_vec(),
                expected: self.input.shape.to_vec(),
                op: OP_ID,
            });
        }
        // V7-CORR-008: reject negative or NaN eps so sqrt(var + eps) never
        // poisons the output with NaN. Positive zero is allowed (the
        // caller accepts exact-divide-by-zero risk on zero-variance input).
        if self.eps < 0.0 || self.eps.is_nan() {
            return Err(TensorRefError::ShapeMismatch {
                name: "eps".to_string(),
                found: Vec::new(),
                expected: Vec::new(),
                op: OP_ID,
            });
        }
        let n = self
            .input
            .element_count()
            .expect("element_count checked above");
        // V7-CORR-012/013 parallel: reject n=0 so the first `Expr::load(input, 0)`
        // is not out-of-bounds.
        if n == 0 {
            return Err(TensorRefError::ShapeMismatch {
                name: self.input.name.as_str().to_string(),
                found: self.input.shape.to_vec(),
                expected: vec![1],
                op: OP_ID,
            });
        }
        let input_name = self.input.name_str();
        let output_name = self.output.name_str();

        let n_expr = Expr::u32(n);
        let n_f32 = Expr::f32(n as f32);

        let sum_loop = Node::loop_for(
            "i",
            Expr::u32(0),
            n_expr.clone(),
            vec![Node::assign(
                "sum_val",
                Expr::add(Expr::var("sum_val"), Expr::load(input_name, Expr::var("i"))),
            )],
        );

        let var_loop = Node::loop_for(
            "i",
            Expr::u32(0),
            n_expr.clone(),
            vec![
                Node::let_bind(
                    "centered",
                    Expr::BinOp {
                        op: BinOp::Sub,
                        left: Box::new(Expr::load(input_name, Expr::var("i"))),
                        right: Box::new(Expr::var("mean")),
                    },
                ),
                Node::assign(
                    "var_sum",
                    Expr::add(
                        Expr::var("var_sum"),
                        Expr::mul(Expr::var("centered"), Expr::var("centered")),
                    ),
                ),
            ],
        );

        let write_loop = Node::loop_for(
            "i",
            Expr::u32(0),
            n_expr,
            vec![Node::Store {
                buffer: output_name.into(),
                index: Expr::var("i"),
                value: Expr::BinOp {
                    op: BinOp::Div,
                    left: Box::new(Expr::BinOp {
                        op: BinOp::Sub,
                        left: Box::new(Expr::load(input_name, Expr::var("i"))),
                        right: Box::new(Expr::var("mean")),
                    }),
                    right: Box::new(Expr::var("inv_denom")),
                },
            }],
        );

        let body = vec![
            Node::let_bind("sum_val", Expr::f32(0.0)),
            sum_loop,
            Node::let_bind(
                "mean",
                Expr::BinOp {
                    op: BinOp::Div,
                    left: Box::new(Expr::var("sum_val")),
                    right: Box::new(n_f32.clone()),
                },
            ),
            Node::let_bind("var_sum", Expr::f32(0.0)),
            var_loop,
            Node::let_bind(
                "variance",
                Expr::BinOp {
                    op: BinOp::Div,
                    left: Box::new(Expr::var("var_sum")),
                    right: Box::new(n_f32),
                },
            ),
            Node::let_bind(
                "inv_denom",
                Expr::UnOp {
                    op: UnOp::Sqrt,
                    operand: Box::new(Expr::add(Expr::var("variance"), Expr::f32(self.eps))),
                },
            ),
            write_loop,
        ];

        let workgroup = self.options.workgroup_size.unwrap_or([1, 1, 1]);
        let generator = self.options.region_generator.unwrap_or(OP_ID);

        Ok(Program::wrapped(
            vec![
                BufferDecl::storage(input_name, 0, BufferAccess::ReadOnly, DataType::F32)
                    .with_count(n),
                BufferDecl::output(output_name, 1, DataType::F32).with_count(n),
            ],
            workgroup,
            vec![wrap(generator, body, None)],
        ))
    }
}

/// Build a Program that layer-normalizes `input` into `output` across
/// `n` F32 elements. Back-compat wrapper around [`LayerNorm`]; panics
/// on contract violation.
#[must_use]
pub fn layer_norm(input: &str, output: &str, n: u32, eps: f32) -> Program {
    LayerNorm::new(
        TensorRef::f32_1d(input, n),
        TensorRef::f32_1d(output, n),
        eps,
    )
    .build()
    .unwrap_or_else(|err| panic!("Fix: layer_norm build failed: {err}"))
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::nn::layer_norm",
        build: || layer_norm("input", "output", 4, 1e-5),
        test_inputs: Some(|| {
            let input = [1.5f32, -2.0, 0.25, 3.75];
            vec![vec![
                input.iter().flat_map(|value| value.to_le_bytes()).collect(),
                vec![0u8; input.len() * core::mem::size_of::<f32>()],
            ]]
        }),
        expected_output: Some(|| vec![
            vec![
                vec![0xb9, 0xd0, 0x99, 0x3e, 0x3b, 0xe3, 0xb0, 0xbf, 0xb9, 0xd0, 0x99, 0xbe, 0x3b, 0xe3, 0xb0, 0x3f, ],
            ],
        ]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_rejects_dtype_mismatch() {
        let err = LayerNorm::new(
            TensorRef::u32_1d("in", 4),
            TensorRef::f32_1d("out", 4),
            1e-5,
        )
        .build()
        .unwrap_err();
        assert!(matches!(err, TensorRefError::DtypeMismatch { .. }));
    }

    #[test]
    fn builder_rejects_shape_mismatch() {
        let err = LayerNorm::new(
            TensorRef::f32_1d("in", 4),
            TensorRef::f32_1d("out", 8),
            1e-5,
        )
        .build()
        .unwrap_err();
        assert!(matches!(err, TensorRefError::ShapeMismatch { .. }));
    }

    #[test]
    fn free_function_and_builder_produce_equal_programs_by_default() {
        let free = layer_norm("in", "out", 4, 1e-5);
        let built = LayerNorm::new(
            TensorRef::f32_1d("in", 4),
            TensorRef::f32_1d("out", 4),
            1e-5,
        )
        .build()
        .unwrap();
        assert_eq!(
            free.to_wire().unwrap(),
            built.to_wire().unwrap(),
            "free `layer_norm` and builder `LayerNorm::build` must be byte-identical"
        );
    }
}
