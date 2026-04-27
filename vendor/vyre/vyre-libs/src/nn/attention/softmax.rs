//! Softmax — `softmax(x)_i = exp(x_i - max(x)) / sum(exp(x_j - max(x)))`.
//!
//! Category-A composition over `BinOp::Sub/Div`, `UnOp::Exp`, and
//! `Expr::max`. The numerically-stable formulation subtracts the max
//! before exponentiating so the sum stays in `[1.0, n]` regardless of
//! the input magnitude.
//!
//! Shape: single-workgroup sequential reduction (three passes — max,
//! sum-of-exp, divide). For production workloads a tiled-parallel
//! softmax is wired through `nn::attention`; this module is the
//! Category-A correctness reference the tiled version must match.
//!
//! ## API surface
//!
//! - [`Softmax`] — typed builder. Accepts [`TensorRef`]s, checks dtype +
//!   shape + name-uniqueness at [`Softmax::build`] time, returns
//!   [`TensorRefError`] on contract violation.
//! - [`softmax`] — back-compat free function. Calls the builder with
//!   default options; panics on contract violation so legacy callers
//!   see the same behavior.
//!
//! Both paths produce the same IR. New code should prefer the builder.

use vyre::ir::{BinOp, BufferAccess, BufferDecl, DataType, Expr, Node, Program, UnOp};

use crate::builder::{check_tensors, BuildOptions};
use crate::region::{wrap, wrap_anonymous};
use crate::tensor_ref::{TensorRef, TensorRefError};

/// Canonical op id; matches the region generator name so conformance
/// certificates stay self-describing.
const OP_ID: &str = "vyre-libs::nn::softmax";

/// Typed Cat-A builder for [`softmax`]. Future knobs (workgroup size,
/// region generator override, tenant id) land as [`BuildOptions`]
/// chains without changing the builder's method surface.
#[derive(Debug, Clone)]
pub struct Softmax {
    input: TensorRef,
    output: TensorRef,
    options: BuildOptions,
}

impl Softmax {
    /// Start a builder with the two required tensors. Use chaining
    /// methods for optional overrides.
    #[must_use]
    pub fn new(input: TensorRef, output: TensorRef) -> Self {
        Self {
            input,
            output,
            options: BuildOptions::default(),
        }
    }

    /// Override [`BuildOptions::workgroup_size`]. Most callers leave
    /// this at the canonical `[1, 1, 1]` — the sequential reduction
    /// doesn't benefit from parallel lanes without workgroup-shared
    /// memory (landing with the sparse/quant extensions).
    #[must_use]
    pub fn with_workgroup_size(mut self, size: [u32; 3]) -> Self {
        self.options = self.options.with_workgroup_size(size);
        self
    }

    /// Override the region generator name. Leave the default unless
    /// the caller wraps this composition inside a larger op and
    /// wants its own generator id in conformance certificates.
    #[must_use]
    pub fn with_region_generator(mut self, name: &'static str) -> Self {
        self.options = self.options.with_region_generator(name);
        self
    }

    /// Stamp the region metadata with a tenant id routed through the
    /// megakernel's tenant-mask table.
    #[must_use]
    pub fn with_tenant_id(mut self, tenant_id: u32) -> Self {
        self.options = self.options.with_tenant_id(tenant_id);
        self
    }

    /// Validate + materialize the Program.
    ///
    /// # Errors
    ///
    /// - [`TensorRefError::DtypeMismatch`] if either tensor isn't `F32`.
    /// - [`TensorRefError::ShapeMismatch`] if `input` and `output`
    ///   shapes diverge (both must be 1-D with matching length).
    /// - [`TensorRefError::NameCollision`] if input and output
    ///   resolve to the same buffer name.
    /// - [`TensorRefError::ElementCountOverflow`] on pathological
    ///   shapes whose product exceeds `u32::MAX`.
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
        let n = self
            .input
            .element_count()
            .expect("element_count checked above");
        // V7-CORR-012: reject n=0 so the first Expr::load(input, 0)
        // sentinel is not an out-of-bounds read. softmax(∅) is
        // undefined; the builder surfaces the error explicitly.
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

        // -- Pass 1: max = max over input[0..n] (sentinel = input[0]).
        let max_loop = Node::loop_for(
            "i",
            Expr::u32(1),
            n_expr.clone(),
            vec![Node::assign(
                "max_val",
                Expr::select(
                    Expr::BinOp {
                        op: BinOp::Gt,
                        left: Box::new(Expr::load(input_name, Expr::var("i"))),
                        right: Box::new(Expr::var("max_val")),
                    },
                    Expr::load(input_name, Expr::var("i")),
                    Expr::var("max_val"),
                ),
            )],
        );

        // -- Pass 2: sum = sum of exp(x_i - max) over input[0..n].
        let sum_loop = Node::loop_for(
            "i",
            Expr::u32(0),
            n_expr.clone(),
            vec![Node::assign(
                "sum_val",
                Expr::add(
                    Expr::var("sum_val"),
                    Expr::UnOp {
                        op: UnOp::Exp,
                        operand: Box::new(Expr::BinOp {
                            op: BinOp::Sub,
                            left: Box::new(Expr::load(input_name, Expr::var("i"))),
                            right: Box::new(Expr::var("max_val")),
                        }),
                    },
                ),
            )],
        );

        // -- Pass 3: output[i] = exp(x_i - max) / sum.
        let write_loop = Node::loop_for(
            "i",
            Expr::u32(0),
            n_expr,
            vec![Node::Store {
                buffer: output_name.into(),
                index: Expr::var("i"),
                value: Expr::BinOp {
                    op: BinOp::Div,
                    left: Box::new(Expr::UnOp {
                        op: UnOp::Exp,
                        operand: Box::new(Expr::BinOp {
                            op: BinOp::Sub,
                            left: Box::new(Expr::load(input_name, Expr::var("i"))),
                            right: Box::new(Expr::var("max_val")),
                        }),
                    }),
                    right: Box::new(Expr::var("sum_val")),
                },
            }],
        );

        let body = vec![
            Node::let_bind("max_val", Expr::load(input_name, Expr::u32(0))),
            max_loop,
            Node::let_bind("sum_val", Expr::f32(0.0)),
            sum_loop,
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

/// Build a softmax Program from raw buffer names. Back-compat wrapper
/// around [`Softmax`]; panics on contract violation. New code should
/// prefer the builder.
#[must_use]
pub fn softmax(input: &str, output: &str, n: u32) -> Program {
    Softmax::new(TensorRef::f32_1d(input, n), TensorRef::f32_1d(output, n))
        .build()
        .unwrap_or_else(|err| panic!("Fix: softmax build failed: {err}"))
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::nn::softmax",
        build: || softmax("input", "output", 4),
        test_inputs: Some(|| {
            let input = [0.5f32, -1.0, 1.5, 0.25];
            vec![vec![
                input.iter().flat_map(|value| value.to_le_bytes()).collect(),
                vec![0u8; input.len() * core::mem::size_of::<f32>()],
            ]]
        }),
        expected_output: Some(|| vec![
            vec![
                vec![0x7b, 0xf0, 0x58, 0x3e, 0x74, 0x9f, 0x41, 0x3d, 0xf3, 0x6c, 0x13, 0x3f, 0xdb, 0xf3, 0x28, 0x3e, ],
            ],
        ]),
    }
}

// Keep the bare wrap_anonymous import live so future builder
// overloads that want the anonymous generator can reach it without
// a re-import.
const _: fn(&'static str, Vec<Node>) -> Node = wrap_anonymous;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_rejects_dtype_mismatch() {
        let err = Softmax::new(TensorRef::u32_1d("in", 4), TensorRef::f32_1d("out", 4))
            .build()
            .unwrap_err();
        assert!(matches!(err, TensorRefError::DtypeMismatch { .. }));
    }

    #[test]
    fn builder_rejects_shape_mismatch() {
        let err = Softmax::new(TensorRef::f32_1d("in", 4), TensorRef::f32_1d("out", 8))
            .build()
            .unwrap_err();
        assert!(matches!(err, TensorRefError::ShapeMismatch { .. }));
    }

    #[test]
    fn builder_rejects_name_collision() {
        let err = Softmax::new(TensorRef::f32_1d("x", 4), TensorRef::f32_1d("x", 4))
            .build()
            .unwrap_err();
        assert!(matches!(err, TensorRefError::NameCollision { .. }));
    }

    #[test]
    fn builder_workgroup_override_lands_in_program() {
        let program = Softmax::new(TensorRef::f32_1d("in", 4), TensorRef::f32_1d("out", 4))
            .with_workgroup_size([64, 1, 1])
            .build()
            .unwrap();
        assert_eq!(program.workgroup_size(), [64, 1, 1]);
    }

    #[test]
    fn builder_region_generator_override_lands_in_program() {
        let program = Softmax::new(TensorRef::f32_1d("in", 4), TensorRef::f32_1d("out", 4))
            .with_region_generator("custom::softmax")
            .build()
            .unwrap();
        match &program.entry()[0] {
            Node::Region { generator, .. } => {
                assert_eq!(generator.as_str(), "custom::softmax");
            }
            other => panic!("expected Region, got {other:?}"),
        }
    }

    #[test]
    fn free_function_and_builder_produce_equal_programs_by_default() {
        let free = softmax("in", "out", 4);
        let built = Softmax::new(TensorRef::f32_1d("in", 4), TensorRef::f32_1d("out", 4))
            .build()
            .unwrap();
        // to_wire is the canonical byte-identity gate — a divergence
        // between the two paths is a refactor regression.
        let free_bytes = free.to_wire().unwrap();
        let built_bytes = built.to_wire().unwrap();
        assert_eq!(
            free_bytes, built_bytes,
            "free `softmax` and builder `Softmax::build` must yield byte-identical wire output"
        );
    }
}
