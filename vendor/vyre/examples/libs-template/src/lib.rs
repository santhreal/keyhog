//! {{crate_name}} — a community Category-A op dialect.
//!
//! Generated from the `vyre-libs-template` scaffold. Follow
//! `AUTHORING.md` in the `vyre-libs` repo for the 5-step recipe.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use vyre_libs::prelude::*;

const OP_ID: &str = "{{crate_name}}::example_op";

/// Typed Cat-A builder for `example_op`.
///
/// `example_op` is a trivial `output[i] = input[i] + 1` composition —
/// replace with your actual logic.
#[derive(Debug, Clone)]
pub struct ExampleOp {
    input: TensorRef,
    output: TensorRef,
    options: BuildOptions,
}

impl ExampleOp {
    /// Start a builder. Input and output must share shape + u32 dtype.
    #[must_use]
    pub fn new(input: TensorRef, output: TensorRef) -> Self {
        Self {
            input,
            output,
            options: BuildOptions::default(),
        }
    }

    /// Override workgroup size.
    #[must_use]
    pub fn with_workgroup_size(mut self, size: [u32; 3]) -> Self {
        self.options = self.options.with_workgroup_size(size);
        self
    }

    /// Override region generator.
    #[must_use]
    pub fn with_region_generator(mut self, name: &'static str) -> Self {
        self.options = self.options.with_region_generator(name);
        self
    }

    /// Validate + build.
    ///
    /// # Errors
    ///
    /// Standard [`TensorRefError`] set.
    pub fn build(self) -> Result<Program, TensorRefError> {
        check_tensors(
            OP_ID,
            &[(&self.input, DataType::U32), (&self.output, DataType::U32)],
        )?;
        if self.input.shape != self.output.shape {
            return Err(TensorRefError::ShapeMismatch {
                name: self.output.name.as_str().to_string(),
                found: self.output.shape.clone(),
                expected: self.input.shape.clone(),
                op: OP_ID,
            });
        }
        let n = self.input.element_count().expect("checked above");
        let input_name = self.input.name_str();
        let output_name = self.output.name_str();

        let i = Expr::var("i");
        let body = vec![
            Node::let_bind("i", Expr::InvocationId { axis: 0 }),
            Node::if_then(
                Expr::lt(i.clone(), Expr::buf_len(input_name)),
                vec![Node::Store {
                    buffer: output_name.into(),
                    index: i.clone(),
                    value: Expr::add(Expr::load(input_name, i), Expr::u32(1)),
                }],
            ),
        ];

        let workgroup = self.options.workgroup_size.unwrap_or([64, 1, 1]);
        let generator = self.options.region_generator.unwrap_or(OP_ID);

        Ok(Program::wrapped(
            vec![
                BufferDecl::storage(input_name, 0, BufferAccess::ReadOnly, DataType::U32)
                    .with_count(n),
                BufferDecl::storage(output_name, 1, BufferAccess::ReadWrite, DataType::U32)
                    .with_count(n),
            ],
            workgroup,
            vec![wrap(generator, body, None)],
        ))
    }
}

/// Back-compat free function. Panics on contract violation.
#[must_use]
pub fn example_op(input: &str, output: &str, n: u32) -> Program {
    ExampleOp::new(TensorRef::u32_1d(input, n), TensorRef::u32_1d(output, n))
        .build()
        .unwrap_or_else(|err| panic!("Fix: example_op build failed: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_rejects_shape_mismatch() {
        let err = ExampleOp::new(TensorRef::u32_1d("a", 4), TensorRef::u32_1d("b", 8))
            .build()
            .unwrap_err();
        assert!(matches!(err, TensorRefError::ShapeMismatch { .. }));
    }

    #[test]
    fn free_and_builder_are_byte_identical() {
        let free = example_op("a", "b", 4);
        let built = ExampleOp::new(TensorRef::u32_1d("a", 4), TensorRef::u32_1d("b", 4))
            .build()
            .unwrap();
        assert_eq!(free.to_wire().unwrap(), built.to_wire().unwrap());
    }
}
