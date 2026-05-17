//! Bias-fused cooperative tiled matmul builder + Cat-A wrapper.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Program};
use vyre_foundation::ir::model::expr::GeneratorRef;
use vyre_primitives::math::semiring_gemm::OP_ID as SEMIRING_GEMM_OP_ID;

use crate::builder::{check_tensors, BuildOptions};
use crate::region::{wrap, wrap_child};
use crate::tensor_ref::{TensorRef, TensorRefError};

use super::body::cooperative_matmul_body;
use super::shape::{output_tile_shape, padded_tile_lane_count, MatrixShape, TileShape};

const OP_ID_BIAS: &str = "vyre-libs::math::matmul_bias_tiled";

/// Typed Cat-A builder for [`matmul_bias_tiled`].
#[derive(Debug, Clone)]
pub struct MatmulBiasTiled {
    a: TensorRef,
    b: TensorRef,
    bias: TensorRef,
    out: TensorRef,
    tile: u32,
    options: BuildOptions,
}

impl MatmulBiasTiled {
    /// Start a builder. `tile` splits the k axis for register-reuse.
    #[must_use]
    pub fn new(a: TensorRef, b: TensorRef, bias: TensorRef, out: TensorRef, tile: u32) -> Self {
        Self {
            a,
            b,
            bias,
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
    /// Same shape-coherence + name-uniqueness errors as [`super::super::MatmulBias`].
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
        if self.tile == 0 {
            return Err(TensorRefError::ShapeMismatch {
                name: "tile".into(),
                found: vec![0],
                expected: vec![1],
                op: OP_ID_BIAS,
            });
        }
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
        let program = matmul_bias_tiled_program(
            self.a.name_str(),
            self.b.name_str(),
            self.bias.name_str(),
            self.out.name_str(),
            m,
            k,
            n,
            self.tile,
            self.options.workgroup_size.unwrap_or([16, 16, 1]),
            self.options.region_generator.unwrap_or(OP_ID_BIAS),
        )?;
        Ok(program)
    }
}

/// Back-compat wrapper; panics on contract violation.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn matmul_bias_tiled(
    a: &str,
    b: &str,
    bias: &str,
    out: &str,
    m: u32,
    k: u32,
    n: u32,
    tile: u32,
) -> Program {
    MatmulBiasTiled::new(
        TensorRef::u32_2d(a, m, k),
        TensorRef::u32_2d(b, k, n),
        TensorRef::u32_1d(bias, n),
        TensorRef::u32_2d(out, m, n),
        tile,
    )
    .build()
    .unwrap_or_else(|err| {
        crate::builder::invalid_output_program(
            OP_ID_BIAS,
            out,
            DataType::U32,
            format!("Fix: {err}"),
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn matmul_bias_tiled_program(
    a: &str,
    b: &str,
    bias: &str,
    out: &str,
    m: u32,
    k: u32,
    n: u32,
    tile: u32,
    workgroup: [u32; 3],
    generator: &'static str,
) -> Result<Program, TensorRefError> {
    if tile == 0 {
        return Err(TensorRefError::ShapeMismatch {
            name: "tile".into(),
            found: vec![0],
            expected: vec![1],
            op: OP_ID_BIAS,
        });
    }
    let (out_tile_cols, out_tile_rows, lane_count) = output_tile_shape(workgroup)?;
    let a_tile_count =
        out_tile_rows
            .checked_mul(tile)
            .ok_or_else(|| TensorRefError::ElementCountOverflow {
                name: "matmul_bias_a_tile".to_string(),
                shape: vec![out_tile_rows, tile],
            })?;
    let b_tile_count =
        tile.checked_mul(out_tile_cols)
            .ok_or_else(|| TensorRefError::ElementCountOverflow {
                name: "matmul_bias_b_tile".to_string(),
                shape: vec![tile, out_tile_cols],
            })?;
    let a_count = m
        .checked_mul(k)
        .ok_or_else(|| TensorRefError::ElementCountOverflow {
            name: a.to_string(),
            shape: vec![m, k],
        })?;
    let b_count = k
        .checked_mul(n)
        .ok_or_else(|| TensorRefError::ElementCountOverflow {
            name: b.to_string(),
            shape: vec![k, n],
        })?;
    let out_count = m
        .checked_mul(n)
        .ok_or_else(|| TensorRefError::ElementCountOverflow {
            name: out.to_string(),
            shape: vec![m, n],
        })?;
    let padded_out_count = padded_tile_lane_count(m, n, out_tile_rows, out_tile_cols, lane_count)?;

    let body = vec![wrap_child(
        SEMIRING_GEMM_OP_ID,
        GeneratorRef {
            name: generator.to_string(),
        },
        cooperative_matmul_body(
            a,
            b,
            Some(bias),
            out,
            MatrixShape { m, k, n },
            TileShape {
                k_tile: tile,
                out_rows: out_tile_rows,
                out_cols: out_tile_cols,
                lanes: lane_count,
                a_values: a_tile_count,
                b_values: b_tile_count,
            },
        ),
    )];

    Ok(Program::wrapped(
        vec![
            BufferDecl::storage(a, 0, BufferAccess::ReadOnly, DataType::U32).with_count(a_count),
            BufferDecl::storage(b, 1, BufferAccess::ReadOnly, DataType::U32).with_count(b_count),
            BufferDecl::storage(bias, 2, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::workgroup("matmul_a_tile", a_tile_count, DataType::U32),
            BufferDecl::workgroup("matmul_b_tile", b_tile_count, DataType::U32),
            BufferDecl::output(out, 3, DataType::U32)
                .with_count(padded_out_count)
                .with_output_byte_range(0..((out_count as usize) * core::mem::size_of::<u32>())),
        ],
        [lane_count, 1, 1],
        vec![wrap(generator, body, None)],
    ))
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::math::matmul_bias_tiled",
        build: || matmul_bias_tiled("a", "b", "bias", "out", 2, 2, 2, 2),
        test_inputs: Some(|| {

            vec![vec![
                crate::test_support::byte_pack::u32_bytes(&[1, 2, 3, 4]),
                crate::test_support::byte_pack::u32_bytes(&[5, 6, 7, 8]),
                crate::test_support::byte_pack::u32_bytes(&[10, 20]),
                vec![0u8; 4 * 4],
            ]]
        }),
        expected_output: Some(|| {

            // out[0] = 19 + 10 = 29
            // out[1] = 22 + 20 = 42
            // out[2] = 43 + 10 = 53
            // out[3] = 50 + 20 = 70
            vec![vec![crate::test_support::byte_pack::u32_bytes(&[29, 42, 53, 70])]]
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_reference::value::Value;

    fn decode_u32_words(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks_exact(core::mem::size_of::<u32>())
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect()
    }

    fn output_zero_bytes(program: &Program) -> Vec<u8> {
        let output = program
            .buffers()
            .iter()
            .find(|buffer| buffer.is_output())
            .expect("Fix: tiled matmul test program must declare an output buffer.");
        vec![0u8; (output.count() as usize) * core::mem::size_of::<u32>()]
    }

    fn run_program(program: &Program, inputs: Vec<Vec<u8>>) -> Vec<u32> {
        let values = inputs.into_iter().map(Value::from).collect::<Vec<_>>();
        let outputs = vyre_reference::reference_eval(program, &values)
            .expect("Fix: tiled matmul must execute in the reference interpreter.");
        decode_u32_words(&outputs[0].to_bytes())
    }

    fn expected_bias_matmul(
        a: &[u32],
        b: &[u32],
        bias: &[u32],
        m: u32,
        k: u32,
        n: u32,
    ) -> Vec<u32> {
        let mut out = Vec::with_capacity((m * n) as usize);
        for row in 0..m {
            for col in 0..n {
                let mut acc = bias[col as usize];
                for kk in 0..k {
                    let av = a[(row * k + kk) as usize];
                    let bv = b[(kk * n + col) as usize];
                    acc = acc.wrapping_add(av.wrapping_mul(bv));
                }
                out.push(acc);
            }
        }
        out
    }

    fn pseudo_random_words(count: usize, seed: &mut u32) -> Vec<u32> {
        (0..count)
            .map(|_| {
                *seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *seed
            })
            .collect()
    }

    #[test]
    fn matmul_bias_tiled_rejects_zero_tile_without_panic() {
        let error = MatmulBiasTiled::new(
            TensorRef::u32_2d("a", 2, 2),
            TensorRef::u32_2d("b", 2, 2),
            TensorRef::u32_1d("bias", 2),
            TensorRef::u32_2d("out", 2, 2),
            0,
        )
        .build()
        .expect_err("zero tile must be a build error");

        assert!(
            error.to_string().contains("tile"),
            "zero-tile bias error must identify the invalid tile dimension: {error}"
        );
    }

    #[test]
    fn cooperative_matmul_bias_tiled_matches_reference_on_edge_tiles() {
        let (m, k, n, tile) = (17_u32, 19_u32, 13_u32, 8_u32);
        let mut seed = 0x5A5A_0717;
        let a = pseudo_random_words((m * k) as usize, &mut seed);
        let b = pseudo_random_words((k * n) as usize, &mut seed);
        let bias = pseudo_random_words(n as usize, &mut seed);
        let program = MatmulBiasTiled::new(
            TensorRef::u32_2d("a", m, k),
            TensorRef::u32_2d("b", k, n),
            TensorRef::u32_1d("bias", n),
            TensorRef::u32_2d("out", m, n),
            tile,
        )
        .with_workgroup_size([8, 8, 1])
        .build()
        .expect("Fix: edge-tiled matmul+bias dimensions are valid.");

        let actual = run_program(
            &program,
            vec![
                crate::test_support::byte_pack::u32_bytes(&a),
                crate::test_support::byte_pack::u32_bytes(&b),
                crate::test_support::byte_pack::u32_bytes(&bias),
                output_zero_bytes(&program),
            ],
        );
        assert_eq!(actual, expected_bias_matmul(&a, &b, &bias, m, k, n));
    }
}
