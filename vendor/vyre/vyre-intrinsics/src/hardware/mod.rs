//! Cat-C hardware intrinsics — each ships a builder, CPU reference
//! (in `vyre-reference`), and dedicated Naga emitter arm. Backends
//! that cannot lower return `UnsupportedByBackend` rather than
//! falling back to slow CPU paths.

use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// `bit_reverse_u32` — reverses every bit in each u32 lane via hardware `reverseBits`.
pub mod bit_reverse_u32;
/// `fma_f32` — IEEE-754 fused multiply-add (byte-identical to `f32::mul_add`).
pub mod fma_f32;
/// `inverse_sqrt_f32` — hardware `inverseSqrt()` approximation.
pub mod inverse_sqrt_f32;
/// `popcount_u32` — hardware `countOneBits` on each u32 lane.
pub mod popcount_u32;
/// `storage_barrier` — cross-workgroup storage-buffer memory fence.
pub mod storage_barrier;
/// `subgroup_add` — wave-level reduction over the subgroup (feature-gated on `subgroup-ops`).
pub mod subgroup_add;
/// `subgroup_ballot` — wave-level predicate ballot bitmask (feature-gated on `subgroup-ops`).
pub mod subgroup_ballot;
/// `subgroup_shuffle` — wave-level lane-to-lane value shuffle (feature-gated on `subgroup-ops`).
pub mod subgroup_shuffle;
/// `workgroup_barrier` — intra-workgroup shared-memory fence.
pub mod workgroup_barrier;

pub(crate) const MAP_WORKGROUP: [u32; 3] = [64, 1, 1];

pub(crate) fn unary_u32_program<F>(input: &str, out: &str, n: u32, expr: F) -> Program
where
    F: Fn(Expr) -> Expr,
{
    let body = vec![crate::region::wrap_anonymous(
        "vyre-intrinsics::hardware::unary_u32_map",
        vec![
            Node::let_bind("idx", Expr::InvocationId { axis: 0 }),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::buf_len(out)),
                vec![Node::store(
                    out,
                    Expr::var("idx"),
                    expr(Expr::load(input, Expr::var("idx"))),
                )],
            ),
        ],
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::output(out, 1, DataType::U32).with_count(n),
        ],
        MAP_WORKGROUP,
        body,
    )
}

pub(crate) fn ternary_f32_program(a: &str, b: &str, c: &str, out: &str, n: u32) -> Program {
    let body = vec![crate::region::wrap_anonymous(
        "vyre-intrinsics::hardware::ternary_f32_map",
        vec![
            Node::let_bind("idx", Expr::InvocationId { axis: 0 }),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::buf_len(out)),
                vec![Node::store(
                    out,
                    Expr::var("idx"),
                    Expr::Fma {
                        a: Box::new(Expr::load(a, Expr::var("idx"))),
                        b: Box::new(Expr::load(b, Expr::var("idx"))),
                        c: Box::new(Expr::load(c, Expr::var("idx"))),
                    },
                )],
            ),
        ],
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(a, 0, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::storage(b, 1, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::storage(c, 2, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::output(out, 3, DataType::F32).with_count(n),
        ],
        MAP_WORKGROUP,
        body,
    )
}

pub(crate) fn pack_u32(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

pub(crate) fn pack_f32(values: &[f32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}

#[cfg(test)]
pub(crate) fn run_program(program: &Program, inputs: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    use vyre_reference::value::Value;
    let values: Vec<Value> = inputs.into_iter().map(|b| Value::Bytes(b.into())).collect();
    vyre_reference::reference_eval(program, &values)
        .expect("intrinsic must execute")
        .into_iter()
        .map(|v| v.to_bytes())
        .collect()
}

#[cfg(test)]
pub(crate) fn lcg_u32(seed: u32, len: usize) -> Vec<u32> {
    let mut s = seed;
    (0..len)
        .map(|_| {
            s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            s
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn lcg_f32(seed: u32, len: usize) -> Vec<f32> {
    lcg_u32(seed, len)
        .into_iter()
        .map(|w| f32::from_bits((w >> 9) | 0x3F00_0000) - 1.0)
        .collect()
}
