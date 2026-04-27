//! Shared floating-point parity helpers.
//!
//! The parity-matrix test and `prove`'s cross-backend oracle both need
//! the same rule: integer/bool buffers compare byte-identical, but F32
//! buffers compare under a bounded-ULP window because WGSL transcendentals
//! are not correctly-rounded. Keeping one implementation means `prove`
//! and `parity_matrix` cannot disagree about what "parity" means.

use vyre::ir::{DataType, Expr, Node, Program, UnOp};

/// Per-buffer comparison outcome for `compare_output_shape`.
#[derive(Debug)]
pub enum BufferParity {
    /// Every output buffer matched the reference (byte-exact for
    /// non-F32, within the ULP window for F32).
    Ok,
    /// A specific buffer diverged; human-readable explanation.
    Mismatch(String),
}

/// Compare two output-buffer vectors against the program's declared
/// buffer layout. F32 buffers use [`f32_buffer_matches`] with
/// [`f32_ulp_tolerance`]; every other element type requires byte
/// identity. Returns [`BufferParity::Ok`] only when every slot passed.
pub fn compare_output_buffers(
    program: &Program,
    outputs_a: &[Vec<u8>],
    outputs_b: &[Vec<u8>],
) -> BufferParity {
    if outputs_a.len() != outputs_b.len() {
        return BufferParity::Mismatch(format!(
            "output buffer count mismatch: {} vs {}",
            outputs_a.len(),
            outputs_b.len()
        ));
    }

    let output_indices = program.output_buffer_indices();
    if output_indices.len() != outputs_a.len() {
        return BufferParity::Mismatch(format!(
            "program declares {} output buffer(s), compared {} result buffer(s)",
            output_indices.len(),
            outputs_a.len()
        ));
    }

    let tolerance = f32_ulp_tolerance(program);
    for (slot, ((bytes_a, bytes_b), buffer_index)) in outputs_a
        .iter()
        .zip(outputs_b.iter())
        .zip(output_indices.iter().copied())
        .enumerate()
    {
        if bytes_a.len() != bytes_b.len() {
            return BufferParity::Mismatch(format!(
                "output buffer {slot} length mismatch: {} vs {}",
                bytes_a.len(),
                bytes_b.len()
            ));
        }
        let element = program.buffers()[buffer_index as usize].element();
        if element == DataType::F32 {
            if !f32_buffer_matches(bytes_a, bytes_b, tolerance) {
                return BufferParity::Mismatch(format!(
                    "output buffer {slot} (F32) exceeded the {tolerance}-ULP window"
                ));
            }
        } else if bytes_a != bytes_b {
            return BufferParity::Mismatch(format!(
                "output buffer {slot} ({element:?}) is not byte-identical"
            ));
        }
    }

    BufferParity::Ok
}

/// Compare two `[u8]` views as packed little-endian f32 arrays under a
/// ULP window. Returns `false` if lengths differ or any element falls
/// outside the window. NaN inputs only match bitwise.
pub fn f32_buffer_matches(bytes_a: &[u8], bytes_b: &[u8], tolerance: u32) -> bool {
    if bytes_a.len() != bytes_b.len() || bytes_a.len() % 4 != 0 {
        return false;
    }
    if tolerance == 0 {
        return bytes_a == bytes_b;
    }
    bytes_a
        .chunks_exact(4)
        .zip(bytes_b.chunks_exact(4))
        .all(|(left, right)| {
            let left = f32::from_bits(u32::from_le_bytes(left.try_into().expect("4 bytes")));
            let right = f32::from_bits(u32::from_le_bytes(right.try_into().expect("4 bytes")));
            left.to_bits() == right.to_bits()
                || ulp_distance(left, right).is_some_and(|ulp| ulp <= tolerance)
        })
}

/// Per-program ULP tolerance. The 4-ULP base covers elementary ops that
/// round once; programs that lower to WGSL transcendentals (`exp`,
/// `log`, `inverseSqrt`, `sqrt`, `sin`, `cos`) widen to 64 ULP because
/// WGSL spec permits per-op rounding divergences in the 2-4 ULP range
/// and softmax-style compositions stack them. Still tight enough to
/// catch wrong-algorithm regressions. Under the `strict-fp` feature the
/// non-transcendental base tightens to 0 (byte-identity); transcendental
/// programs stay at 64 because no WGSL backend can deliver bitwise parity
/// on `exp`/`log`/`sin`/`cos`/`sqrt`.
#[cfg(not(feature = "strict-fp"))]
/// Return the allowed f32 ULP tolerance for parity checks under the active FP policy.
pub fn f32_ulp_tolerance(program: &Program) -> u32 {
    if program_has_transcendental(program) {
        64
    } else {
        4
    }
}

#[cfg(feature = "strict-fp")]
/// Return the allowed f32 ULP tolerance for parity checks under the active FP policy.
pub fn f32_ulp_tolerance(program: &Program) -> u32 {
    if program_has_transcendental(program) {
        64
    } else {
        0
    }
}

/// Sign-aware ULP distance between two same-signed finite f32 values.
/// Returns `None` for NaN on either side.
pub fn ulp_distance(left: f32, right: f32) -> Option<u32> {
    if left.is_nan() || right.is_nan() {
        return None;
    }
    let left = ordered_f32_bits(left);
    let right = ordered_f32_bits(right);
    Some(left.abs_diff(right))
}

fn ordered_f32_bits(value: f32) -> u32 {
    let bits = value.to_bits();
    if bits & 0x8000_0000 != 0 {
        !bits
    } else {
        bits | 0x8000_0000
    }
}

fn program_has_transcendental(program: &Program) -> bool {
    program.entry().iter().any(node_has_transcendental)
}

fn expr_has_transcendental(expr: &Expr) -> bool {
    match expr {
        Expr::UnOp { op, operand } => {
            matches!(
                op,
                UnOp::Exp | UnOp::Log | UnOp::Sqrt | UnOp::InverseSqrt | UnOp::Sin | UnOp::Cos
            ) || expr_has_transcendental(operand)
        }
        Expr::BinOp { left, right, .. } => {
            expr_has_transcendental(left) || expr_has_transcendental(right)
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            expr_has_transcendental(cond)
                || expr_has_transcendental(true_val)
                || expr_has_transcendental(false_val)
        }
        Expr::Cast { value, .. } => expr_has_transcendental(value),
        Expr::Fma { a, b, c } => {
            expr_has_transcendental(a) || expr_has_transcendental(b) || expr_has_transcendental(c)
        }
        Expr::Load { index, .. } => expr_has_transcendental(index),
        Expr::Atomic {
            index,
            expected,
            value,
            ..
        } => {
            expr_has_transcendental(index)
                || expected.as_deref().is_some_and(expr_has_transcendental)
                || expr_has_transcendental(value)
        }
        Expr::SubgroupAdd { value } | Expr::SubgroupBallot { cond: value } => {
            expr_has_transcendental(value)
        }
        Expr::SubgroupShuffle { value, lane } => {
            expr_has_transcendental(value) || expr_has_transcendental(lane)
        }
        Expr::Call { args, .. } => args.iter().any(expr_has_transcendental),
        _ => false,
    }
}

fn node_has_transcendental(node: &Node) -> bool {
    match node {
        Node::Let { value, .. } | Node::Assign { value, .. } => expr_has_transcendental(value),
        Node::Store { index, value, .. } => {
            expr_has_transcendental(index) || expr_has_transcendental(value)
        }
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            expr_has_transcendental(cond)
                || then.iter().any(node_has_transcendental)
                || otherwise.iter().any(node_has_transcendental)
        }
        Node::Loop { from, to, body, .. } => {
            expr_has_transcendental(from)
                || expr_has_transcendental(to)
                || body.iter().any(node_has_transcendental)
        }
        Node::Block(body) => body.iter().any(node_has_transcendental),
        Node::Region { body, .. } => body.iter().any(node_has_transcendental),
        _ => false,
    }
}
