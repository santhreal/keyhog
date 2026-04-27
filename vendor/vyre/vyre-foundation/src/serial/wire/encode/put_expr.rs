//! Expression encoder for the stable IR wire format.

use crate::serial::wire::framing::{put_len_u32, put_string, put_u32, put_u8};
use crate::serial::wire::tags::{atomic_op_tag, bin_op_tag, put_data_type, un_op_tag};
use crate::serial::wire::Expr;

/// Append the wire-format tag and payload for one [`Expr`] to `out`.
///
/// # Role
///
/// This is the leaf encoder of the IR wire format. Every expression
/// variant is mapped to a single-byte discriminant followed by a
/// variant-specific payload. The discriminant table is the contract
/// between encoder and decoder; changing it is a breaking schema
/// change (audit L.1.47).
///
/// # Invariants
///
/// * `out` is appended to only; no bytes are removed or reordered.
/// * Recursive calls for nested expressions (`Load`, `BinOp`, `UnOp`,
///   `Call`, `Select`, `Cast`, `Fma`, `Atomic`) preserve this
///   invariant.
///
/// # Pre-conditions
///
/// `expr` must use only enum variants that have a registered stable
/// wire tag. Variants added to `Expr` without an assigned tag
/// will fail encoding (audit L.1.27 / I4).
///
/// # Return semantics
///
/// * `Ok(())` – the expression was fully appended to `out`.
/// * `Err(String)` – an actionable diagnostic starting with `Fix:`
///   describing the unsupported variant or oversized payload.
///
/// # Failure modes
///
/// * **Unmapped variant** – `bin_op_tag`, `un_op_tag`, or
///   `atomic_op_tag` returns `Err` when the op has no wire tag.
/// * **String overflow** – `put_string` rejects names longer than
///   [`crate::serial::wire::MAX_STRING_LEN`].
/// * **Length overflow** – `put_len_u32` rejects argument counts
///   larger than `u32::MAX`.
#[inline]
#[must_use]
pub fn put_expr(out: &mut Vec<u8>, expr: &Expr) -> Result<(), String> {
    match expr {
        Expr::LitU32(value) => {
            put_u8(out, 0);
            put_u32(out, *value);
        }
        Expr::LitI32(value) => {
            put_u8(out, 1);
            put_u32(out, u32::from_le_bytes(value.to_le_bytes()));
        }
        Expr::LitBool(value) => {
            put_u8(out, 2);
            put_u8(out, u8::from(*value));
        }
        Expr::LitF32(value) => {
            put_u8(out, 15);
            put_u32(out, canonical_f32_bits(*value));
        }
        Expr::Var(name) => {
            put_u8(out, 3);
            put_string(out, name)?;
        }
        Expr::Load { buffer, index } => {
            put_u8(out, 4);
            put_string(out, buffer)?;
            put_expr(out, index)?;
        }
        Expr::BufLen { buffer } => {
            put_u8(out, 5);
            put_string(out, buffer)?;
        }
        Expr::InvocationId { axis } => {
            put_u8(out, 6);
            put_u8(out, *axis);
        }
        Expr::WorkgroupId { axis } => {
            put_u8(out, 7);
            put_u8(out, *axis);
        }
        Expr::LocalId { axis } => {
            put_u8(out, 8);
            put_u8(out, *axis);
        }
        Expr::BinOp { op, left, right } => {
            put_u8(out, 9);
            // Opaque BinOp serializes as tag 0x80 + u32 extension id.
            // Non-Opaque variants go through the standard bin_op_tag table.
            if let crate::ir::BinOp::Opaque(id) = op {
                put_u8(out, 0x80);
                put_u32(out, id.as_u32());
            } else {
                put_u8(out, bin_op_tag(*op)?);
            }
            put_expr(out, left)?;
            put_expr(out, right)?;
        }
        Expr::UnOp { op, operand } => {
            put_u8(out, 10);
            if let crate::ir::UnOp::Opaque(id) = op {
                put_u8(out, 0x80);
                put_u32(out, id.as_u32());
            } else {
                put_u8(out, un_op_tag(op.clone())?);
            }
            put_expr(out, operand)?;
        }
        Expr::Call { op_id, args } => {
            put_u8(out, 11);
            put_string(out, op_id.as_str())?;
            put_len_u32(out, args.len(), "call argument count")?;
            for arg in args {
                put_expr(out, arg)?;
            }
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            put_u8(out, 12);
            put_expr(out, cond)?;
            put_expr(out, true_val)?;
            put_expr(out, false_val)?;
        }
        Expr::Cast { target, value } => {
            put_u8(out, 13);
            put_data_type(out, target)?;
            put_expr(out, value)?;
        }
        Expr::Fma { a, b, c } => {
            put_u8(out, 16);
            put_expr(out, a)?;
            put_expr(out, b)?;
            put_expr(out, c)?;
        }
        Expr::Atomic {
            op,
            buffer,
            index,
            expected,
            value,
        } => {
            put_u8(out, 14);
            if let crate::ir::AtomicOp::Opaque(id) = op {
                put_u8(out, 0x80);
                put_u32(out, id.as_u32());
            } else {
                put_u8(out, atomic_op_tag(*op)?);
            }
            put_string(out, buffer)?;
            put_expr(out, index)?;
            match expected {
                Some(expected) => {
                    put_u8(out, 1);
                    put_expr(out, expected)?;
                }
                None => put_u8(out, 0),
            }
            put_expr(out, value)?;
        }
        Expr::SubgroupAdd { value } => {
            put_u8(out, 17);
            put_expr(out, value)?;
        }
        Expr::SubgroupShuffle { value, lane } => {
            put_u8(out, 18);
            put_expr(out, value)?;
            put_expr(out, lane)?;
        }
        Expr::SubgroupBallot { cond } => {
            put_u8(out, 19);
            put_expr(out, cond)?;
        }
        Expr::SubgroupLocalId => {
            put_u8(out, 20);
        }
        Expr::SubgroupSize => {
            put_u8(out, 21);
        }
        Expr::Opaque(extension) => {
            put_u8(out, 0x80);
            put_string(out, extension.extension_kind())?;
            let payload = extension.wire_payload();
            put_len_u32(out, payload.len(), "opaque expression payload length")?;
            out.extend_from_slice(&payload);
        }
    }
    Ok(())
}

#[inline]
fn canonical_f32_bits(value: f32) -> u32 {
    let bits = value.to_bits();
    if bits == (-0.0f32).to_bits() {
        0.0f32.to_bits()
    } else {
        bits
    }
}
