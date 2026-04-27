//! Program encoder for the stable `VYRE` wire format.

use super::put_node;
use crate::ir_inner::model::program::{CacheLocality, MemoryKind};
use crate::ir_inner::model::types::{BufferAccess, DataType};
use crate::serial::wire::framing::{
    put_string, put_u32, put_u8, FLAG_OPAQUE_ENDIAN_FIXED, MAGIC, WIRE_FORMAT_VERSION,
};
use crate::serial::wire::tags::access_tag::access_tag;
use crate::serial::wire::Program;
const METADATA_OP_ID: &str = "vyre.program.metadata";

/// Serialize a complete [`Program`] into the `VYRE` wire envelope.
///
/// # Role
///
/// This is the entry-point encoder. It produces the exact byte
/// sequence that [`Program::from_wire`] expects: magic, version,
/// entry-op id, buffer table, work-group size, and entry body.
///
/// # Invariants
///
/// * The output is a fresh `Vec<u8>`; the caller owns it.
/// * Capacity is pre-allocated heuristically to avoid reallocations
///   on typical programs, but the vector grows naturally if the
///   estimate is low.
///
/// # Pre-conditions
///
/// The program must use only enum variants that have stable wire
/// tags. A well-formed program should always encode successfully;
/// encoding failure signals either an unsupported variant
/// (audit L.1.27 / I4) or a field that exceeds wire-format bounds
/// (audit I10).
///
/// # Return semantics
///
/// * `Ok(Vec<u8>)` – a complete VIR0 blob starting with [`MAGIC`]
///   and [`WIRE_FORMAT_VERSION`].
/// * `Err(String)` – an actionable diagnostic starting with `Fix:`.
///
/// # Failure modes
///
/// * **Buffer count overflow** – more than `u32::MAX` buffers.
/// * **String overflow** – buffer names or the entry op id longer
///   than [`crate::serial::wire::MAX_STRING_LEN`] are rejected.
/// * **Unmapped variant** – `access_tag`, `put_data_type`, or nested
///   `put_expr` / `put_node` calls fail when an enum variant has no
///   wire tag.
///
/// # Versioning
///
/// The version bytes are emitted immediately after the magic
/// (audit L.1.47). Any breaking schema change must bump
/// [`WIRE_FORMAT_VERSION`] so older decoders reject the payload
/// with a clear version-mismatch message instead of arbitrary
/// downstream parse errors.
#[inline]
#[must_use]
pub fn to_wire(program: &Program) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    to_wire_into(program, &mut out)?;
    Ok(out)
}

/// Serialize a complete [`Program`] into the `VYRE` wire envelope,
/// appending to an existing buffer.
///
/// # Role
///
/// Same semantics as [`to_wire`], but appends to `dst` instead of
/// returning a fresh `Vec<u8>`. The caller may `dst.clear()` and
/// reuse the same buffer across many calls to avoid O(N) heap
/// allocations when encoding batched programs.
///
/// # Invariants
///
/// * Bytes are appended to `dst`; existing content is preserved.
/// * Capacity is reserved heuristically to avoid reallocations.
///
/// # Pre-conditions
///
/// Same as [`to_wire`].
///
/// # Return semantics
///
/// * `Ok(())` – the complete VIR0 blob was appended to `dst`.
/// * `Err(String)` – an actionable diagnostic starting with `Fix:`.
#[inline]
pub fn to_wire_into(program: &Program, dst: &mut Vec<u8>) -> Result<(), String> {
    reject_non_roundtrippable_shapes(program)?;
    let mut body = Vec::with_capacity(program.entry().len().saturating_mul(32) + 256);
    put_nodes_section(&mut body, program)?;
    put_memory_regions(&mut body, program)?;
    put_output_set(&mut body);

    let digest = blake3::hash(&body);
    dst.reserve(MAGIC.len() + 2 + 2 + 32 + body.len());
    dst.extend_from_slice(MAGIC);
    dst.extend_from_slice(&WIRE_FORMAT_VERSION.to_le_bytes());
    dst.extend_from_slice(&FLAG_OPAQUE_ENDIAN_FIXED.to_le_bytes());
    dst.extend_from_slice(digest.as_bytes());
    dst.extend_from_slice(&body);
    Ok(())
}

fn reject_non_roundtrippable_shapes(program: &Program) -> Result<(), String> {
    for (axis, size) in program.workgroup_size().into_iter().enumerate() {
        if size == 0 {
            return Err(format!(
                "Fix: workgroup_size[{axis}] is 0. Encode only programs whose workgroup dimensions are >= 1."
            ));
        }
    }

    for buffer in program.buffers() {
        if buffer.count() == 0 && buffer.access() == BufferAccess::Workgroup {
            return Err(format!(
                "Fix: workgroup buffer `{}` has count 0. Encode only positive-length shared-memory buffers.",
                buffer.name()
            ));
        }
        // Output buffers may legitimately carry count 0 to signal a
        // runtime-determined size (the dispatch layer rebinds them
        // with a concrete byte length once it knows the host's
        // capacity). The wire format records `count = 0` and the
        // `output_byte_range` check below validates start/end
        // ordering without needing a fixed full-size. The earlier
        // strict rejection failed every Program fingerprinted with
        // a zero-length scratch output (run_arbitrary, conformance,
        // dispatch_determinism — see tests).
        if buffer.count() == 0 && buffer.is_pipeline_live_out() {
            return Err(format!(
                "Fix: live-out buffer `{}` has count 0. Encode only positive-length externally-visible buffers.",
                buffer.name()
            ));
        }
        if let Some(range) = buffer.output_byte_range() {
            let elem_size = buffer.element().size_bytes().unwrap_or(0) as u64;
            let count = buffer.count() as u64;
            let full_size = if count == 0 {
                // runtime-sized: we can't validate against full_size here,
                // but we can still check start <= end.
                u64::MAX
            } else {
                count.saturating_mul(elem_size)
            };
            let start = range.start as u64;
            let end = range.end as u64;
            if start > end {
                return Err(format!(
                    "Fix: buffer `{}` output byte range has start ({}) > end ({}). Encode only valid ranges.",
                    buffer.name(),
                    range.start,
                    range.end
                ));
            }
            if end > full_size && full_size != u64::MAX {
                return Err(format!(
                    "Fix: buffer `{}` output byte range end ({}) exceeds full buffer size ({}). Encode only ranges that fit within the declared buffer size.",
                    buffer.name(),
                    range.end,
                    full_size
                ));
            }
        }
    }

    Ok(())
}

fn put_nodes_section(out: &mut Vec<u8>, program: &Program) -> Result<(), String> {
    put_leb_u64(
        out,
        u64::try_from(program.entry().len() + 1).map_err(|err| {
            format!(
                "Fix: node count cannot fit u64 ({err}); split the Program before serialization."
            )
        })?,
    );
    put_node_record(out, METADATA_OP_ID, &metadata_payload(program)?, &[])?;
    // VYRE_IR_HOTSPOTS CRIT (to_wire.rs:150): the previous loop
    // allocated a fresh `Vec<u8>` per node — N independent heap
    // allocations for N-node programs. Reusing a single scratch
    // vector that's cleared per iteration keeps the underlying
    // capacity across nodes (the allocator reuses the same backing
    // buffer).
    let mut payload = Vec::with_capacity(64);
    for node in program.entry() {
        payload.clear();
        put_node(&mut payload, node)?;
        put_node_record(
            out,
            crate::ir_inner::model::node::node_op_id(node),
            &payload,
            &[],
        )?;
    }
    Ok(())
}

fn put_node_record(
    out: &mut Vec<u8>,
    op_id: &str,
    payload: &[u8],
    operands: &[u32],
) -> Result<(), String> {
    put_leb_str(out, op_id)?;
    put_leb_u64(
        out,
        u64::try_from(payload.len()).map_err(|err| {
            format!("Fix: node payload length cannot fit u64 ({err}); split the Program.")
        })?,
    );
    out.extend_from_slice(payload);
    put_leb_u64(
        out,
        u64::try_from(operands.len()).map_err(|err| {
            format!("Fix: node operand count cannot fit u64 ({err}); split the Program.")
        })?,
    );
    for operand in operands {
        put_leb_u32(out, *operand);
    }
    Ok(())
}

fn metadata_payload(program: &Program) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.extend_from_slice(b"VYRE-META");
    match program.entry_op_id() {
        Some(op_id) => {
            put_u8(&mut out, 1);
            put_string(&mut out, op_id)?;
        }
        None => put_u8(&mut out, 0),
    }
    for size in program.workgroup_size() {
        put_u32(&mut out, size);
    }
    put_u8(&mut out, u8::from(program.is_non_composable_with_self()));
    put_leb_u64(
        &mut out,
        u64::try_from(program.buffers().len()).map_err(|err| {
            format!("Fix: buffer metadata count cannot fit u64 ({err}); split the Program.")
        })?,
    );
    for buffer in program.buffers() {
        put_string(&mut out, buffer.name())?;
        put_u32(&mut out, buffer.binding());
        put_u32(&mut out, buffer.count());
        put_u8(&mut out, u8::from(buffer.is_output()));
        put_u8(&mut out, u8::from(buffer.is_pipeline_live_out()));
        match buffer.output_byte_range() {
            Some(range) => {
                put_u8(&mut out, 1);
                put_leb_u64(&mut out, u64::try_from(range.start).map_err(|err| {
                    format!("Fix: output range start cannot fit u64 ({err}); split the output buffer.")
                })?);
                put_leb_u64(
                    &mut out,
                    u64::try_from(range.end).map_err(|err| {
                        format!(
                            "Fix: output range end cannot fit u64 ({err}); split the output buffer."
                        )
                    })?,
                );
            }
            None => put_u8(&mut out, 0),
        }
        put_hints_payload(&mut out, buffer.hints())?;
    }
    Ok(out)
}

fn put_memory_regions(out: &mut Vec<u8>, program: &Program) -> Result<(), String> {
    put_leb_u64(
        out,
        u64::try_from(program.buffers().len()).map_err(|err| {
            format!("Fix: memory-region count cannot fit u64 ({err}); split the Program.")
        })?,
    );
    // VYRE_IR_HOTSPOTS CRIT (to_wire.rs:254,276): a fresh Vec<u8>
    // was allocated per buffer for the shape sub-payload and another
    // for the hints sub-payload — 2×B allocations for B buffers.
    // Reuse two scratch vectors across the loop; both are cleared
    // per iteration and keep their capacity.
    let mut shape = Vec::with_capacity(16);
    let mut hints = Vec::with_capacity(16);
    for (index, buffer) in program.buffers().iter().enumerate() {
        put_leb_u32(
            out,
            u32::try_from(index).map_err(|err| {
                format!("Fix: memory-region id {index} cannot fit u32 ({err}); split the Program.")
            })?,
        );
        put_u8(out, memory_kind_tag(buffer.kind()));
        put_u8(out, access_tag(buffer.access())?);
        put_u8(out, data_type_tag(&buffer.element())?);
        put_u8(out, 0);
        shape.clear();
        put_leb_u64(&mut shape, u64::from(buffer.count()));
        if let DataType::Array { element_size } = buffer.element() {
            put_leb_u64(
                &mut shape,
                u64::try_from(element_size).map_err(|err| {
                    format!("Fix: array element size cannot fit u64 ({err}); cap the element size.")
                })?,
            );
        }
        if let DataType::Opaque(id) = buffer.element() {
            // Opaque payload = u32 extension id (LEB-encoded as u64 to match
            // the surrounding wire convention; decoder caps at u32::MAX).
            put_leb_u64(&mut shape, u64::from(id.as_u32()));
        }
        put_leb_u64(
            out,
            u64::try_from(shape.len()).map_err(|err| {
                format!("Fix: shape payload length cannot fit u64 ({err}); split the Program.")
            })?,
        );
        out.extend_from_slice(&shape);
        hints.clear();
        put_hints_payload(&mut hints, buffer.hints())?;
        put_leb_u64(
            out,
            u64::try_from(hints.len()).map_err(|err| {
                format!("Fix: hints payload length cannot fit u64 ({err}); split the Program.")
            })?,
        );
        out.extend_from_slice(&hints);
    }
    Ok(())
}

fn put_output_set(out: &mut Vec<u8>) {
    put_leb_u64(out, 0);
}

fn put_hints_payload(out: &mut Vec<u8>, hints: crate::ir::MemoryHints) -> Result<(), String> {
    match hints.coalesce_axis {
        Some(axis) => {
            put_u8(out, 1);
            put_u8(out, axis);
        }
        None => put_u8(out, 0),
    }
    put_u32(out, hints.preferred_alignment);
    put_u8(
        out,
        match hints.cache_locality {
            CacheLocality::Streaming => 0,
            CacheLocality::Temporal => 1,
            CacheLocality::Random => 2,
        },
    );
    Ok(())
}

fn memory_kind_tag(kind: MemoryKind) -> u8 {
    match kind {
        MemoryKind::Global => 0,
        MemoryKind::Shared => 1,
        MemoryKind::Uniform => 2,
        MemoryKind::Local => 3,
        MemoryKind::Readonly => 4,
        MemoryKind::Push => 5,
        MemoryKind::Persistent => 6,
    }
}

fn data_type_tag(value: &DataType) -> Result<u8, String> {
    Ok(match value {
        DataType::U32 => 0x01,
        DataType::I32 => 0x02,
        DataType::U64 => 0x03,
        DataType::Vec2U32 => 0x04,
        DataType::Vec4U32 => 0x05,
        DataType::Bool => 0x06,
        DataType::Bytes => 0x07,
        DataType::Array { .. } => 0x08,
        DataType::F16 => 0x09,
        DataType::BF16 => 0x0A,
        DataType::F32 => 0x0B,
        DataType::F64 => 0x0C,
        DataType::Tensor => 0x0D,
        DataType::U8 => 0x0E,
        DataType::U16 => 0x0F,
        DataType::I8 => 0x10,
        DataType::I16 => 0x11,
        DataType::I64 => 0x12,
        DataType::Handle(_) => 0x13,
        DataType::Vec { .. } => 0x14,
        DataType::TensorShaped { .. } => 0x15,
        DataType::Opaque(_) => 0x80,
        _ => {
            return Err(
                "Fix: unknown DataType variant cannot be serialized into VYRE wire format."
                    .to_string(),
            );
        }
    })
}

fn put_leb_str(out: &mut Vec<u8>, value: &str) -> Result<(), String> {
    put_leb_u64(
        out,
        u64::try_from(value.len()).map_err(|err| {
            format!("Fix: string length cannot fit u64 ({err}); shorten the identifier.")
        })?,
    );
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_leb_u32(out: &mut Vec<u8>, value: u32) {
    put_leb_u64(out, u64::from(value));
}

fn put_leb_u64(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BufferDecl, DataType, Expr, Node, Program};

    #[test]
    fn to_wire_into_appends_byte_for_byte() {
        let program = Program::wrapped(
            vec![
                BufferDecl::read_write("a", 0, DataType::U32),
                BufferDecl::read("b", 1, DataType::U32),
            ],
            [64, 1, 1],
            vec![
                Node::let_bind("idx", Expr::gid_x()),
                Node::store("a", Expr::var("idx"), Expr::load("b", Expr::var("idx"))),
            ],
        );

        let mut separate = Vec::new();
        for _ in 0..100 {
            separate.extend_from_slice(&to_wire(&program).unwrap());
        }

        let mut reused = Vec::new();
        for _ in 0..100 {
            to_wire_into(&program, &mut reused).unwrap();
        }

        assert_eq!(
            separate, reused,
            "100 separate to_wire calls must match 100 to_wire_into calls into the same buffer"
        );
    }
}
