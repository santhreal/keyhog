use crate::cpu_op;

pub(crate) fn primitive_math_div_cpu(input: &[u8], output: &mut Vec<u8>) {
    output.clear();
    let Some(lhs) = input.get(0..4) else {
        tracing::error!(
            "primitive.math.div CPU reference received {} input bytes; expected 8. Fix: pass two little-endian u32 operands.",
            input.len()
        );
        return;
    };
    let Some(rhs) = input.get(4..8) else {
        tracing::error!(
            "primitive.math.div CPU reference received {} input bytes; expected 8. Fix: pass two little-endian u32 operands.",
            input.len()
        );
        return;
    };
    let lhs = u32::from_le_bytes([lhs[0], lhs[1], lhs[2], lhs[3]]);
    let rhs = u32::from_le_bytes([rhs[0], rhs[1], rhs[2], rhs[3]]);
    output.extend_from_slice(&if rhs == 0 { 0 } else { lhs / rhs }.to_le_bytes());
}

pub(crate) fn cpu_fn_for_composition(id: &str) -> Option<cpu_op::CpuFn> {
    match id {
        "primitive.math.div" => Some(primitive_math_div_cpu),
        _ => None,
    }
}
