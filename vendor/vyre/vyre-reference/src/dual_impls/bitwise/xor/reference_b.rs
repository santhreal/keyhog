//! Bit-by-bit XOR reference for `primitive.bitwise.xor`.

/// Compute XOR by reconstructing each output bit independently.
pub fn reference(input: &[u8]) -> Vec<u8> {
    if input.len() < 8 {
        return vec![0; 4];
    }

    let mut output = [0_u8; 4];
    for bit_index in 0..32 {
        let left = bit_at(input, bit_index);
        let right = bit_at(input, bit_index + 32);
        if left != right {
            output[bit_index / 8] |= 1 << (bit_index % 8);
        }
    }
    output.to_vec()
}

fn bit_at(input: &[u8], bit_index: usize) -> bool {
    let byte = input[bit_index / 8];
    let mask = 1_u8 << (bit_index % 8);
    byte & mask != 0
}
