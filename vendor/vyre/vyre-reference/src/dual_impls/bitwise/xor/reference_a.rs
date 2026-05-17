//! Direct u32 XOR reference for `primitive.bitwise.xor`.

/// Compute XOR from the first two little-endian `u32` words in `input`.
pub fn reference(input: &[u8]) -> Vec<u8> {
    if input.len() < 8 {
        return vec![0; 4];
    }

    let left = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    let right = u32::from_le_bytes([input[4], input[5], input[6], input[7]]);
    (left ^ right).to_le_bytes().to_vec()
}
