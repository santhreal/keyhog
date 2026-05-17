//! Direct u32 NOT reference for `primitive.bitwise.not`.

/// Compute NOT of the first little-endian `u32` word in `input`.
pub fn reference(input: &[u8]) -> Vec<u8> {
    if input.len() < 4 {
        return vec![0; 4];
    }

    let value = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    (!value).to_le_bytes().to_vec()
}
