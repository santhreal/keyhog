//! Bit-by-bit NOT reference for `primitive.bitwise.not`.

/// Compute NOT by flipping each bit independently.
pub fn reference(input: &[u8]) -> Vec<u8> {
    if input.len() < 4 {
        return vec![0; 4];
    }

    let mut output = [0_u8; 4];
    for bit_index in 0..32 {
        let byte = input[bit_index / 8];
        let mask = 1_u8 << (bit_index % 8);
        let bit_set = byte & mask != 0;
        if !bit_set {
            output[bit_index / 8] |= 1 << (bit_index % 8);
        }
    }
    output.to_vec()
}
