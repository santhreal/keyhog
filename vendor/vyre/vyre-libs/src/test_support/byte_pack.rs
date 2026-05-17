pub fn u32_bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

pub fn bytes_to_u32(slice: &[u8]) -> Vec<u32> {
    slice
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip() {
        let original = vec![1, 2, 3, 0xFFFFFFFF, 0x12345678];
        let bytes = u32_bytes(&original);
        let back = bytes_to_u32(&bytes);
        assert_eq!(original, back);
    }

    #[test]
    fn test_empty_input() {
        let original: Vec<u32> = vec![];
        let bytes = u32_bytes(&original);
        assert!(bytes.is_empty());
        let back = bytes_to_u32(&bytes);
        assert!(back.is_empty());
    }
}
