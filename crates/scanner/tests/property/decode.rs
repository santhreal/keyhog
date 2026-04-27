use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;
use proptest::prelude::*;

proptest! {
    #[test]
    fn proptest_decode_never_panics(s in "\\PC*") {
        let chunk = Chunk {
            data: s,
            metadata: Default::default(),
        };
        let _ = decode_chunk(&chunk, 3, true, None, None);
    }

    #[test]
    fn proptest_decode_with_deep_recursion(s in "\\PC*", depth in 0..15usize) {
        let chunk = Chunk {
            data: s,
            metadata: Default::default(),
        };
        let _ = decode_chunk(&chunk, depth, true, None, None);
    }
}
