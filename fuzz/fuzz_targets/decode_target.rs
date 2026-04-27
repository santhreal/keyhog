#![no_main]
use libfuzzer_sys::fuzz_target;
use keyhog_scanner::decode::decode_chunk;
use keyhog_core::Chunk;

fuzz_target!(|data: &[u8]| {
    // Treat the first 2 bytes as parameters
    if data.len() < 2 {
        return;
    }
    
    let depth = (data[0] % 12) as usize;
    let validate = (data[1] % 2) == 0;
    let payload = &data[2..];
    
    if let Ok(text) = std::str::from_utf8(payload) {
        let chunk = Chunk {
            data: text.to_string(),
            metadata: Default::default(),
        };
        
        // Ensure no panics in the recursive decoder
        let _ = decode_chunk(&chunk, depth, validate, None);
    }
});
