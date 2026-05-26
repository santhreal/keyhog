use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

fn main() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    let s = CompiledScanner::compile(keyhog_core::load_detectors(&d).unwrap()).unwrap();
    let texts = [
        "SPOTIFY_CLIENT_ID=0123456789abcdef0123456789abcdef",
        "spotify_client_id=0123456789abcdef0123456789abcdef",
        "reddit_ads_client_id=AbCdEfGhIjKlMnOp",
        "PARDOT_BUSINESS_UNIT_ID=0Uv1234567890AbCdE",
        "MARKETO_CLIENT_SECRET=fedcba9876543210fedcba98",
    ];
    for text in texts {
        s.clear_fragment_cache();
        let m = s.scan(&Chunk {
            data: text.into(),
            metadata: ChunkMetadata {
                source_type: "x".into(),
                path: Some("t.txt".into()),
                ..Default::default()
            },
        });
        println!("--- {text}");
        for x in &m {
            println!("  {} {}", x.detector_id, x.credential.as_ref());
        }
        if m.is_empty() {
            println!("  (none)");
        }
    }
}
