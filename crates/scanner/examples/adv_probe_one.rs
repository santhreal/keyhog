use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

fn main() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    let scanner =
        CompiledScanner::compile(keyhog_core::load_detectors(&d).unwrap()).unwrap();
    let text = "ADOBE_CLIENT_ID=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d";
    let cred = "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d";
    let synth = "ADOBECLIENTID=06bedf573b15af0894474a09de20a334";
    let synth_cred = "06bedf573b15af0894474a09de20a334";
    for (label, t, c) in [
        ("contract", text, cred),
        ("synth", synth, synth_cred),
    ] {
        scanner.clear_fragment_cache();
        let chunk = Chunk {
            data: t.into(),
            metadata: ChunkMetadata {
                source_type: "x".into(),
                path: Some("t.txt".into()),
                ..Default::default()
            },
        };
        let matches = scanner.scan(&chunk);
        let ok = matches
            .iter()
            .any(|m| m.credential.as_ref().contains(c));
        println!("{label} ok={ok} matches={}", matches.len());
        for m in &matches {
            println!("  det={} cred={}", m.detector_id, m.credential.as_ref());
        }
    }
}
