//! Count contract evasions that still DROPPED after fixes.
use std::path::PathBuf;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Contract {
    detector_id: String,
    #[serde(default)]
    evasion: Vec<Positive>,
}

#[derive(Debug, Deserialize)]
struct Positive {
    text: String,
    credential: String,
}

fn main() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    let scanner = CompiledScanner::compile(keyhog_core::load_detectors(&d).unwrap()).unwrap();
    let contracts_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/contracts");
    let mut dropped = 0usize;
    let mut pass = 0usize;
    for entry in std::fs::read_dir(&contracts_dir).unwrap().flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let c: Contract = match toml::from_str(&text) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for e in &c.evasion {
            scanner.clear_fragment_cache();
            let chunk = Chunk {
                data: e.text.clone().into(),
                metadata: ChunkMetadata {
                    source_type: "contract".into(),
                    path: Some("contract.txt".into()),
                    ..Default::default()
                },
            };
            let matches = scanner.scan(&chunk);
            let ok = matches
                .iter()
                .any(|m| m.credential.as_ref().contains(&e.credential));
            if ok {
                pass += 1;
            } else {
                dropped += 1;
                println!("DROPPED\t{}\t{}", c.detector_id, e.text.replace('\n', "\\n"));
            }
        }
    }
    eprintln!("pass={pass} dropped={dropped}");
}
