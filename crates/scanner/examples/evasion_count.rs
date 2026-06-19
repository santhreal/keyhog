//! Count contract evasions that still DROPPED after fixes.
use std::io::{self, ErrorKind};
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    let scanner = CompiledScanner::compile(keyhog_core::load_detectors(&d)?)?;
    let contracts_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/contracts");
    let mut dropped = 0usize;
    let mut pass = 0usize;
    for entry in std::fs::read_dir(&contracts_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path)?;
        if text.starts_with("version https://git-lfs.github.com/spec/v1") {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("contract {} is a Git LFS pointer", path.display()),
            )
            .into());
        }
        let c: Contract = toml::from_str(&text)?;
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
                println!(
                    "DROPPED\t{}\t{}",
                    c.detector_id,
                    e.text.replace('\n', "\\n")
                );
            }
        }
    }
    eprintln!("pass={pass} dropped={dropped}");
    Ok(())
}
