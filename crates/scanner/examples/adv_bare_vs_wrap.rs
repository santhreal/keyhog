use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct Contract {
    detector_id: String,
    #[serde(default)]
    positive: Vec<Positive>,
}
#[derive(Debug, Deserialize)]
struct Positive {
    text: String,
    credential: String,
}

fn chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "x".into(),
            path: Some("t.txt".into()),
            ..Default::default()
        },
    }
}

fn fires(scanner: &CompiledScanner, text: &str, cred: &str) -> bool {
    scanner.clear_fragment_cache();
    scanner
        .scan(&chunk(text))
        .iter()
        .any(|m| m.credential.as_ref().contains(cred))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    let scanner = CompiledScanner::compile(keyhog_core::load_detectors(&d)?)?;
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/contracts");
    let mut both_fail = Vec::new();
    let mut bare_ok_wrap_fail = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
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
        for p in &c.positive {
            let bare = fires(&scanner, &p.text, &p.credential);
            let wrapped = fires(
                &scanner,
                &format!("CREDENTIAL_PAYLOAD={}\n", p.text),
                &p.credential,
            );
            if !wrapped {
                if bare {
                    bare_ok_wrap_fail.push((
                        c.detector_id.clone(),
                        p.text.clone(),
                        p.credential.clone(),
                    ));
                } else {
                    both_fail.push(c.detector_id.clone());
                }
            }
        }
    }
    let mut both: HashMap<String, usize> = HashMap::new();
    for d in both_fail {
        *both.entry(d).or_default() += 1;
    }
    println!("BARE_OK_WRAP_FAIL={}", bare_ok_wrap_fail.len());
    for (d, t, c) in &bare_ok_wrap_fail {
        println!("  E? {d}: cred={c:?} text={t:?}");
    }
    println!("BOTH_FAIL unique detectors:");
    let mut v: Vec<_> = both.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    for (d, n) in v {
        println!("  C? {n} {d}");
    }
    Ok(())
}
