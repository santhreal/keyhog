use std::path::PathBuf;
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Contract { detector_id: String, #[serde(default)] positive: Vec<Positive> }
#[derive(Debug, Deserialize)]
struct Positive { text: String, credential: String }

fn chunk(text: &str) -> Chunk {
    Chunk { data: text.into(), metadata: ChunkMetadata { source_type: "x".into(), path: Some("t.txt".into()), ..Default::default() } }
}
fn fires(scanner: &CompiledScanner, text: &str, cred: &str) -> bool {
    scanner.clear_fragment_cache();
    scanner.scan(&chunk(text)).iter().any(|m| m.credential.as_ref().contains(cred))
}
fn wrap(label: &str, text: &str) -> String {
    let je = serde_json::to_string(text).unwrap();
    match label {
        ".env" => format!("CREDENTIAL_PAYLOAD={text}\n"),
        "json" => format!("{{\n  \"payload\": {je}\n}}\n"),
        "yaml" => format!("payload: |\n  {text}\n"),
        "dockerfile" => format!("FROM scratch\nENV PAYLOAD={text}\n"),
        _ => text.to_string(),
    }
}

fn main() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR")); d.pop(); d.pop(); d.push("detectors");
    let scanner = CompiledScanner::compile(keyhog_core::load_detectors(&d).unwrap()).unwrap();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/contracts");
    for w in [".env", "json", "yaml", "dockerfile"] {
        let mut n = 0;
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") { continue; }
            let c: Contract = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            for p in &c.positive {
                let bare = fires(&scanner, &p.text, &p.credential);
                let wrapped = fires(&scanner, &wrap(w, &p.text), &p.credential);
                if bare && !wrapped { n += 1; println!("E {w} {} cred={:?}", c.detector_id, p.credential); }
            }
        }
        println!("wrapper {w}: bare_ok_wrap_fail={n}");
    }
}
