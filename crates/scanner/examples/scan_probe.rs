use keyhog_core::{load_detectors, Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

fn scan(scanner: &CompiledScanner, text: &str) -> Vec<String> {
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "probe".into(),
            ..Default::default()
        },
    };
    scanner
        .scan(&chunk)
        .into_iter()
        .map(|m| m.credential.as_ref().to_string())
        .collect()
}

fn main() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    let scanner = CompiledScanner::compile(load_detectors(&d).unwrap()).unwrap();

    for text in [
        "STEAM_API_KEY=15eb9b9185146a3ab266d4e7ba0c5aba",
        "CREDENTIAL_PAYLOAD=STEAM_API_KEY=15eb9b9185146a3ab266d4e7ba0c5aba\n",
        "split_io_api_key=YWJjZGVmZ2hpamtsbW5vcA==",
    ] {
        println!("{text:?} => {:?}", scan(&scanner, text));
    }
}
