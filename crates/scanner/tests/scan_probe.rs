use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

fn scan(text: &str) -> Vec<String> {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "probe".into(),
            path: Some("contract.txt".into()),
            ..Default::default()
        },
    };
    scanner
        .scan(&chunk)
        .into_iter()
        .map(|m| m.credential.as_ref().to_string())
        .collect()
}

#[test]
fn probe_splitio_and_aws() {
    let splitio = scan("split_io_api_key=YWJjZGVmZ2hpamtsbW5vcA==");
    eprintln!("splitio creds: {splitio:?}");
    assert!(
        splitio
            .iter()
            .any(|c| c.contains("YWJjZGVmZ2hpamtsbW5vcA=")),
        "splitio should surface base64 credential"
    );

    let aws = scan("AWS_SECRET_ACCESS_KEY=ev0BsFtSD7S/4VWYObxiEhME3hJBXeYzR43jgiB1");
    eprintln!("aws creds: {aws:?}");
    assert!(
        aws.iter()
            .any(|c| c.contains("ev0BsFtSD7S/4VWYObxiEhME3hJBXeYzR43jgiB1")),
        "aws secret should fire"
    );
}
