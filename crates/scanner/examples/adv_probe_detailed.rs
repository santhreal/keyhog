use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec};
use keyhog_scanner::CompiledScanner;
use regex::Regex;
use std::path::PathBuf;

fn main() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    let detectors = keyhog_core::load_detectors(&d).unwrap();
    let targets = [
        "spotify-client-credentials",
        "reddit-ads-api-credentials",
        "pardot-api-credentials",
        "marketo-api-credentials",
    ];
    for id in targets {
        let det = detectors.iter().find(|x| x.id == id).expect(id);
        println!("=== {id} ===");
        for (i, p) in det.patterns.iter().enumerate() {
            let re = Regex::new(&p.regex).unwrap();
            println!("  pattern[{i}] = {}", p.regex);
            let sample = match id {
                "spotify-client-credentials" => {
                    "SPOTIFY_CLIENT_ID=25b7136a1e10908bb8e7a0f15e1a29d2"
                }
                "reddit-ads-api-credentials" => "reddit_ads_client_id=AbCdEfGhIjKlMnOp",
                "pardot-api-credentials" => "PARDOT_BUSINESS_UNIT_ID=0Uv1234567890AbCdE",
                "marketo-api-credentials" => "MARKETO_CLIENT_SECRET=fedcba9876543210fedcba98",
                _ => "",
            };
            if let Some(cap) = re.captures(sample) {
                println!("    direct regex OK: {:?}", cap.get(p.group.unwrap_or(0)));
            } else {
                println!("    direct regex MISS on {sample}");
            }
        }
    }

    let s = CompiledScanner::compile(detectors).unwrap();
    let texts = [
        (
            "datadog-api-key",
            "DD_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        ),
        (
            "spotify-client-credentials",
            "SPOTIFY_CLIENT_ID=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        ),
        (
            "reddit-ads-api-credentials",
            "reddit_ads_client_id=kP4mN8qR2sT6vX0z",
        ),
        (
            "pardot-api-credentials",
            "PARDOT_BUSINESS_UNIT_ID=0UvKp4mN8qR2sT6vX0",
        ),
        (
            "marketo-api-credentials",
            "MARKETO_CLIENT_SECRET=Kp4mN8qR2sT6vX0zW3yB5cD7fH9jK1",
        ),
    ];
    for (expect_id, text) in texts {
        s.clear_fragment_cache();
        let m = s.scan(&Chunk {
            data: text.into(),
            metadata: ChunkMetadata {
                source_type: "x".into(),
                path: Some("t.txt".into()),
                ..Default::default()
            },
        });
        println!(
            "--- scan {expect_id}: {} hits {:?}",
            m.len(),
            m.iter()
                .map(|x| format!("{}={}", x.detector_id, x.credential.as_ref()))
                .collect::<Vec<_>>()
        );
    }
}
