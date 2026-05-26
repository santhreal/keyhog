use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
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

#[derive(Clone, Copy)]
enum Wrapper {
    DotEnv,
    Json,
    Yaml,
    Dockerfile,
    ShellExport,
    Ini,
    GithubActions,
    KubernetesSecret,
}
impl Wrapper {
    const ALL: &[Wrapper] = &[
        Wrapper::DotEnv,
        Wrapper::Json,
        Wrapper::Yaml,
        Wrapper::Dockerfile,
        Wrapper::ShellExport,
        Wrapper::Ini,
        Wrapper::GithubActions,
        Wrapper::KubernetesSecret,
    ];
    fn label(self) -> &'static str {
        match self {
            Wrapper::DotEnv => ".env",
            Wrapper::Json => "json",
            Wrapper::Yaml => "yaml",
            Wrapper::Dockerfile => "dockerfile",
            Wrapper::ShellExport => "shell-export",
            Wrapper::Ini => "ini",
            Wrapper::GithubActions => "github-actions",
            Wrapper::KubernetesSecret => "k8s-secret",
        }
    }
    fn wrap(self, text: &str) -> String {
        let json_escaped = serde_json::to_string(text).unwrap_or_else(|_| String::from("\"\""));
        match self {
            Wrapper::DotEnv => format!("CREDENTIAL_PAYLOAD={text}\n"),
            Wrapper::Json => format!("{{\n  \"payload\": {json_escaped}\n}}\n"),
            Wrapper::Yaml => format!("payload: |\n  {text}\n"),
            Wrapper::Dockerfile => format!("FROM scratch\nENV PAYLOAD={text}\n"),
            Wrapper::ShellExport => format!("#!/usr/bin/env bash\nexport PAYLOAD={text}\n"),
            Wrapper::Ini => format!("[secrets]\npayload={text}\n"),
            Wrapper::GithubActions => format!("name: ci\non: [push]\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    env:\n      PAYLOAD: {text}\n    steps:\n      - run: echo $PAYLOAD\n"),
            Wrapper::KubernetesSecret => format!("apiVersion: v1\nkind: Secret\nmetadata:\n  name: payload-secret\ntype: Opaque\nstringData:\n  payload: {text}\n"),
        }
    }
}

fn main() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    let scanner = CompiledScanner::compile(keyhog_core::load_detectors(&d).unwrap()).unwrap();
    let contracts_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/contracts");
    let mut by_detector: HashMap<String, usize> = HashMap::new();
    let mut by_wrapper: HashMap<String, usize> = HashMap::new();
    let mut empty = 0usize;
    let mut partial = 0usize;
    let mut total = 0usize;
    let mut samples: BTreeMap<String, String> = BTreeMap::new();
    for entry in std::fs::read_dir(&contracts_dir).unwrap().flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let c: Contract = toml::from_str(&text).unwrap();
        for p in &c.positive {
            for wrapper in Wrapper::ALL {
                total += 1;
                scanner.clear_fragment_cache();
                let wrapped = wrapper.wrap(&p.text);
                let chunk = Chunk {
                    data: wrapped.into(),
                    metadata: ChunkMetadata {
                        source_type: "adv".into(),
                        path: Some("x.txt".into()),
                        ..Default::default()
                    },
                };
                let matches = scanner.scan(&chunk);
                let ok = matches
                    .iter()
                    .any(|m| m.credential.as_ref().contains(&p.credential));
                if !ok {
                    *by_detector.entry(c.detector_id.clone()).or_default() += 1;
                    *by_wrapper.entry(wrapper.label().to_string()).or_default() += 1;
                    let saw: Vec<String> = matches
                        .iter()
                        .map(|m| m.credential.as_ref().to_string())
                        .collect();
                    if saw.is_empty() {
                        empty += 1;
                    } else {
                        partial += 1;
                    }
                    samples.entry(c.detector_id.clone()).or_insert_with(|| {
                        format!(
                            "wrapper={} cred={:?} saw={:?} contract={}",
                            wrapper.label(),
                            p.credential,
                            saw,
                            path.display()
                        )
                    });
                }
            }
        }
    }
    println!(
        "TOTAL={} FAIL={} EMPTY={} PARTIAL={}",
        total,
        by_detector.values().sum::<usize>(),
        empty,
        partial
    );
    println!("--- by detector ---");
    let mut v: Vec<_> = by_detector.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    for (d, n) in &v {
        println!("{n:4} {d}");
    }
    println!("--- by wrapper ---");
    let mut w: Vec<_> = by_wrapper.into_iter().collect();
    w.sort_by(|a, b| b.1.cmp(&a.1));
    for (d, n) in &w {
        println!("{n:4} {d}");
    }
    println!("--- samples ---");
    for (d, s) in samples {
        println!("{d}: {s}");
    }
}
