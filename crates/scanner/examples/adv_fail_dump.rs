use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use serde::Deserialize;

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
        let je = serde_json::to_string(text).unwrap();
        match self {
            Wrapper::DotEnv => format!("CREDENTIAL_PAYLOAD={text}\n"),
            Wrapper::Json => format!("{{\n  \"payload\": {je}\n}}\n"),
            Wrapper::Yaml => format!("payload: |\n  {text}\n"),
            Wrapper::Dockerfile => format!("FROM scratch\nENV PAYLOAD={text}\n"),
            Wrapper::ShellExport => format!("#!/usr/bin/env bash\nexport PAYLOAD={text}\n"),
            Wrapper::Ini => format!("[secrets]\npayload={text}\n"),
            Wrapper::GithubActions => format!(
                "name: ci\non: [push]\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    env:\n      PAYLOAD: {text}\n    steps:\n      - run: echo $PAYLOAD\n"
            ),
            Wrapper::KubernetesSecret => format!(
                "apiVersion: v1\nkind: Secret\nmetadata:\n  name: payload-secret\ntype: Opaque\nstringData:\n  payload: {text}\n"
            ),
        }
    }
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

fn main() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    let scanner = CompiledScanner::compile(keyhog_core::load_detectors(&d).unwrap()).unwrap();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/contracts");
    let out_path = std::env::var("ADV_FAIL_OUT").unwrap_or_else(|_| "/tmp/adv_fails.txt".into());
    let mut out = File::create(&out_path).unwrap();
    let mut total = 0usize;
    let mut fails = 0usize;
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if text.starts_with("version https://git-lfs.github.com/spec/v1") {
            continue;
        }
        let Ok(c) = toml::from_str::<Contract>(&text) else {
            continue;
        };
        for (pi, p) in c.positive.iter().enumerate() {
            for w in Wrapper::ALL {
                total += 1;
                let wrapped = w.wrap(&p.text);
                if !fires(&scanner, &wrapped, &p.credential) {
                    fails += 1;
                    let bare = fires(&scanner, &p.text, &p.credential);
                    writeln!(
                        out,
                        "{}\tbare_ok={}\twrapper={}\tpi={}\tcred={}",
                        c.detector_id, bare, w.label(), pi, p.credential
                    )
                    .unwrap();
                }
            }
        }
    }
    eprintln!("wrote {fails}/{total} failures to {out_path}");
}
