use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Contract { detector_id: String, #[serde(default)] positive: Vec<Positive> }
#[derive(Debug, Deserialize)]
struct Positive { text: String, credential: String }

#[derive(Clone, Copy)]
enum Wrapper { DotEnv, Json, Yaml, Dockerfile, ShellExport, Ini, GithubActions, KubernetesSecret }
impl Wrapper {
    const ALL: &[Wrapper] = &[Wrapper::DotEnv, Wrapper::Json, Wrapper::Yaml, Wrapper::Dockerfile, Wrapper::ShellExport, Wrapper::Ini, Wrapper::GithubActions, Wrapper::KubernetesSecret];
    fn label(self) -> &'static str {
        match self { Wrapper::DotEnv=>".env", Wrapper::Json=>"json", Wrapper::Yaml=>"yaml", Wrapper::Dockerfile=>"dockerfile", Wrapper::ShellExport=>"shell-export", Wrapper::Ini=>"ini", Wrapper::GithubActions=>"github-actions", Wrapper::KubernetesSecret=>"k8s-secret" }
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
            Wrapper::GithubActions => format!("name: ci\non: [push]\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    env:\n      PAYLOAD: {text}\n    steps:\n      - run: echo $PAYLOAD\n"),
            Wrapper::KubernetesSecret => format!("apiVersion: v1\nkind: Secret\nmetadata:\n  name: payload-secret\ntype: Opaque\nstringData:\n  payload: {text}\n"),
        }
    }
}

fn chunk(text: &str) -> Chunk {
    Chunk { data: text.into(), metadata: ChunkMetadata { source_type: "x".into(), path: Some("t.txt".into()), ..Default::default() } }
}
fn fires(scanner: &CompiledScanner, text: &str, cred: &str) -> bool {
    scanner.clear_fragment_cache();
    scanner.scan(&chunk(text)).iter().any(|m| m.credential.as_ref().contains(cred))
}

fn main() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR")); d.pop(); d.pop(); d.push("detectors");
    let scanner = CompiledScanner::compile(keyhog_core::load_detectors(&d).unwrap()).unwrap();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/contracts");
    let mut total = 0usize;
    let mut bare_fail = 0usize;
    let mut wrap_fail_e = 0usize; // bare ok, wrap fail
    let mut by_wrapper: HashMap<String, usize> = HashMap::new();
    let mut bare_fail_detectors: BTreeMap<String, usize> = BTreeMap::new();
    let mut e_detectors: BTreeMap<String, usize> = BTreeMap::new();
    let mut e_samples: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") { continue; }
        let Ok(text) = std::fs::read_to_string(&path) else { continue; };
        if text.starts_with("version https://git-lfs.github.com/spec/v1") {
            continue;
        }
        let Ok(c) = toml::from_str::<Contract>(&text) else { continue; };
        for p in &c.positive {
            let bare = fires(&scanner, &p.text, &p.credential);
            if !bare {
                bare_fail += Wrapper::ALL.len();
                *bare_fail_detectors.entry(c.detector_id.clone()).or_default() += Wrapper::ALL.len();
                total += Wrapper::ALL.len();
                continue;
            }
            for w in Wrapper::ALL {
                total += 1;
                let wrapped = fires(&scanner, &w.wrap(&p.text), &p.credential);
                if !wrapped {
                    wrap_fail_e += 1;
                    if wrap_fail_e <= 120 {
                        e_samples.push(format!(
                            "{} :: wrapper {} :: cred {:?}",
                            c.detector_id,
                            w.label(),
                            p.credential
                        ));
                    }
                    *by_wrapper.entry(w.label().to_string()).or_default() += 1;
                    *e_detectors.entry(c.detector_id.clone()).or_default() += 1;
                }
            }
        }
    }
    println!("TOTAL={total} BARE_FAIL={bare_fail} WRAP_FAIL_E={wrap_fail_e}");
    println!("ADVERSARIAL_MISS_EST={}", bare_fail + wrap_fail_e);
    println!("--- E by wrapper ---");
    let mut wv: Vec<_> = by_wrapper.into_iter().collect(); wv.sort_by(|a,b| b.1.cmp(&a.1));
    for (w,n) in &wv { println!("{n:4} {w}"); }
    println!("--- top bare-fail (C) detectors ---");
    let mut bv: Vec<_> = bare_fail_detectors.into_iter().collect(); bv.sort_by(|a,b| b.1.cmp(&a.1));
    for (d,n) in bv.iter().take(20) { println!("{n:4} {d}"); }
    println!("--- top E detectors ---");
    let mut ev: Vec<_> = e_detectors.into_iter().collect(); ev.sort_by(|a,b| b.1.cmp(&a.1));
    for (d,n) in ev.iter().take(20) { println!("{n:4} {d}"); }
    if !e_samples.is_empty() {
        println!("--- E samples ---");
        for s in e_samples.iter().take(60) {
            println!("{s}");
        }
    }
}
