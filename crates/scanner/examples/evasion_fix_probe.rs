//! Probe candidate evasion wrappers for contracts whose evasion DROPPED.
use std::path::PathBuf;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Contract {
    detector_id: String,
    #[serde(default)]
    positive: Vec<Positive>,
    #[serde(default)]
    evasion: Vec<Positive>,
}

#[derive(Debug, Deserialize)]
struct Positive {
    text: String,
    credential: String,
}

fn candidates(positive_text: &str, credential: &str) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    let cred = credential.trim_matches('"');

    if positive_text.contains('=') {
        out.push(("env_bare", positive_text.to_string()));
        if let Some((k, v)) = positive_text.split_once('=') {
            let v = v.trim_matches('"');
            out.push(("yaml_inline", format!("{k}: {v}")));
            out.push(("bearer_env", format!("Authorization: Bearer {v}")));
            out.push(("dotenv", format!("{k}={v}")));
            if v != cred {
                out.push(("env_cred", format!("{k}={cred}")));
                out.push(("yaml_cred", format!("{k}: {cred}")));
            }
        }
        out.push(("yaml_block", format!("payload: |\n  {positive_text}")));
        out.push(("env_export", format!("export {positive_text}")));
    } else if let Some((k, v)) = positive_text.split_once(':') {
        let v = v.trim().trim_matches('"');
        out.push(("header_bare", positive_text.to_string()));
        out.push(("bearer", format!("Authorization: Bearer {v}")));
        out.push(("yaml_inline", format!("{k}: {v}")));
        out.push(("json_api_key", format!("{{\"api_key\":\"{v}\"}}")));
    } else {
        out.push(("anchor_bare", positive_text.to_string()));
        out.push(("yaml_block", format!("payload: |\n  {positive_text}")));
    }

    if credential.starts_with("http") || credential.contains("://") || positive_text.contains("://")
    {
        out.push(("yaml_url", format!("payload: |\n  {positive_text}")));
    }

    out.push(("yaml_block", format!("credentials: |\n  {positive_text}")));
    out.push((
        "xml_wrap",
        format!("<credentials>{positive_text}</credentials>"),
    ));
    out.push(("xml", format!("<token>{cred}</token>")));
    out.push(("xml_api_key", format!("<apiKey>{cred}</apiKey>")));
    out.push(("bearer", format!("Authorization: Bearer {cred}")));
    out.push(("json_cred", format!("{{\"api_key\":\"{cred}\"}}")));
    out
}

fn strip_comment_prefix(text: &str) -> Option<String> {
    let trimmed = text.trim_start();
    if let Some(rest) = trimmed.strip_prefix("# ") {
        return Some(rest.to_string());
    }
    if let Some(idx) = trimmed.find('\n') {
        let first = trimmed[..idx].trim();
        if first.starts_with('#') {
            return Some(trimmed[idx + 1..].trim_start().to_string());
        }
    }
    None
}

fn surfaces(scanner: &CompiledScanner, text: &str, credential: &str) -> bool {
    scanner.clear_fragment_cache();
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "probe".into(),
            path: Some("probe.txt".into()),
            ..Default::default()
        },
    };
    scanner
        .scan(&chunk)
        .iter()
        .any(|m| m.credential.as_ref().contains(credential))
}

fn main() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    let scanner = CompiledScanner::compile(keyhog_core::load_detectors(&d).unwrap()).unwrap();
    let contracts_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/contracts");

    let mut fixed = 0usize;
    let mut unfixed = 0usize;
    let mut pattern_counts: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();

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
        let Some(pos) = c.positive.first() else {
            continue;
        };
        let Some(eva) = c.evasion.first() else {
            continue;
        };
        // Match against positive credential — evasion field may drift from surfaced value.
        let target_cred = &pos.credential;
        if surfaces(&scanner, &eva.text, target_cred) {
            continue;
        }

        let mut found = None;
        let mut extra: Vec<(&'static str, String)> = Vec::new();
        if let Some(stripped) = strip_comment_prefix(&eva.text) {
            extra.push(("comment_stripped", stripped));
        }
        'outer: for pos in &c.positive {
            let mut cands = candidates(&pos.text, target_cred);
            cands.extend(extra.iter().map(|(l, t)| (*l, t.clone())));
            for (label, cand) in cands {
                if surfaces(&scanner, &cand, target_cred) {
                    found = Some((label, cand));
                    break 'outer;
                }
            }
        }
        if let Some((label, cand)) = found {
            fixed += 1;
            *pattern_counts.entry(label).or_default() += 1;
            println!(
                "OK\t{}\t{}\t{}",
                c.detector_id,
                label,
                cand.replace('\n', "\\n")
            );
        } else {
            unfixed += 1;
            println!("NO\t{}", c.detector_id);
        }
    }
    eprintln!("fixed={fixed} unfixed={unfixed} patterns={pattern_counts:?}");
}
