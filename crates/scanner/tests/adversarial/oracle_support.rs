//! Shared helpers for per-detector adversarial oracle tests (one `#[test]` per file).

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;
use std::sync::OnceLock;

pub fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

pub fn production_scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
        let mut config = keyhog_scanner::ScannerConfig::default();
        config.unicode_normalization = true;
        config.min_confidence = 0.0;
        CompiledScanner::compile(detectors)
            .expect("compile scanner")
            .with_config(config)
    })
}

pub fn scan_text(text: &str, path: &str) -> Vec<RawMatch> {
    let unescaped_text = unescape_rust_unicode(text);
    let chunk = Chunk {
        data: unescaped_text.into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    production_scanner().scan(&chunk)
}

fn unescape_rust_unicode(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' && chars.peek() == Some(&'u') {
            chars.next(); // consume 'u'
            if chars.peek() == Some(&'{') {
                chars.next(); // consume '{'
                let mut hex = String::new();
                let mut valid = false;
                while let Some(&next_ch) = chars.peek() {
                    if next_ch == '}' {
                        chars.next(); // consume '}'
                        valid = true;
                        break;
                    } else if next_ch.is_ascii_hexdigit() {
                        hex.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
                if valid {
                    if let Ok(code) = u32::from_str_radix(&hex, 16) {
                        if let Some(unicode_char) = char::from_u32(code) {
                            output.push(unicode_char);
                            continue;
                        }
                    }
                }
                output.push('\\');
                output.push('u');
                output.push('{');
                output.push_str(&hex);
                if valid {
                    output.push('}');
                }
            } else {
                output.push('\\');
                output.push('u');
            }
        } else {
            output.push(ch);
        }
    }
    output
}

pub fn hits_for_detector<'a>(matches: &'a [RawMatch], detector_id: &str) -> Vec<&'a RawMatch> {
    matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == detector_id)
        .collect()
}

pub fn assert_detector_fires(detector_id: &str, text: &str, credential: &str) {
    let matches = scan_text(text, &format!("{detector_id}-positive.txt"));
    assert!(
        matches.iter().any(|m| {
            let normalized =
                keyhog_scanner::unicode_hardening::normalize_homoglyphs(m.credential.as_ref());
            normalized == credential
        }),
        "{detector_id} must fire on positive oracle; credential={credential:?} all={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

pub fn assert_detector_silent(detector_id: &str, text: &str) {
    let matches = scan_text(text, &format!("{detector_id}-near-miss.txt"));
    let hits = hits_for_detector(&matches, detector_id);
    assert!(
        hits.is_empty(),
        "{detector_id} near-miss must NOT fire; got {:?} for text:\n{text}",
        hits.iter()
            .map(|m| m.credential.as_ref())
            .collect::<Vec<_>>()
    );
}

pub fn assert_detector_silent_across_chunk_boundary(detector_id: &str, text: &str) {
    let path = format!("{detector_id}-near-miss-chunk.txt");
    let pad = "z\n".repeat(4096);
    let len_a = pad.len();
    let chunk_a = Chunk {
        data: pad.into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some(path.clone()),
            base_offset: 0,
            ..Default::default()
        },
    };
    let chunk_b = Chunk {
        data: unescape_rust_unicode(text).into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some(path),
            base_offset: len_a,
            ..Default::default()
        },
    };
    production_scanner().clear_fragment_cache();
    let results = production_scanner().scan_coalesced(&[chunk_a, chunk_b]);
    let flat: Vec<RawMatch> = results.into_iter().flatten().collect();
    let hits = hits_for_detector(&flat, detector_id);
    assert!(
        hits.is_empty(),
        "{detector_id} near-miss must NOT fire across chunk boundary; got {:?} for text:\n{text}",
        hits.iter()
            .map(|m| m.credential.as_ref())
            .collect::<Vec<_>>()
    );
}

pub fn parity_keys(results: &[Vec<RawMatch>]) -> std::collections::BTreeSet<(String, String)> {
    results
        .iter()
        .flatten()
        .map(|m| {
            (
                m.detector_id.as_ref().to_string(),
                m.credential.as_ref().to_string(),
            )
        })
        .collect()
}
