//! Differential gate for the decode-recursion FOCUS restriction: windowing the
//! phase-2 pass on a decode sub-chunk to its decoded span (+margin) instead of
//! the whole spliced parent context must NEVER change the finding set. The
//! context outside the span was already scanned (and deduped) by the parent, so
//! only matches touching the decoded text are new, those start inside the focus
//! window and are preserved exactly (full splice kept for keyword_nearby / line
//! offsets / keyword AC). Scans each input with focus ON vs OFF, asserts equal.
//!
//! Big sweep:
//!   KEYHOG_GATE_PARITY_N=200000 cargo test --profile release-fast \
//!     -p keyhog-scanner --test decode_focus_parity -- --nocapture

use super::support;
use support::paths::{corpus_dir, corpus_files, detector_dir};

use base64::Engine;
use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};

struct Lcg(u64);
impl Lcg {
    fn next_u32(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) as u32
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u32() as usize) % n
        }
    }
}

// Secrets across literal-prefix (gateable homoglyph), no-literal shape, and
// site-specific detectors, plus a private-key block. Embedding them base64/hex
// encoded forces them through decode-recursion, where the focus restriction runs.
const TOKENS: &[&str] = &[
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB",
    "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789cd",
    "xoxb-1234567890-ABCDEFGHIJKLMNOPQRSTUVWX",
    "sk_live_0123456789abcdefABCDEFxyz0",
    "AKIAIOSFODNN7EXAMPLE",
    "glpat-abcdefghij1234567890ABCD",
    "key=AbCdEf0123456789AbCdEf0123 visualcrossing",
    "api_key=\"0123456789abcdef0123456789abcdef\" api.nasa.gov",
    "1/1234567890123456/abcdef0123456789abcdef0123456789",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj3aQ\n-----END RSA PRIVATE KEY-----",
];

const DETECTOR_IDS: &[&str] = &[
    "github-classic-pat",
    "github-oauth-access-token",
    "slack-bot-token",
    "stripe-secret-key",
    "aws-access-key",
    "gitlab-personal-access-token",
    "visualcrossing-api-key",
    "nasa-api-key",
    "private-key",
];

const DEFAULT_PARITY_N: usize = 256;
const DEFAULT_CORPUS_CAP: usize = 0;

// Filler with NO credential prefixes, sometimes carries a "keyword" token so the
// keyword_nearby signal interacts with the decoded text (the exact case the focus
// restriction must keep exact by computing signals over the full splice).
const FILLER: &[u8] =
    b"the quick brown fox token secret key api password value config path index name 0123\n";

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}
fn hexs(s: &str) -> String {
    s.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

fn gen(rng: &mut Lcg) -> Vec<u8> {
    let mut b = Vec::new();
    for _ in 0..rng.below(80) {
        b.push(FILLER[rng.below(FILLER.len())]);
    }
    let n_tokens = rng.below(3);
    for _ in 0..n_tokens {
        let tok = TOKENS[rng.below(TOKENS.len())];
        match rng.below(10) {
            0..=3 => {
                // base64-encoded inside an assignment (decode-recursion path)
                b.extend_from_slice(b"data = \"");
                b.extend_from_slice(b64(tok).as_bytes());
                b.extend_from_slice(b"\"\n");
            }
            4..=5 => {
                // hex-encoded
                b.extend_from_slice(b"blob: ");
                b.extend_from_slice(hexs(tok).as_bytes());
                b.push(b'\n');
            }
            _ => {
                b.extend_from_slice(tok.as_bytes());
                b.push(b'\n');
            }
        }
        for _ in 0..rng.below(50) {
            b.push(FILLER[rng.below(FILLER.len())]);
        }
    }
    b
}

fn deterministic_cases() -> Vec<Vec<u8>> {
    let mut cases = Vec::new();
    for token in TOKENS {
        cases.push(format!("data = \"{}\"\n", b64(token)).into_bytes());
        cases.push(format!("blob: {}\n", hexs(token)).into_bytes());
        cases.push(format!("prefix token secret {token} suffix\n").into_bytes());
    }
    cases
}

fn chunk_of(bytes: &[u8], label: &str) -> Chunk {
    Chunk {
        data: String::from_utf8_lossy(bytes).into_owned().into(),
        metadata: ChunkMetadata {
            source_type: "focus".into(),
            path: Some(label.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

fn canonical(m: &[Vec<RawMatch>]) -> Vec<(String, String, String)> {
    let mut v: Vec<_> = m
        .iter()
        .flatten()
        .map(|x| {
            (
                x.detector_id.to_string(),
                x.credential.to_string(),
                format!("{:?}", x.location),
            )
        })
        .collect();
    v.sort();
    v
}

fn scan_both(
    s: &CompiledScanner,
    c: &Chunk,
) -> (Vec<(String, String, String)>, Vec<(String, String, String)>) {
    keyhog_scanner::testing::set_decode_focus(&s, Some(true));
    s.clear_fragment_cache();
    let on = canonical(&[s.scan_with_backend(c, ScanBackend::CpuFallback)]);
    keyhog_scanner::testing::set_decode_focus(&s, Some(false));
    s.clear_fragment_cache();
    let off = canonical(&[s.scan_with_backend(c, ScanBackend::CpuFallback)]);
    (on, off)
}

fn diff_panic(label: &str, on: &[(String, String, String)], off: &[(String, String, String)]) {
    use std::collections::BTreeSet;
    let a: BTreeSet<_> = on.iter().collect();
    let o: BTreeSet<_> = off.iter().collect();
    eprintln!("DECODE-FOCUS DIVERGENCE {label}");
    for x in o.difference(&a) {
        eprintln!("  MISSING with focus (RECALL LOSS!): {x:?}");
    }
    for x in a.difference(&o) {
        eprintln!("  EXTRA with focus: {x:?}");
    }
    panic!("decode focus changed findings on {label}");
}

#[test]
fn decode_focus_parity_default() {
    let _telemetry_guard = super::super::telemetry_serial::lock();
    let mut detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    detectors.retain(|detector| DETECTOR_IDS.contains(&detector.id.as_str()));
    for id in DETECTOR_IDS {
        assert!(
            detectors.iter().any(|detector| detector.id == *id),
            "decode focus parity detector subset missing shipped detector {id}"
        );
    }
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let n: usize = std::env::var("KEYHOG_GATE_PARITY_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PARITY_N);
    let corpus_cap: usize = std::env::var("KEYHOG_GATE_PARITY_CORPUS_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_CORPUS_CAP);

    let deterministic_cases = deterministic_cases();
    for (i, b) in deterministic_cases.iter().enumerate() {
        let c = chunk_of(b, &format!("deterministic-{i}"));
        let (on, off) = scan_both(&scanner, &c);
        if on != off {
            eprintln!(
                "input: {:?}",
                String::from_utf8_lossy(&b[..b.len().min(240)])
            );
            diff_panic(&format!("deterministic-{i}"), &on, &off);
        }
    }
    let mut rng = Lcg(0xf0cad_e1234_5678);
    let mut checked = deterministic_cases.len();
    for i in 0..n {
        let b = gen(&mut rng);
        let c = chunk_of(&b, &format!("syn-{i}"));
        let (on, off) = scan_both(&scanner, &c);
        if on != off {
            eprintln!(
                "input: {:?}",
                String::from_utf8_lossy(&b[..b.len().min(240)])
            );
            diff_panic(&format!("syn-{i}"), &on, &off);
        }
        checked += 1;
    }

    if let Some(root) = corpus_dir() {
        let files = corpus_files(&root, corpus_cap);
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        let mut cur = Vec::new();
        for f in &files {
            cur.extend_from_slice(f);
            cur.push(b'\n');
            if cur.len() >= 16 * 1024 {
                chunks.push(std::mem::take(&mut cur));
            }
        }
        if !cur.is_empty() {
            chunks.push(cur);
        }
        for (i, c) in chunks.iter().enumerate() {
            let ch = chunk_of(c, &format!("corpus-{i}"));
            let (on, off) = scan_both(&scanner, &ch);
            if on != off {
                diff_panic(&format!("corpus-{i}"), &on, &off);
            }
            checked += 1;
        }
    }

    keyhog_scanner::testing::set_decode_focus(&scanner, None);
    eprintln!("decode_focus_parity: {checked} inputs, focus-on ≡ focus-off");
    assert!(
        checked >= n + TOKENS.len(),
        "expected random sweep plus deterministic token coverage, got {checked}"
    );
}
