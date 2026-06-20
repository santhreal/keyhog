//! Differential gate for confirmed shared-anchor localization.
//!
//! The optimized path verifies eligible triggered `ac_map` patterns at required
//! prefix candidate positions instead of walking the whole scan window. This
//! test compares that default path with a test-only scanner whose confirmed
//! anchor index is removed, proving the localized path is finding-identical to
//! the legacy whole-chunk extraction path.

use super::support;
use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use support::paths::detector_dir;

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

const TOKENS: &[&str] = &[
    "const stripe = \"sk_live_0123456789abcdefghijklmnopqrstuv\";",
    "let stripe_test = \"sk_test_0123456789abcdefghijklmnopqrstuv\";",
    "api_key = \"0123456789abcdef0123456789abcdef\"",
    "API_TOKEN = \"abcdefghijklmnopqrstuvwxyz0123456789\"",
    "key-[a-f0-9]{32} is just detector prose, not a real token",
    "AKIAIOSFODNN7EXAMPLE",
    "plain filler token secret api key without valid credential",
];

const FILLER: &[u8] =
    b"abcdefghijklmnopqrstuvwxyz 0123456789 \n\t=:;\"' config value path token secret key api\n";

fn gen(rng: &mut Lcg) -> Vec<u8> {
    let mut bytes = Vec::new();
    for _ in 0..rng.below(80) {
        bytes.push(FILLER[rng.below(FILLER.len())]);
    }
    for _ in 0..(rng.below(4) + 1) {
        bytes.extend_from_slice(TOKENS[rng.below(TOKENS.len())].as_bytes());
        bytes.push(b'\n');
        for _ in 0..rng.below(80) {
            bytes.push(FILLER[rng.below(FILLER.len())]);
        }
    }
    bytes
}

fn large_payload() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2 * 1024 * 1024);
    let filler = b"fn ordinary_function() { let x = compute_value(42); }\n";
    let secret = b"const api_key = \"sk_live_0123456789abcdefghijklmnopqrstuv\";\n";
    let mut since_secret = 0usize;
    while bytes.len() < 2 * 1024 * 1024 {
        if since_secret >= 64 * 1024 {
            bytes.extend_from_slice(secret);
            since_secret = 0;
        } else {
            bytes.extend_from_slice(filler);
            since_secret += filler.len();
        }
    }
    bytes.truncate(2 * 1024 * 1024);
    bytes
}

fn chunk_of(bytes: &[u8], label: &str) -> Chunk {
    Chunk {
        data: String::from_utf8_lossy(bytes).into_owned().into(),
        metadata: ChunkMetadata {
            source_type: "confirmed-anchor-parity".into(),
            path: Some(label.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

fn canonical(matches: &[Vec<RawMatch>]) -> Vec<(String, String, String)> {
    let mut rows: Vec<_> = matches
        .iter()
        .flatten()
        .map(|m| {
            (
                m.detector_id.to_string(),
                m.credential.to_string(),
                format!("{:?}", m.location),
            )
        })
        .collect();
    rows.sort();
    rows
}

fn scan(scanner: &CompiledScanner, chunk: &Chunk) -> Vec<(String, String, String)> {
    scanner.clear_fragment_cache();
    canonical(
        &scanner.scan_chunks_with_backend(std::slice::from_ref(chunk), ScanBackend::CpuFallback),
    )
}

#[test]
fn confirmed_anchor_parity_default() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors load");
    let anchored = CompiledScanner::compile(detectors.clone()).expect("anchored scanner compiles");
    assert!(
        keyhog_scanner::testing::confirmed_anchor_eligible_count(&anchored) > 0,
        "confirmed anchor index must cover at least one current ac_map pattern"
    );
    let mut baseline = CompiledScanner::compile(detectors).expect("baseline scanner compiles");
    keyhog_scanner::testing::disable_confirmed_anchor(&mut baseline);

    let n: usize = std::env::var("KEYHOG_CONFIRMED_ANCHOR_PARITY_N")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2_000);
    let mut rng = Lcg(0x9e37_79b9_7f4a_7c15);
    for i in 0..n {
        let bytes = gen(&mut rng);
        let chunk = chunk_of(&bytes, &format!("synthetic-{i}.rs"));
        let optimized = scan(&anchored, &chunk);
        let reference = scan(&baseline, &chunk);
        assert_eq!(
            optimized,
            reference,
            "confirmed anchor changed findings for synthetic case {i}: {}",
            String::from_utf8_lossy(&bytes[..bytes.len().min(200)])
        );
    }

    let large = chunk_of(&large_payload(), "large.rs");
    assert_eq!(scan(&anchored, &large), scan(&baseline, &large));
}
