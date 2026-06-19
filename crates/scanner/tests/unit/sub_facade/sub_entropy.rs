//! Standalone unit coverage for `keyhog_scanner::entropy` and
//! `keyhog_scanner::testing::entropy_fast` public functions.
//!
//! Positive / negative / boundary / adversarial cases that assert REAL numeric
//! values (Shannon bits within an epsilon, exact booleans, exact path verdicts),
//! never `!is_empty`-style decoration.

use keyhog_scanner::entropy::{
    is_entropy_appropriate, is_entropy_appropriate_with_content, normalized_entropy,
    shannon_entropy, HIGH_ENTROPY_THRESHOLD, LOW_ENTROPY_THRESHOLD, VERY_HIGH_ENTROPY_THRESHOLD,
};
use keyhog_scanner::testing::entropy_fast::{
    has_high_entropy_fast, shannon_entropy_scalar, shannon_entropy_simd,
};

const EPS: f64 = 1e-9;
/// The SIMD reductions (AVX2/AVX512/NEON) and the scalar path are allowed to
/// differ only in the last few float ULPs from FMA reassociation.
const SIMD_EPS: f64 = 1e-9;

fn approx(a: f64, b: f64, eps: f64) -> bool {
    (a - b).abs() <= eps
}

// ---------------------------------------------------------------------------
// shannon_entropy — known closed-form values
// ---------------------------------------------------------------------------

#[test]
fn shannon_empty_is_zero() {
    assert_eq!(shannon_entropy(b""), 0.0);
    assert_eq!(shannon_entropy_scalar(b""), 0.0);
    assert_eq!(shannon_entropy_simd(b""), 0.0);
}

#[test]
fn shannon_single_repeated_byte_is_zero() {
    // One symbol -> 0 bits/byte, exactly.
    assert!(approx(shannon_entropy(b"aaaaaaaa"), 0.0, EPS));
    assert!(approx(shannon_entropy(&[0x41; 100]), 0.0, EPS));
}

#[test]
fn shannon_two_equal_symbols_is_one_bit() {
    // 50/50 distribution -> exactly 1 bit/byte.
    let data = b"abababab"; // 4 'a', 4 'b'
    assert!(
        approx(shannon_entropy(data), 1.0, EPS),
        "got {}",
        shannon_entropy(data)
    );
}

#[test]
fn shannon_four_equal_symbols_is_two_bits() {
    // 4 distinct symbols, equal counts -> log2(4) = 2 bits/byte.
    let data = b"abcdabcdabcdabcd";
    assert!(
        approx(shannon_entropy(data), 2.0, EPS),
        "got {}",
        shannon_entropy(data)
    );
}

#[test]
fn shannon_256_distinct_bytes_is_eight_bits() {
    // Every byte value exactly once -> log2(256) = 8 bits/byte, the ceiling.
    let data: Vec<u8> = (0u16..256).map(|b| b as u8).collect();
    let h = shannon_entropy(&data);
    assert!(approx(h, 8.0, 1e-9), "got {}", h);
}

#[test]
fn shannon_two_symbols_skewed_distribution() {
    // 7 'a', 1 'b' over 8 bytes. H = -(7/8 log2 7/8 + 1/8 log2 1/8).
    let data = b"aaaaaaab";
    let p_a: f64 = 7.0 / 8.0;
    let p_b: f64 = 1.0 / 8.0;
    let expected = -(p_a * p_a.log2() + p_b * p_b.log2());
    assert!(
        approx(shannon_entropy(data), expected, EPS),
        "got {} want {}",
        shannon_entropy(data),
        expected
    );
}

#[test]
fn shannon_scalar_matches_simd_on_many_inputs() {
    // Differential: the dispatched SIMD path must agree with the pure scalar
    // reference on every shape (short, long, skewed, binary).
    let cases: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"a".to_vec(),
        b"hello world this is a test".to_vec(),
        b"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".to_vec(),
        (0u16..256).map(|b| b as u8).collect(),
        vec![0u8; 64], // all-null padding contract
        {
            // 1500 pseudo-random-ish bytes to exercise the >1024 uncached and
            // >255 active-len reduction path.
            let mut v = Vec::with_capacity(1500);
            let mut x: u32 = 0x1234_5678;
            for _ in 0..1500 {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                v.push((x >> 16) as u8);
            }
            v
        },
    ];
    for case in &cases {
        let s = shannon_entropy_scalar(case);
        let v = shannon_entropy_simd(case);
        assert!(
            approx(s, v, SIMD_EPS),
            "scalar {} vs simd {} diverged on len {}",
            s,
            v,
            case.len()
        );
    }
}

#[test]
fn shannon_caches_repeat_small_inputs_consistently() {
    // The <=1024 path is thread-local-cached; a repeat call must return the
    // identical value (no cache corruption / off-by-one).
    let data = b"correct horse battery staple 9F2k";
    let first = shannon_entropy(data);
    let second = shannon_entropy(data);
    assert_eq!(first, second);
    assert!(approx(first, shannon_entropy_scalar(data), SIMD_EPS));
}

#[test]
fn shannon_null_padding_contract_8byte_chunks() {
    // A trailing all-null 8-byte chunk is treated as padding and dropped, so a
    // value plus 8 nulls scores the same entropy as the value alone (over the
    // active bytes). Use a 16-byte value so the value occupies exactly 2 chunks.
    let value = b"ABCDEFGHabcdefgh"; // 16 distinct -> log2(16)=4 over active
    let mut padded = value.to_vec();
    padded.extend_from_slice(&[0u8; 8]);
    let h_value = shannon_entropy(value);
    let h_padded = shannon_entropy(&padded);
    assert!(
        approx(h_value, h_padded, EPS),
        "padding-stripped entropy mismatch: {} vs {}",
        h_value,
        h_padded
    );
}

// ---------------------------------------------------------------------------
// normalized_entropy — rescaled to 0..1
// ---------------------------------------------------------------------------

#[test]
fn normalized_empty_is_zero() {
    assert_eq!(normalized_entropy(b""), 0.0);
}

#[test]
fn normalized_single_symbol_is_zero() {
    // <=1 unique byte -> 0.0 by definition (no division by log2(1)=0).
    assert_eq!(normalized_entropy(b"aaaaaa"), 0.0);
}

#[test]
fn normalized_uniform_distribution_is_one() {
    // 4 equal symbols: raw entropy 2 bits, max possible log2(4)=2 -> 1.0.
    let h = normalized_entropy(b"abcdabcdabcdabcd");
    assert!(approx(h, 1.0, EPS), "got {}", h);
}

#[test]
fn normalized_is_bounded_unit_interval() {
    let samples: &[&[u8]] = &[
        b"abc",
        b"aaaab",
        b"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",
        b"the quick brown fox jumps over the lazy dog",
    ];
    for s in samples {
        let h = normalized_entropy(s);
        assert!((0.0..=1.0).contains(&h), "out of range: {} for {:?}", h, s);
    }
}

// ---------------------------------------------------------------------------
// has_high_entropy_fast — sound early-exit predicate
// ---------------------------------------------------------------------------

#[test]
fn high_entropy_fast_rejects_low_entropy() {
    // Single distinct byte: ceiling log2(1) = -inf < any threshold -> false.
    assert!(!has_high_entropy_fast(b"aaaaaaaaaaaaaaaa", 4.5));
    // Two distinct symbols cap at log2(2)=1 bit; cannot clear 4.5.
    assert!(!has_high_entropy_fast(b"ababababababab", 4.5));
}

#[test]
fn high_entropy_fast_accepts_high_entropy() {
    // 256 distinct bytes -> 8 bits/byte, clears 4.5 and even 7.9.
    let data: Vec<u8> = (0u16..256).map(|b| b as u8).collect();
    assert!(has_high_entropy_fast(&data, 4.5));
    assert!(has_high_entropy_fast(&data, 7.9));
    assert!(!has_high_entropy_fast(&data, 8.1)); // above the 8.0 ceiling
}

#[test]
fn high_entropy_fast_agrees_with_direct_entropy() {
    // The fast predicate must equal `shannon_entropy >= threshold` for inputs
    // whose distinct-byte ceiling permits the threshold (no false early exit).
    let cases: Vec<Vec<u8>> = vec![
        b"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".to_vec(),
        b"hello world".to_vec(),
        (0u16..64).map(|b| b as u8).collect(),
    ];
    for thr in [3.0_f64, 4.5, 5.0] {
        for case in &cases {
            let fast = has_high_entropy_fast(case, thr);
            let direct = shannon_entropy_scalar(case) >= thr;
            assert_eq!(
                fast,
                direct,
                "threshold {} len {} fast {} direct {}",
                thr,
                case.len(),
                fast,
                direct
            );
        }
    }
}

// ---------------------------------------------------------------------------
// is_entropy_appropriate — path gating truth table
// ---------------------------------------------------------------------------

#[test]
fn entropy_appropriate_no_path_is_true() {
    assert!(is_entropy_appropriate(None, false));
    assert!(is_entropy_appropriate(None, true));
}

#[test]
fn entropy_appropriate_lock_and_map_hard_off() {
    assert!(!is_entropy_appropriate(Some("Cargo.lock"), true));
    assert!(!is_entropy_appropriate(Some("bundle.js.map"), true));
    assert!(!is_entropy_appropriate(Some("yarn.lock"), false));
}

#[test]
fn entropy_appropriate_minified_hard_off() {
    assert!(!is_entropy_appropriate(Some("app.min.js"), true));
    assert!(!is_entropy_appropriate(Some("style.min.css"), true));
}

#[test]
fn entropy_appropriate_config_files_on() {
    for p in [
        ".env",
        "prod.env",
        "config.yaml",
        "settings.yml",
        "app.toml",
        "service.properties",
        "main.cfg",
        "nginx.conf",
        "app.ini",
        "secrets.pem",
        "id_rsa.key",
        "terraform.tfvars",
        "infra.hcl",
    ] {
        assert!(
            is_entropy_appropriate(Some(p), false),
            "expected config file {} to be entropy-appropriate",
            p
        );
    }
}

#[test]
fn entropy_appropriate_source_files_off_without_allow() {
    // A plain .rs source file is OFF unless allow_source_files is set.
    assert!(!is_entropy_appropriate(Some("src/main.rs"), false));
    assert!(is_entropy_appropriate(Some("src/main.rs"), true));
    assert!(!is_entropy_appropriate(Some("app.go"), false));
}

#[test]
fn entropy_appropriate_package_manifests_off() {
    // Manifests are OFF even with allow_source_files because their keyword
    // arrays look high-entropy but are package metadata.
    for p in [
        "Cargo.toml",
        "package.json",
        "pyproject.toml",
        "pom.xml",
        "build.gradle",
        "Gemfile",
    ] {
        assert!(
            !is_entropy_appropriate(Some(p), false),
            "manifest {} must be OFF",
            p
        );
    }
}

#[test]
fn entropy_appropriate_secrets_rs_off_but_secrets_yaml_on() {
    // `secrets.rs` is source code ABOUT credentials, not a credential file.
    assert!(!is_entropy_appropriate(Some("tui/secrets.rs"), false));
    // `secrets.yaml` IS a config/secret file.
    assert!(is_entropy_appropriate(Some("k8s/secrets.yaml"), false));
    // Exact stem `secrets` (no extension) counts.
    assert!(is_entropy_appropriate(Some("secrets"), false));
}

#[test]
fn entropy_appropriate_with_content_lifts_json_only_with_keyword() {
    let keywords = vec!["api_key".to_string(), "secret".to_string()];
    // Plain .json with no keyword assignment line -> OFF.
    assert!(!is_entropy_appropriate_with_content(
        Some("data.json"),
        false,
        "{\"colors\": [\"red\", \"green\"]}",
        &keywords,
    ));
    // .json WITH a secret-keyword assignment line -> lifted ON.
    assert!(is_entropy_appropriate_with_content(
        Some("config.json"),
        false,
        "{\"api_key\": \"AKIAEXAMPLE0000\"}",
        &keywords,
    ));
}

#[test]
fn entropy_appropriate_with_content_lifts_source_with_keyword() {
    let keywords = vec!["apikey".to_string()];
    // A go source file with a const apiKey assignment is lifted ON.
    let src = "package main\nconst apiKey = \"abc123def456ghi789\"\n";
    assert!(is_entropy_appropriate_with_content(
        Some("client.go"),
        false,
        src,
        &keywords,
    ));
    // The same source file with no keyword line stays OFF.
    let plain = "package main\nfunc main() {}\n";
    assert!(!is_entropy_appropriate_with_content(
        Some("client.go"),
        false,
        plain,
        &keywords,
    ));
}

// ---------------------------------------------------------------------------
// Threshold constants — documented ordering invariants
// ---------------------------------------------------------------------------

#[test]
fn entropy_threshold_constants_ordered() {
    assert!(LOW_ENTROPY_THRESHOLD < HIGH_ENTROPY_THRESHOLD);
    assert!(HIGH_ENTROPY_THRESHOLD < VERY_HIGH_ENTROPY_THRESHOLD);
    assert_eq!(LOW_ENTROPY_THRESHOLD, 3.0);
    assert_eq!(HIGH_ENTROPY_THRESHOLD, 4.5);
    assert_eq!(VERY_HIGH_ENTROPY_THRESHOLD, 5.8);
}
