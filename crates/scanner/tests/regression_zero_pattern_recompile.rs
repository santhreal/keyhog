//! #134 perf regression gate: a `CompiledScanner` compiles every pattern AT MOST
//! ONCE for its lifetime, so scanning many chunks (the "many files" workload)
//! rebuilds zero regexes after warm-up. This locks the #13 fix ("cache the
//! pattern compile"); a regression that reintroduced per-scan `Regex::new` would
//! make the process-wide `LazyRegex` compile-event counter climb across scans.
//!
//! Mechanism: detector patterns are seeded eagerly at `compile()` (their
//! `OnceLock` is pre-filled and never runs the init closure), and lazy
//! regexes (multiline / decode / generic-assignment / shared) compile at most
//! once on first touch. `testing::lazy_regex_compile_events()` counts only those
//! real first-use compilations. The gate primes a chunk (one scan, which may
//! compile that chunk's lazy paths once), snapshots the counter, then re-scans
//! and asserts the counter does not move. Run `--test-threads=1` so the global
//! counter's deltas are not perturbed by another test compiling concurrently.

mod support;

use keyhog_core::Chunk;
use keyhog_scanner::testing::lazy_regex_compile_events;
use keyhog_scanner::CompiledScanner;
use std::sync::OnceLock;
use support::contracts::{make_chunk, scanner};

/// One shared scanner, warmed once. `warm()` forces first-touch compilation of
/// the lazy regex caches so that, combined with a per-chunk priming scan, the
/// measured re-scans operate entirely on already-compiled regexes.
fn primed() -> &'static CompiledScanner {
    static S: OnceLock<CompiledScanner> = OnceLock::new();
    S.get_or_init(|| {
        let s = scanner();
        s.warm();
        s
    })
}

fn chunk(text: &str) -> Chunk {
    make_chunk(text, "filesystem", "recompile.txt")
}

/// Scan `text` once to prime its lazy paths, then re-scan it `rounds` times and
/// assert the process-wide compile-event counter never advanced, i.e. the
/// re-scans recompiled nothing.
fn assert_rescan_recompiles_nothing(text: &str, rounds: usize) {
    let s = primed();
    let c = chunk(text);
    s.clear_fragment_cache();
    let _ = s.scan(&c); // prime this chunk's lazy regex paths (compile-at-most-once)
    let before = lazy_regex_compile_events();
    for _ in 0..rounds {
        s.clear_fragment_cache();
        let _ = s.scan(&c);
    }
    let after = lazy_regex_compile_events();
    assert_eq!(
        after, before,
        "re-scanning recompiled {} regex(es) for {text:?}, pattern compile is not cached across scans",
        after - before
    );
}

// ── representative content classes: re-scanning recompiles nothing ───────────

#[test]
fn rescan_zero_aws_credentials() {
    assert_rescan_recompiles_nothing(
        "[default]\naws_access_key_id = AKIAZ7QH4XNB2WKLP3RV\naws_secret_access_key = wJalrXUtnFEMI7K8MDENGbPxRfiCYEXKEYAAAA\n",
        5,
    );
}

#[test]
fn rescan_zero_gcp_service_account_json() {
    assert_rescan_recompiles_nothing(
        "{\n  \"type\": \"service_account\",\n  \"project_id\": \"demo-proj-7788\",\n  \"private_key\": \"-----BEGIN PRIVATE KEY-----\\nMIIEvAIB\\n-----END PRIVATE KEY-----\\n\"\n}",
        5,
    );
}

#[test]
fn rescan_zero_gitlab_tokens() {
    assert_rescan_recompiles_nothing(
        "GITLAB_TOKEN=glpat-Ab3Cd6Ef9Gh2Ij5Kl8Mn\nKAS_TOKEN=glagent-Hx7Kp2Qm9Rn4Sb6Tw8Vz1Yc3\n",
        5,
    );
}

#[test]
fn rescan_zero_jwt() {
    assert_rescan_recompiles_nothing(
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.abcDEF0123456789xyz",
        5,
    );
}

#[test]
fn rescan_zero_pem_private_key() {
    assert_rescan_recompiles_nothing(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJK\n-----END RSA PRIVATE KEY-----\n",
        5,
    );
}

#[test]
fn rescan_zero_url_credentials() {
    assert_rescan_recompiles_nothing(
        "DATABASE_URL=postgres://app:Pg5ecretPass99Xy@db.example.com:5432/mydb\n",
        5,
    );
}

#[test]
fn rescan_zero_base64_wrapped_secret() {
    // Exercises the decode-through path (a base64 blob the scanner may decode).
    assert_rescan_recompiles_nothing(
        "token: QUtJQVo3UUg0WE5CMldLTFAzUlY= secret: d0phbHJYVXRuRkVNSTdLOE1ERU5HYlB4UmZpQ1k=",
        5,
    );
}

#[test]
fn rescan_zero_multiline_concat() {
    // Exercises the multiline string-concatenation preprocessor path.
    assert_rescan_recompiles_nothing(
        "const KEY = \"AKIA\" +\n  \"Z7QH4XNB2W\" +\n  \"KLP3RV\";\nSECRET = 'abc' . 'def' . 'ghijklmnop';",
        5,
    );
}

#[test]
fn rescan_zero_unicode_homoglyph() {
    // Exercises the unicode-normalization / homoglyph fold path.
    assert_rescan_recompiles_nothing(
        "ＡＫＩＡ\u{200b}password\u{0301} = \"S3cr3tＶalue1234567890\"\n",
        5,
    );
}

#[test]
fn rescan_zero_binary_like_bytes() {
    assert_rescan_recompiles_nothing(
        "\x00\x01\x02ELF\x7f binary\x00 AKIAZ7QH4XNB2WKLP3RV \x00\x1b embedded",
        5,
    );
}

#[test]
fn rescan_zero_empty_chunk() {
    assert_rescan_recompiles_nothing("", 5);
}

#[test]
fn rescan_zero_large_repeated_chunk() {
    let text = "password=Sup3rSecretValue12345 ".repeat(4096);
    assert_rescan_recompiles_nothing(&text, 3);
}

#[test]
fn rescan_zero_high_entropy_random() {
    assert_rescan_recompiles_nothing("api_key = 7Hx9Kp2Qm4Rn8Sb6Tw1Vz3Yc5Ad0Be7Cf2Dg9Eh4Fi6Gj", 5);
}

#[test]
fn rescan_zero_kitchen_sink() {
    let text = concat!(
        "AKIAZ7QH4XNB2WKLP3RV glpat-Ab3Cd6Ef9Gh2Ij5Kl8Mn ",
        "postgres://u:Pg5ecretPass99Xy@h/db GOCSPX-Me6Qq1St5Uv2Wy8Ab4Zd ",
        "-----BEGIN PRIVATE KEY-----\\nMIIE\\n-----END PRIVATE KEY-----\\n ",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig AZURE_CLIENT_SECRET=Xy8Q~kPv3mNz.aB7dEfGhIjKlMnOpQ"
    );
    assert_rescan_recompiles_nothing(text, 5);
}

// ── structural invariants ─────────────────────────────────────────────────────

#[test]
fn warm_is_idempotent_compiles_nothing() {
    let s = primed(); // already warmed once in the OnceLock initializer
    let before = lazy_regex_compile_events();
    s.warm();
    s.warm();
    let after = lazy_regex_compile_events();
    assert_eq!(
        after,
        before,
        "a redundant warm() recompiled {} regex(es)",
        after - before
    );
}

#[test]
fn fifty_rescans_compile_nothing() {
    let s = primed();
    let c = chunk(
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI7K8MDENGbPxRfiCYEXKEYAAAA password=Hunter2Value99",
    );
    s.clear_fragment_cache();
    let _ = s.scan(&c);
    let before = lazy_regex_compile_events();
    for _ in 0..50 {
        s.clear_fragment_cache();
        let _ = s.scan(&c);
    }
    assert_eq!(
        lazy_regex_compile_events(),
        before,
        "50 re-scans recompiled a regex"
    );
}

#[test]
fn cold_first_scan_then_warm_rescans_compile_nothing() {
    // The "cold vs warm" measurement: the first scan of a chunk may compile its
    // lazy paths once; every subsequent (warm) scan must recompile nothing.
    let s = primed();
    let c = chunk(
        "token: glsoat-Kc4Np8Qr3St9Uw6Xz2Yb5Bd7E client_secret=Xy8Q~kPv3mNz.aB7dEfGhIjKlMnOp",
    );
    s.clear_fragment_cache();
    let _ = s.scan(&c); // cold for this chunk's lazy paths
    let warm0 = lazy_regex_compile_events();
    s.clear_fragment_cache();
    let _ = s.scan(&c); // warm
    let warm1 = lazy_regex_compile_events();
    assert_eq!(
        warm1,
        warm0,
        "the warm re-scan recompiled {} regex(es)",
        warm1 - warm0
    );
}

#[test]
fn distinct_primed_files_in_sequence_compile_nothing() {
    let s = primed();
    let texts = [
        "AKIAZ7QH4XNB2WKLP3RV",
        "glpat-Ab3Cd6Ef9Gh2Ij5Kl8Mn",
        "postgres://u:Pg5ecretPass99Xy@h/db",
        "-----BEGIN PRIVATE KEY-----\\nMIIE\\n-----END PRIVATE KEY-----\\n",
        "AZURE_CLIENT_SECRET=Xy8Q~kPv3mNz.aB7dEfGhIjKlMnOpQ",
    ];
    // Prime each distinct file once.
    for t in texts {
        let c = chunk(t);
        s.clear_fragment_cache();
        let _ = s.scan(&c);
    }
    let before = lazy_regex_compile_events();
    // Now scan the whole sequence again: a real multi-file scan, zero recompiles.
    for t in texts {
        let c = chunk(t);
        s.clear_fragment_cache();
        let _ = s.scan(&c);
    }
    assert_eq!(
        lazy_regex_compile_events(),
        before,
        "scanning a primed file sequence recompiled a regex"
    );
}

#[test]
fn clearing_fragment_cache_does_not_recompile_patterns() {
    // Clearing the per-chunk fragment memo must not touch the regex OnceLocks.
    let s = primed();
    let c = chunk("password=Sup3rSecretValue12345 AKIAZ7QH4XNB2WKLP3RV");
    s.clear_fragment_cache();
    let _ = s.scan(&c);
    let before = lazy_regex_compile_events();
    for _ in 0..10 {
        s.clear_fragment_cache();
    }
    s.clear_fragment_cache();
    let _ = s.scan(&c);
    assert_eq!(
        lazy_regex_compile_events(),
        before,
        "clearing the fragment cache recompiled a regex"
    );
}

#[test]
fn compile_event_counter_is_monotonic_non_decreasing() {
    // The observable only ever ticks forward on a real compile; it never resets.
    let a = lazy_regex_compile_events();
    let s = primed();
    s.clear_fragment_cache();
    let _ = s.scan(&chunk("just some text without obvious secrets"));
    let b = lazy_regex_compile_events();
    assert!(b >= a, "compile-event counter went backwards: {a} -> {b}");
}

#[test]
fn second_scanner_from_same_corpus_rescans_compile_nothing() {
    // The compile-once guarantee is per-scanner: a freshly built, warmed scanner
    // also reaches steady state with zero recompiles on re-scan.
    let fresh = scanner();
    fresh.warm();
    let c = chunk("AKIAZ7QH4XNB2WKLP3RV glpat-Ab3Cd6Ef9Gh2Ij5Kl8Mn password=Hunter2Value99");
    fresh.clear_fragment_cache();
    let _ = fresh.scan(&c);
    let before = lazy_regex_compile_events();
    for _ in 0..5 {
        fresh.clear_fragment_cache();
        let _ = fresh.scan(&c);
    }
    assert_eq!(
        lazy_regex_compile_events(),
        before,
        "a second scanner recompiled a regex on re-scan"
    );
}

#[test]
fn interleaved_diverse_chunks_after_priming_compile_nothing() {
    let s = primed();
    let primers = [
        "AKIAZ7QH4XNB2WKLP3RV",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
        "QUtJQVo3UUg0WE5CMldLTFAzUlY=",
    ];
    for t in primers {
        s.clear_fragment_cache();
        let _ = s.scan(&chunk(t));
    }
    let before = lazy_regex_compile_events();
    for _ in 0..3 {
        for t in primers {
            s.clear_fragment_cache();
            let _ = s.scan(&chunk(t));
        }
    }
    assert_eq!(
        lazy_regex_compile_events(),
        before,
        "interleaved diverse re-scans recompiled a regex"
    );
}
