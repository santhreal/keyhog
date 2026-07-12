//! CPU-tier backend trigger parity: `ScanBackend::CpuFallback` (the pure-CPU
//! "scalar" vyre AC + regex path) vs `ScanBackend::SimdCpu` (the Hyperscan/SIMD
//! prefilter path) MUST surface the byte-identical finding set on the same
//! input.
//!
//! The two CPU backends reach the regex confirmation stage through DIFFERENT
//! trigger collectors: `SimdCpu` routes candidate positions through the
//! Hyperscan multi-pattern NFA + SIMD prefilter, while `CpuFallback` uses the
//! vyre Aho-Corasick literal set. A detector whose keywords land in the AC
//! literal set (e.g. `aws-access-key`, keyword `AKIA`) and one that has NO
//! standalone literal-prefix and fires only once the regex confirms an
//! in-window vendor fingerprint (`twilio-auth-token`) must BOTH yield the same
//! `(detector_id, credential, absolute_offset)` triples on either backend — a
//! divergence is a real recall/precision bug in one collector, not a nuance.
//!
//! Host-independence: this file asserts CPU-vs-CPU parity only — never the GPU
//! path. `SimdCpu` is gated on `warm_backend`, because on a build without the
//! `simd` feature (or a host whose Hyperscan DB failed to build) a forced
//! `SimdCpu` scan hard-exits the process by contract; when it is unavailable we
//! still assert the concrete `CpuFallback` finding values and report the skipped
//! SIMD leg loudly (CLAUDE.md Law 10).

mod support;
use std::collections::BTreeSet;
use support::paths::detector_dir;

use keyhog_core::{load_detectors, Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};

// ---- fixtures / shared helpers ------------------------------------------------

fn scanner() -> CompiledScanner {
    let detectors = load_detectors(&detector_dir()).expect("load on-disk detectors");
    CompiledScanner::compile(detectors).expect("compile scanner")
}

fn chunk(text: &str, path: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some(path.into()),
            ..Default::default()
        },
    }
}

fn chunk_at(text: &str, path: &str, base_offset: usize) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some(path.into()),
            base_offset,
            ..Default::default()
        },
    }
}

/// Reset cross-file state, then scan on a specific backend. Every parity leg
/// clears first so a reused scanner never leaks fragment state between backends.
fn run(sc: &CompiledScanner, chunks: &[Chunk], backend: ScanBackend) -> Vec<Vec<RawMatch>> {
    sc.clear_fragment_cache();
    sc.scan_chunks_with_backend(chunks, backend)
}

/// `(detector_id, credential, absolute_offset)` triples — the exact parity key.
fn triples(results: &[Vec<RawMatch>]) -> BTreeSet<(String, String, usize)> {
    results
        .iter()
        .flat_map(|c| c.iter())
        .map(|m| {
            (
                m.detector_id.as_ref().to_string(),
                m.credential.as_ref().to_string(),
                m.location.offset,
            )
        })
        .collect()
}

/// `(detector_id, credential)` pairs — offset-independent membership checks.
fn pairs(results: &[Vec<RawMatch>]) -> BTreeSet<(String, String)> {
    results
        .iter()
        .flat_map(|c| c.iter())
        .map(|m| {
            (
                m.detector_id.as_ref().to_string(),
                m.credential.as_ref().to_string(),
            )
        })
        .collect()
}

fn count_detector(results: &[Vec<RawMatch>], id: &str) -> usize {
    results
        .iter()
        .flat_map(|c| c.iter())
        .filter(|m| m.detector_id.as_ref() == id)
        .count()
}

/// All offsets a given detector surfaced at.
fn offsets_of(results: &[Vec<RawMatch>], id: &str) -> Vec<usize> {
    results
        .iter()
        .flat_map(|c| c.iter())
        .filter(|m| m.detector_id.as_ref() == id)
        .map(|m| m.location.offset)
        .collect()
}

/// Run the SAME chunks on both CPU backends. The SIMD leg is `None` only when
/// this build/host has no usable Hyperscan prefilter (feature `simd` off or the
/// database failed to build) — forcing `SimdCpu` there would hard-exit the
/// process, so we gate on the side-effect-free `warm_backend` probe.
fn both_cpu_backends(
    sc: &CompiledScanner,
    chunks: &[Chunk],
) -> (Vec<Vec<RawMatch>>, Option<Vec<Vec<RawMatch>>>) {
    let scalar = run(sc, chunks, ScanBackend::CpuFallback);
    let simd = if sc.warm_backend(ScanBackend::SimdCpu) {
        Some(run(sc, chunks, ScanBackend::SimdCpu))
    } else {
        eprintln!(
            "SKIP simd leg: ScanBackend::SimdCpu unavailable on this build/host \
             (no usable Hyperscan prefilter); asserting CpuFallback values only"
        );
        None
    };
    (scalar, simd)
}

const AWS_KEY: &str = "AKIAQYLPMN5HFIQR7XYA";
// Known-valid classic PAT: `ghp_` + 36 chars with a CORRECT trailing CRC32
// checksum, so it clears the shipped `GithubClassicPatValidator` gate. The
// previous fixture `ghp_aBcD1234EFgh5678ijklMNop9012qrSTuvWX` was fabricated
// with a bad checksum — once checksum wiring landed it was silently dropped, so
// `github-classic-pat` surfaced zero findings and this (CI-orphaned) parity
// suite failed. This is the same canonical token as `regression_github_pat_
// boundary::GHP_VALID` (see keyhog checksum-fixture contract).
const GHP_TOKEN: &str = "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";
const TWILIO_AUTH_TOKEN: &str = "4c9a8f6e3b7d1a2c5e8f0b9d6a3c4e1f";

// A Twilio account_sid + auth_token env-pair; the required `account_sid`
// companion (`AC` + 32 hex) is present, so `twilio-auth-token` surfaces. This
// is the shipped companion-contract positive shape.
const TWILIO_PAIR: &str = "TWILIO_ACCOUNT_SID=AC1b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\n\
     TWILIO_AUTH_TOKEN=4c9a8f6e3b7d1a2c5e8f0b9d6a3c4e1f\n";

// ---- tests --------------------------------------------------------------------

#[test]
fn aws_ac_literal_scalar_and_simd_identical_triples() {
    let sc = scanner();
    let chunks = vec![chunk(
        "const AWS_KEY = \"AKIAQYLPMN5HFIQR7XYA\";\n",
        "aws.rs",
    )];
    let (scalar, simd) = both_cpu_backends(&sc, &chunks);

    // Concrete scalar values (always asserted).
    assert_eq!(
        count_detector(&scalar, "aws-access-key"),
        1,
        "CpuFallback must surface exactly one aws-access-key finding"
    );
    assert!(
        pairs(&scalar).contains(&("aws-access-key".to_string(), AWS_KEY.to_string())),
        "CpuFallback must surface the AKIA key with its exact credential bytes"
    );

    if let Some(simd) = simd {
        assert_eq!(
            triples(&scalar),
            triples(&simd),
            "AC-literal detector: CpuFallback vs SimdCpu triple sets must be identical"
        );
        assert_eq!(count_detector(&simd, "aws-access-key"), 1);
    }
}

#[test]
fn aws_credential_bytes_exact_on_both_cpu_backends() {
    let sc = scanner();
    let chunks = vec![chunk(
        "aws_access_key_id = AKIAQYLPMN5HFIQR7XYA\n",
        "config.ini",
    )];
    let (scalar, simd) = both_cpu_backends(&sc, &chunks);

    let scalar_creds: BTreeSet<String> = scalar
        .iter()
        .flat_map(|c| c.iter())
        .filter(|m| m.detector_id.as_ref() == "aws-access-key")
        .map(|m| m.credential.as_ref().to_string())
        .collect();
    assert_eq!(
        scalar_creds,
        BTreeSet::from([AWS_KEY.to_string()]),
        "CpuFallback aws-access-key credential set must be exactly the one AKIA key"
    );

    if let Some(simd) = simd {
        let simd_creds: BTreeSet<String> = simd
            .iter()
            .flat_map(|c| c.iter())
            .filter(|m| m.detector_id.as_ref() == "aws-access-key")
            .map(|m| m.credential.as_ref().to_string())
            .collect();
        assert_eq!(
            simd_creds, scalar_creds,
            "SimdCpu aws-access-key credentials must match CpuFallback exactly"
        );
    }
}

#[test]
fn twilio_auth_token_hs_only_scalar_and_simd_identical_triples() {
    let sc = scanner();
    let chunks = vec![chunk(TWILIO_PAIR, "twilio.env")];
    let (scalar, simd) = both_cpu_backends(&sc, &chunks);

    // The auth-token credential surfaces via the regex-confirm path (no
    // standalone literal prefix); assert it is present on CpuFallback.
    assert!(
        pairs(&scalar).contains(&(
            "twilio-auth-token".to_string(),
            TWILIO_AUTH_TOKEN.to_string()
        )),
        "CpuFallback must surface the Twilio auth token once the companion gate is satisfied"
    );

    if let Some(simd) = simd {
        assert_eq!(
            triples(&scalar),
            triples(&simd),
            "HS-only detector twilio-auth-token: CpuFallback vs SimdCpu triple sets must be identical"
        );
        assert!(pairs(&simd).contains(&(
            "twilio-auth-token".to_string(),
            TWILIO_AUTH_TOKEN.to_string()
        )));
    }
}

#[test]
fn twilio_auth_token_present_on_both_backends() {
    let sc = scanner();
    let chunks = vec![chunk(TWILIO_PAIR, "twilio.env")];
    let (scalar, simd) = both_cpu_backends(&sc, &chunks);

    assert!(
        count_detector(&scalar, "twilio-auth-token") >= 1,
        "CpuFallback must fire twilio-auth-token at least once for the companion-satisfied pair"
    );
    let scalar_has_token = scalar.iter().flat_map(|c| c.iter()).any(|m| {
        m.detector_id.as_ref() == "twilio-auth-token" && m.credential.as_ref() == TWILIO_AUTH_TOKEN
    });
    assert!(
        scalar_has_token,
        "CpuFallback twilio-auth-token findings must include the exact auth-token credential"
    );

    if let Some(simd) = simd {
        let simd_has_token = simd.iter().flat_map(|c| c.iter()).any(|m| {
            m.detector_id.as_ref() == "twilio-auth-token"
                && m.credential.as_ref() == TWILIO_AUTH_TOKEN
        });
        assert!(
            simd_has_token,
            "SimdCpu twilio-auth-token findings must include the exact auth-token credential"
        );
    }
}

#[test]
fn twilio_negative_twin_without_companion_suppressed_on_both_backends() {
    let sc = scanner();
    // Auth token ALONE — the required `account_sid` companion is absent, so the
    // detector must suppress the finding on either backend (negative twin).
    let chunks = vec![chunk(
        "TWILIO_AUTH_TOKEN=4c9a8f6e3b7d1a2c5e8f0b9d6a3c4e1f\n",
        "twilio_lonely.env",
    )];
    let (scalar, simd) = both_cpu_backends(&sc, &chunks);

    assert_eq!(
        count_detector(&scalar, "twilio-auth-token"),
        0,
        "CpuFallback must suppress twilio-auth-token when the required account_sid companion is absent"
    );
    if let Some(simd) = simd {
        assert_eq!(
            count_detector(&simd, "twilio-auth-token"),
            0,
            "SimdCpu must also suppress the companion-less twilio-auth-token"
        );
        assert_eq!(
            triples(&scalar),
            triples(&simd),
            "negative-twin parity: both CPU backends must agree on the (suppressed) finding set"
        );
    }
}

#[test]
fn combined_aws_github_twilio_chunk_parity_and_members() {
    let sc = scanner();
    let text = format!(
        "const AWS_KEY = \"{AWS_KEY}\";\n\
         const PAT     = \"{GHP_TOKEN}\";\n\
         {TWILIO_PAIR}"
    );
    let chunks = vec![chunk(&text, "mixed_secrets.rs")];
    let (scalar, simd) = both_cpu_backends(&sc, &chunks);

    let scalar_pairs = pairs(&scalar);
    for expected in [
        ("aws-access-key", AWS_KEY),
        ("github-classic-pat", GHP_TOKEN),
        ("twilio-auth-token", TWILIO_AUTH_TOKEN),
    ] {
        assert!(
            scalar_pairs.contains(&(expected.0.to_string(), expected.1.to_string())),
            "CpuFallback must surface {} = {}",
            expected.0,
            expected.1
        );
    }

    if let Some(simd) = simd {
        assert_eq!(
            triples(&scalar),
            triples(&simd),
            "mixed AC-literal + HS-only corpus: CpuFallback vs SimdCpu triple sets must be identical"
        );
    }
}

#[test]
fn clean_text_zero_findings_on_both_cpu_backends() {
    let sc = scanner();
    let chunks = vec![chunk(
        "// pure prose, no credentials here at all\n\
         fn hello() -> Result<(), Error> { Ok(()) }\n",
        "clean.rs",
    )];
    let (scalar, simd) = both_cpu_backends(&sc, &chunks);

    assert_eq!(
        triples(&scalar),
        BTreeSet::<(String, String, usize)>::new(),
        "CpuFallback must find nothing in credential-free text"
    );
    if let Some(simd) = simd {
        assert_eq!(
            triples(&simd),
            BTreeSet::<(String, String, usize)>::new(),
            "SimdCpu must also find nothing in credential-free text"
        );
    }
}

#[test]
fn aws_overlong_run_rejected_adversarial_on_both_backends() {
    let sc = scanner();
    // AKIA followed by 17 uppercase-alnum chars: the trailing `\b` in
    // `(AKIA|ASIA)[0-9A-Z]{16}\b` fails inside a longer word-char run, so the
    // detector must fail closed (0 findings) rather than report the 20-char
    // prefix. Adversarial twin of the valid 20-char key.
    let chunks = vec![chunk(
        "key = AKIAQYLPMN5HFIQR7XYAZ\n", // AKIA + 17 trailing = overlong
        "overlong.txt",
    )];
    let (scalar, simd) = both_cpu_backends(&sc, &chunks);

    assert_eq!(
        count_detector(&scalar, "aws-access-key"),
        0,
        "CpuFallback must reject an AKIA run longer than 20 chars"
    );
    if let Some(simd) = simd {
        assert_eq!(
            count_detector(&simd, "aws-access-key"),
            0,
            "SimdCpu must also reject the overlong AKIA run"
        );
        assert_eq!(triples(&scalar), triples(&simd));
    }
}

#[test]
fn multi_chunk_same_file_absolute_offsets_and_parity() {
    let sc = scanner();
    let chunks = vec![
        chunk_at(
            "header\nconst KEY = \"AKIAQYLPMN5HFIQR7XYA\";\n",
            "multi.txt",
            0,
        ),
        chunk_at(
            &format!("const PAT = \"{GHP_TOKEN}\";\n"),
            "multi.txt",
            4096,
        ),
    ];
    let (scalar, simd) = both_cpu_backends(&sc, &chunks);

    // aws lives in chunk 0 (base 0) -> small absolute offset; github in chunk 1
    // (base 4096) -> offset carries the base. `offset = source_offset +
    // base_offset` is the documented absolute-offset contract.
    let aws_offsets = offsets_of(&scalar, "aws-access-key");
    assert_eq!(
        aws_offsets.len(),
        1,
        "exactly one aws finding across the two chunks"
    );
    assert!(
        aws_offsets[0] < 4096,
        "chunk-0 aws finding offset {} must stay below the second chunk's base 4096",
        aws_offsets[0]
    );

    let ghp_offsets = offsets_of(&scalar, "github-classic-pat");
    assert_eq!(ghp_offsets.len(), 1, "exactly one github PAT finding");
    assert!(
        ghp_offsets[0] >= 4096,
        "chunk-1 github finding offset {} must include base_offset 4096",
        ghp_offsets[0]
    );

    if let Some(simd) = simd {
        assert_eq!(
            triples(&scalar),
            triples(&simd),
            "multi-chunk absolute offsets must be identical across CPU backends"
        );
    }
}

#[test]
fn simd_backend_determinism_run_twice_identical() {
    let sc = scanner();
    if !sc.warm_backend(ScanBackend::SimdCpu) {
        eprintln!("SKIP: SimdCpu unavailable on this build/host");
        // Fall back to a concrete CpuFallback determinism assertion so the run
        // still proves a value rather than passing vacuously.
        let chunks = vec![chunk(&format!("k=\"{AWS_KEY}\"\n"), "det.txt")];
        let a = triples(&run(&sc, &chunks, ScanBackend::CpuFallback));
        let b = triples(&run(&sc, &chunks, ScanBackend::CpuFallback));
        assert_eq!(a, b, "CpuFallback must be deterministic across two runs");
        assert!(
            a.iter()
                .any(|(id, cred, _)| id == "aws-access-key" && cred == AWS_KEY),
            "the determinism fixture must surface the AKIA key"
        );
        return;
    }
    let chunks = vec![chunk(&format!("k=\"{AWS_KEY}\"\n"), "det.txt")];
    let a = triples(&run(&sc, &chunks, ScanBackend::SimdCpu));
    let b = triples(&run(&sc, &chunks, ScanBackend::SimdCpu));
    assert_eq!(
        a, b,
        "SimdCpu must yield byte-identical findings across two runs on the same input"
    );
    assert!(
        a.iter()
            .any(|(id, cred, _)| id == "aws-access-key" && cred == AWS_KEY),
        "the determinism fixture must actually surface the AKIA key"
    );
}

#[test]
fn cpu_fallback_determinism_run_twice_identical() {
    let sc = scanner();
    let chunks = vec![chunk(TWILIO_PAIR, "det_twilio.env")];
    let a = triples(&run(&sc, &chunks, ScanBackend::CpuFallback));
    let b = triples(&run(&sc, &chunks, ScanBackend::CpuFallback));
    assert_eq!(
        a, b,
        "CpuFallback must yield byte-identical findings across two runs"
    );
    assert!(
        a.iter()
            .any(|(id, cred, _)| id == "twilio-auth-token" && cred == TWILIO_AUTH_TOKEN),
        "the twilio determinism fixture must actually surface the auth token"
    );
}

#[test]
fn unicode_surroundings_byte_offset_parity() {
    let sc = scanner();
    // Multibyte runes before/around the key exercise byte-offset accounting;
    // both CPU collectors must report the SAME absolute byte offset.
    let text = format!(
        "// 日本語 comment\n\
         const ключ = \"{AWS_KEY}\";\n\
         emoji 🦀🚀 token=\"{GHP_TOKEN}\"\n"
    );
    let chunks = vec![chunk(&text, "unicode.txt")];
    let (scalar, simd) = both_cpu_backends(&sc, &chunks);

    assert!(
        pairs(&scalar).contains(&("aws-access-key".to_string(), AWS_KEY.to_string())),
        "CpuFallback must surface the AKIA key amid multibyte surroundings"
    );
    assert!(
        pairs(&scalar).contains(&("github-classic-pat".to_string(), GHP_TOKEN.to_string())),
        "CpuFallback must surface the ghp_ token amid multibyte surroundings"
    );

    if let Some(simd) = simd {
        assert_eq!(
            triples(&scalar),
            triples(&simd),
            "byte-offset accounting must match across CPU backends with multibyte context"
        );
    }
}

#[test]
fn false_prefix_storm_single_real_key_parity() {
    let sc = scanner();
    // 200 `AKIA_...` decoys (underscore breaks the [0-9A-Z]{16} body so none
    // are valid keys) bracketing ONE real key. The literal-prefix collector
    // must confirm with the regex and surface exactly the single real key on
    // both backends.
    let mut s = String::with_capacity(8192);
    for i in 0..200 {
        s.push_str(&format!("noise AKIA_{i:08}_short\n"));
    }
    s.push_str(&format!("\nconst KEY = \"{AWS_KEY}\";\n"));
    for i in 0..200 {
        s.push_str(&format!("more  AKIA_{i:08}_short\n"));
    }
    let chunks = vec![chunk(&s, "storm.txt")];
    let (scalar, simd) = both_cpu_backends(&sc, &chunks);

    assert_eq!(
        count_detector(&scalar, "aws-access-key"),
        1,
        "CpuFallback must confirm exactly the one real AKIA key amid 400 decoys"
    );
    assert!(
        pairs(&scalar).contains(&("aws-access-key".to_string(), AWS_KEY.to_string())),
        "the surfaced aws finding must carry the real key's bytes"
    );

    if let Some(simd) = simd {
        assert_eq!(count_detector(&simd, "aws-access-key"), 1);
        assert_eq!(
            triples(&scalar),
            triples(&simd),
            "false-prefix-storm: CpuFallback vs SimdCpu triple sets must be identical"
        );
    }
}

#[test]
fn scanbackend_cpu_variant_labels_are_stable_and_distinct() {
    // Pure enum-contract assertions: no host dependence. Locks the operator-
    // visible labels the two CPU backends report and that they are distinct
    // variants (so the parity tests above compare two genuinely different paths).
    assert_eq!(ScanBackend::SimdCpu.label(), "simd-regex");
    assert_eq!(ScanBackend::CpuFallback.label(), "cpu-fallback");
    assert_ne!(ScanBackend::SimdCpu, ScanBackend::CpuFallback);
    assert_eq!(ScanBackend::CpuFallback, ScanBackend::CpuFallback);
}
