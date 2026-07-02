//! SIMD-vs-scalar single-chunk scan parity.
//!
//! The two always-comparable CPU tiers — [`ScanBackend::CpuFallback`] (pure
//! vyre Aho-Corasick + regex "scalar" path) and [`ScanBackend::SimdCpu`] (the
//! Hyperscan NFA + SIMD prefilter path) — MUST surface the byte-identical
//! finding set for the SAME single chunk. They reach the regex-confirm stage
//! through DIFFERENT candidate collectors, so a divergence is a real
//! recall/precision bug in one collector.
//!
//! This file drives the per-chunk [`CompiledScanner::scan_with_backend`] entry
//! point (one `Chunk` at a time, not the multi-chunk batch its sibling
//! `regression_backend_trigger_parity` uses) and pins:
//!   * exact credential bytes and absolute byte offset on the scalar path,
//!   * negative-twin suppression (overlong self-delimiting tokens, missing
//!     companion),
//!   * control-byte handling — whitespace controls (0x09/0x0A/0x0D) are KEPT so
//!     a tab/newline-delimited key still resolves, while non-whitespace controls
//!     (0x08/0x0C) are sanitized out yet leave the key intact,
//!   * determinism across repeated scans.
//!
//! HOST-INDEPENDENCE: the `SimdCpu` leg is gated on `warm_backend`. On a build
//! without the `simd` feature (or a host whose Hyperscan DB failed to build) a
//! forced `SimdCpu` scan hard-exits by contract, so when it is unavailable we
//! assert the concrete `CpuFallback` values alone and report the skipped SIMD
//! leg loudly (CLAUDE.md Law 10). No GPU path is ever touched.

use std::collections::BTreeSet;
use std::path::PathBuf;

use keyhog_core::{load_detectors, Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};

// ---- fixtures / shared helpers -----------------------------------------------

/// Absolute path to `crates/scanner/../../detectors` from `CARGO_MANIFEST_DIR`
/// so the load is cwd-stable under any test runner.
fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

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

/// Clear cross-chunk fragment state, then scan ONE chunk on a chosen backend.
fn run(sc: &CompiledScanner, ch: &Chunk, backend: ScanBackend) -> Vec<RawMatch> {
    sc.clear_fragment_cache();
    sc.scan_with_backend(ch, backend)
}

/// `(detector_id, credential, absolute_offset)` triples — the exact parity key.
fn triples(matches: &[RawMatch]) -> BTreeSet<(String, String, usize)> {
    matches
        .iter()
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
fn pairs(matches: &[RawMatch]) -> BTreeSet<(String, String)> {
    matches
        .iter()
        .map(|m| {
            (
                m.detector_id.as_ref().to_string(),
                m.credential.as_ref().to_string(),
            )
        })
        .collect()
}

fn count_detector(matches: &[RawMatch], id: &str) -> usize {
    matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == id)
        .count()
}

/// Scan the SAME chunk on both CPU backends. The SIMD leg is `None` only when
/// this build/host has no usable Hyperscan prefilter — forcing `SimdCpu` there
/// would hard-exit the process, so we gate on the side-effect-free
/// `warm_backend` probe (Law 10: skip is reported loudly).
fn both(sc: &CompiledScanner, ch: &Chunk) -> (Vec<RawMatch>, Option<Vec<RawMatch>>) {
    let scalar = run(sc, ch, ScanBackend::CpuFallback);
    let simd = if sc.warm_backend(ScanBackend::SimdCpu) {
        Some(run(sc, ch, ScanBackend::SimdCpu))
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
// Canonical valid-checksum classic PAT (github-classic-pat validates the token's
// trailing CRC — a fabricated random body is silently dropped). Reused across the
// scanner/cli detection suites.
const GHP_TOKEN: &str = "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";
const TWILIO_AUTH_TOKEN: &str = "4c9a8f6e3b7d1a2c5e8f0b9d6a3c4e1f";

// account_sid (`AC` + 32 hex) companion present -> `twilio-auth-token` surfaces.
const TWILIO_PAIR: &str = "TWILIO_ACCOUNT_SID=AC1b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\n\
     TWILIO_AUTH_TOKEN=4c9a8f6e3b7d1a2c5e8f0b9d6a3c4e1f\n";

// ---- tests -------------------------------------------------------------------

#[test]
fn aws_single_chunk_exact_offset_and_simd_parity() {
    let sc = scanner();
    // `AWS=` (4 bytes) then the key: the `=` is a non-word char, so the key's
    // implicit left boundary holds and the credential starts at byte 4.
    let text = format!("AWS={AWS_KEY}\n");
    let expected_offset = text.find(AWS_KEY).expect("key present in fixture");
    assert_eq!(expected_offset, 4, "fixture pins the key at byte offset 4");

    let ch = chunk(&text, "aws.env");
    let (scalar, simd) = both(&sc, &ch);

    assert_eq!(
        count_detector(&scalar, "aws-access-key"),
        1,
        "CpuFallback must surface exactly one aws-access-key finding"
    );
    let m = scalar
        .iter()
        .find(|m| m.detector_id.as_ref() == "aws-access-key")
        .expect("aws finding present on scalar path");
    assert_eq!(m.credential.as_ref(), AWS_KEY, "exact credential bytes");
    assert_eq!(
        m.location.offset, expected_offset,
        "scalar absolute offset must equal the byte index of the key"
    );

    if let Some(simd) = simd {
        assert_eq!(
            triples(&scalar),
            triples(&simd),
            "AC-literal detector: scalar vs SimdCpu triple sets must be identical"
        );
    }
}

#[test]
fn github_pat_single_chunk_exact_and_parity() {
    let sc = scanner();
    let text = format!("const PAT = \"{GHP_TOKEN}\";\n");
    let ch = chunk(&text, "gh.rs");
    let (scalar, simd) = both(&sc, &ch);

    assert_eq!(
        count_detector(&scalar, "github-classic-pat"),
        1,
        "CpuFallback must surface exactly one github-classic-pat finding"
    );
    assert!(
        pairs(&scalar).contains(&("github-classic-pat".to_string(), GHP_TOKEN.to_string())),
        "the ghp_ finding must carry the exact 40-char token bytes"
    );

    if let Some(simd) = simd {
        assert_eq!(
            triples(&scalar),
            triples(&simd),
            "ghp_ literal detector: scalar vs SimdCpu triple sets must be identical"
        );
    }
}

#[test]
fn github_pat_overlong_negative_twin_zero_both() {
    let sc = scanner();
    // ghp_ + 37 alnum chars: the trailing `\b` in `ghp_[A-Za-z0-9]{36}\b` fails
    // inside a longer word-char run, so the detector must fail closed.
    let text = format!("token={GHP_TOKEN}Z\n"); // 37th trailing char -> overlong
    let ch = chunk(&text, "overlong_gh.txt");
    let (scalar, simd) = both(&sc, &ch);

    assert_eq!(
        count_detector(&scalar, "github-classic-pat"),
        0,
        "CpuFallback must reject an overlong ghp_ run (self-delimiting token)"
    );
    if let Some(simd) = simd {
        assert_eq!(
            count_detector(&simd, "github-classic-pat"),
            0,
            "SimdCpu must also reject the overlong ghp_ run"
        );
        assert_eq!(triples(&scalar), triples(&simd));
    }
}

#[test]
fn aws_overlong_negative_twin_zero_both() {
    let sc = scanner();
    // AKIA + 17 trailing uppercase-alnum: 21-char run, trailing `\b` fails.
    let text = format!("key = {AWS_KEY}Z\n");
    let ch = chunk(&text, "overlong_aws.txt");
    let (scalar, simd) = both(&sc, &ch);

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
fn clean_chunk_zero_findings_both() {
    let sc = scanner();
    let text = "// pure prose, no credentials here at all\n\
                fn hello() -> Result<(), Error> { Ok(()) }\n";
    let ch = chunk(text, "clean.rs");
    let (scalar, simd) = both(&sc, &ch);

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
fn empty_chunk_zero_findings_both() {
    let sc = scanner();
    let ch = chunk("", "empty.txt");
    let (scalar, simd) = both(&sc, &ch);

    assert_eq!(
        scalar.len(),
        0,
        "CpuFallback on an empty chunk must yield zero matches (no panic, no spurious finding)"
    );
    assert_eq!(
        triples(&scalar),
        BTreeSet::<(String, String, usize)>::new(),
        "empty chunk scalar triple set must be exactly empty"
    );
    if let Some(simd) = simd {
        assert_eq!(
            triples(&simd),
            BTreeSet::<(String, String, usize)>::new(),
            "SimdCpu on an empty chunk must also yield the empty triple set"
        );
    }
}

#[test]
fn whitespace_control_bytes_preserved_key_found_both() {
    let sc = scanner();
    // The scan path KEEPS whitespace controls 0x09 (tab) / 0x0A (LF) / 0x0D
    // (CR). A tab-delimited key stays delimited, so it must still surface with
    // its exact bytes on both CPU backends.
    let text = format!("TOKEN\t{AWS_KEY}\r\n");
    assert!(text.contains('\t') && text.contains('\r'));
    let ch = chunk(&text, "ws_controls.txt");
    let (scalar, simd) = both(&sc, &ch);

    assert_eq!(
        count_detector(&scalar, "aws-access-key"),
        1,
        "a tab/CR-delimited AWS key must still be found (whitespace controls are kept)"
    );
    assert!(
        pairs(&scalar).contains(&("aws-access-key".to_string(), AWS_KEY.to_string())),
        "credential bytes must be exactly the AKIA key with no stray control bytes"
    );
    if let Some(simd) = simd {
        assert_eq!(
            triples(&scalar),
            triples(&simd),
            "whitespace-control context: scalar vs SimdCpu triples must be identical"
        );
    }
}

#[test]
fn nonws_control_bytes_sanitized_key_found_both() {
    let sc = scanner();
    // The scan path SANITIZES non-whitespace controls 0x08 (BS) / 0x0C (FF).
    // Placed adjacent to the key they are stripped, leaving the credential
    // intact, so the AWS key still resolves with its exact bytes on both CPU
    // backends. (If the byte were kept, it would fuse into the run and could
    // perturb the finding — the parity + exact-bytes assertion pins it does not.)
    let text = format!("AWS=\x0c{AWS_KEY}\x08\n");
    assert!(text.contains('\u{0008}') && text.contains('\u{000c}'));
    let ch = chunk(&text, "nonws_controls.txt");
    let (scalar, simd) = both(&sc, &ch);

    assert_eq!(
        count_detector(&scalar, "aws-access-key"),
        1,
        "AWS key must survive stripping of adjacent 0x08/0x0C control bytes"
    );
    let creds: BTreeSet<String> = scalar
        .iter()
        .filter(|m| m.detector_id.as_ref() == "aws-access-key")
        .map(|m| m.credential.as_ref().to_string())
        .collect();
    assert_eq!(
        creds,
        BTreeSet::from([AWS_KEY.to_string()]),
        "credential must be exactly the AKIA key, with no residual control bytes fused in"
    );
    if let Some(simd) = simd {
        assert_eq!(
            triples(&scalar),
            triples(&simd),
            "non-whitespace-control sanitization: scalar vs SimdCpu triples must be identical"
        );
    }
}

#[test]
fn two_secrets_one_chunk_members_and_parity() {
    let sc = scanner();
    let text = format!(
        "const AWS_KEY = \"{AWS_KEY}\";\n\
         const PAT     = \"{GHP_TOKEN}\";\n"
    );
    let ch = chunk(&text, "mixed.rs");
    let (scalar, simd) = both(&sc, &ch);

    let sp = pairs(&scalar);
    assert!(
        sp.contains(&("aws-access-key".to_string(), AWS_KEY.to_string())),
        "scalar must surface the AWS key"
    );
    assert!(
        sp.contains(&("github-classic-pat".to_string(), GHP_TOKEN.to_string())),
        "scalar must surface the ghp_ token"
    );
    assert_eq!(count_detector(&scalar, "aws-access-key"), 1);
    assert_eq!(count_detector(&scalar, "github-classic-pat"), 1);

    if let Some(simd) = simd {
        assert_eq!(
            triples(&scalar),
            triples(&simd),
            "mixed AC-literal + ghp_ chunk: scalar vs SimdCpu triples must be identical"
        );
    }
}

#[test]
fn twilio_companion_pair_surfaces_both() {
    let sc = scanner();
    let ch = chunk(TWILIO_PAIR, "twilio.env");
    let (scalar, simd) = both(&sc, &ch);

    assert!(
        count_detector(&scalar, "twilio-auth-token") >= 1,
        "CpuFallback must fire twilio-auth-token when the account_sid companion is present"
    );
    assert!(
        pairs(&scalar).contains(&(
            "twilio-auth-token".to_string(),
            TWILIO_AUTH_TOKEN.to_string()
        )),
        "the twilio finding must carry the exact 32-hex auth-token bytes"
    );

    if let Some(simd) = simd {
        assert_eq!(
            triples(&scalar),
            triples(&simd),
            "companion-satisfied twilio pair: scalar vs SimdCpu triples must be identical"
        );
        assert!(pairs(&simd).contains(&(
            "twilio-auth-token".to_string(),
            TWILIO_AUTH_TOKEN.to_string()
        )));
    }
}

#[test]
fn twilio_without_companion_suppressed_both() {
    let sc = scanner();
    // Auth token ALONE — the required account_sid companion is absent, so the
    // finding must be suppressed on either backend (negative twin).
    let text = format!("TWILIO_AUTH_TOKEN={TWILIO_AUTH_TOKEN}\n");
    let ch = chunk(&text, "twilio_lonely.env");
    let (scalar, simd) = both(&sc, &ch);

    assert_eq!(
        count_detector(&scalar, "twilio-auth-token"),
        0,
        "CpuFallback must suppress twilio-auth-token with no account_sid companion"
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
            "negative-twin parity: both CPU backends must agree on the suppressed set"
        );
    }
}

#[test]
fn cpu_fallback_determinism_twice() {
    let sc = scanner();
    let text = format!("k=\"{AWS_KEY}\"\n");
    let ch = chunk(&text, "det.txt");
    let a = triples(&run(&sc, &ch, ScanBackend::CpuFallback));
    let b = triples(&run(&sc, &ch, ScanBackend::CpuFallback));
    assert_eq!(
        a, b,
        "CpuFallback must yield byte-identical findings across two scans of the same chunk"
    );
    assert!(
        a.iter()
            .any(|(id, cred, _)| id == "aws-access-key" && cred == AWS_KEY),
        "the determinism fixture must actually surface the AKIA key"
    );
}

#[test]
fn simd_or_cpu_determinism_twice() {
    let sc = scanner();
    let ch = chunk(TWILIO_PAIR, "det_twilio.env");
    let backend = if sc.warm_backend(ScanBackend::SimdCpu) {
        ScanBackend::SimdCpu
    } else {
        eprintln!("SKIP: SimdCpu unavailable; running CpuFallback determinism instead");
        ScanBackend::CpuFallback
    };
    let a = triples(&run(&sc, &ch, backend));
    let b = triples(&run(&sc, &ch, backend));
    assert_eq!(
        a, b,
        "the chosen CPU backend must be deterministic across two scans"
    );
    assert!(
        a.iter()
            .any(|(id, cred, _)| id == "twilio-auth-token" && cred == TWILIO_AUTH_TOKEN),
        "the twilio determinism fixture must actually surface the auth token"
    );
}

#[test]
fn scanbackend_labels_and_variants_contract() {
    // Pure enum-contract assertions: no host dependence. Locks the operator-
    // visible labels the two compared CPU backends report and that they are
    // distinct variants (so every parity leg above compares two real paths).
    assert_eq!(ScanBackend::CpuFallback.label(), "cpu-fallback");
    assert_eq!(ScanBackend::SimdCpu.label(), "simd-regex");
    assert_ne!(ScanBackend::SimdCpu, ScanBackend::CpuFallback);
    assert_eq!(ScanBackend::CpuFallback, ScanBackend::CpuFallback);
}
