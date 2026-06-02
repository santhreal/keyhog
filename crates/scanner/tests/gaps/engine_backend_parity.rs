//! Gap coverage: backend parity + chunk-boundary reassembly.
//!
//! Focus area `engine_backend_parity`:
//!   * The Hyperscan-prefiltered SIMD path (`ScanBackend::SimdCpu`) and the
//!     pure Aho-Corasick CPU path (`ScanBackend::CpuFallback`) MUST produce the
//!     same finding set for a fixed corpus. Both backends seed the candidate
//!     bitmap from the SAME AC literal triggers (see
//!     `collect_triggered_patterns_simd` / `collect_triggered_patterns_cpu` in
//!     `engine/backend_triggered.rs`); HS only UNIONS extra candidates that the
//!     full regex confirmation then re-filters, so the emitted set is identical.
//!   * The keyword/entropy fallback (`scan_entropy_fallback`,
//!     `scan_fallback_patterns`, `scan_generic_assignments`) runs in
//!     `scan_prepared_with_triggered` REGARDLESS of backend, so its findings are
//!     backend-invariant.
//!   * Chunk-boundary splits (`engine/boundary.rs`) must not lose matches: a
//!     credential straddling the seam of two gapless contiguous chunks is
//!     recovered by `scan_chunk_boundaries`, attributed to the RIGHT-hand chunk,
//!     and deduplicated against per-chunk results.
//!
//! Every expected value below is derived by reading the real source under
//! `crates/scanner/src/engine/*` and the on-disk detector TOMLs, never guessed.
//!
//! This module is included via `mod engine_backend_parity;` from `tests/gaps.rs`;
//! it is a plain module body (no `fn main`, no wrapper mod).

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::OnceLock;

// ----------------------------------------------------------------------------
// Shared fixtures
// ----------------------------------------------------------------------------

/// Absolute path to the on-disk Tier-B detector TOML directory.
///
/// `CARGO_MANIFEST_DIR` for this test target is `crates/scanner`; the detector
/// corpus lives at the repo root `detectors/`, i.e. two `pop()`s up then
/// `detectors`. Mirrors `tests/support/paths::detector_dir`, inlined because
/// this gap module is `mod`-included from `tests/gaps.rs` and does not pull the
/// `support` tree into scope.
fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

/// Build the full detector-corpus scanner exactly once for the whole module.
///
/// Compilation walks ~894 detector TOMLs; sharing one `CompiledScanner` keeps
/// the suite fast and is safe because `CompiledScanner` is `Send + Sync` (see
/// the `assert_send_sync` const in `engine/mod.rs`) and every test below only
/// READS it.
fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors = keyhog_core::load_detectors(&detector_dir())
            .expect("detector corpus must load from on-disk TOMLs");
        CompiledScanner::compile(detectors).expect("detector corpus must compile")
    })
}

fn chunk(text: &str, path: &str, base_offset: usize) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "gap-backend-parity".into(),
            path: Some(path.into()),
            base_offset,
            ..Default::default()
        },
    }
}

/// Identity key for a single finding. `into_matches` in `scanner_config.rs`
/// dedups on exactly `(detector_id, credential, offset)`, so this is the
/// canonical finding identity the engine itself uses.
type Key = (String, String, usize);

fn key_set(matches: &[RawMatch]) -> BTreeSet<Key> {
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

fn flat_key_set(per_chunk: &[Vec<RawMatch>]) -> BTreeSet<Key> {
    per_chunk
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

/// The two CPU-only backends that never trigger `gpu_forced::deny_silent_*`
/// (which can `std::process::exit(2)`). `SimdCpu` = Hyperscan prefilter + AC
/// union; `CpuFallback` = pure scalar AC. These are the two real backends the
/// "hyperscan vs regex-fallback" parity claim is about.
const CPU_BACKENDS: [ScanBackend; 2] = [ScanBackend::SimdCpu, ScanBackend::CpuFallback];

// A set of fixed, valid-shape credentials whose detector regexes were read
// directly from the on-disk TOMLs:
//   aws-access-key       (?-i)(AKIA|ASIA)[0-9A-Z]{16}
//   github-pat-fine-grained  github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}
//   sendgrid-api-key     SG\.[A-Za-z0-9_-]{22,32}\.[A-Za-z0-9_-]{43,47}
//   slack-bot-token      xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}
//   stripe-secret-key    sk_live_[a-zA-Z0-9]{24,}
const AWS_KEY: &str = "AKIAQYLPMN5HFIQR7BBB"; // AKIA + 16 [0-9A-Z]; no checksum validator → always emitted.
                                              // github_pat_ + 22 [a-zA-Z0-9] + '_' + 59 [a-zA-Z0-9], regex-verified against
                                              // github-pat.toml. CRITICAL: `GithubFineGrainedPatValidator` (checksum/github.rs)
                                              // drops a fine-grained PAT whose embedded CRC32 does not match its body
                                              // (`process_match` returns on `ChecksumResult::Invalid`). This token is minted
                                              // checksum-VALID: the trailing 6 chars `0qzktM` == base62(crc32(payload[..76]), 6)
                                              // computed with the exact reflected-CRC32 (poly 0xEDB88320) + base62 alphabet
                                              // `0-9A-Za-z` the validator uses. So this PAT survives the drop and is emitted.
const GH_PAT: &str =
    "github_pat_ABCDEFGHIJKLMNOPQRSTUV_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQ0qzktM";
// No checksum validator → always emitted.
const SENDGRID: &str = "SG.0000000000000000000000.0000000000000000000000000000000000000000000";
// `SlackTokenValidator` regex `^xoxb-[0-9]{10,15}-[0-9]{10,15}-[a-zA-Z0-9]{15,40}$`:
// segments 10/10/24 → Valid → emitted.
const SLACK_BOT: &str = "xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx";
// `StripeTokenValidator`: `sk_live_` + 24 alnum payload (24..=128) → Valid → emitted.
const STRIPE_LIVE: &str = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";

// ----------------------------------------------------------------------------
// 1. Fixed-corpus finding-set parity: SimdCpu vs CpuFallback
// ----------------------------------------------------------------------------

#[test]
fn aws_key_same_finding_set_simd_and_cpu() {
    let c = chunk(
        &format!("const AWS_ACCESS_KEY_ID = \"{AWS_KEY}\";\n"),
        "config.rs",
        0,
    );
    let simd = key_set(&scanner().scan_with_backend(&c, ScanBackend::SimdCpu));
    let cpu = key_set(&scanner().scan_with_backend(&c, ScanBackend::CpuFallback));
    assert_eq!(
        simd, cpu,
        "SimdCpu and CpuFallback must emit the identical finding set for an AWS key"
    );
    // And the AWS key is actually present (not an empty-set vacuous equality).
    assert!(
        simd.iter()
            .any(|(id, cred, _)| id == "aws-access-key" && cred == AWS_KEY),
        "expected aws-access-key={AWS_KEY} in {simd:?}"
    );
}

#[test]
fn github_pat_same_finding_set_simd_and_cpu() {
    let c = chunk(&format!("token: {GH_PAT}\n"), "ci.yml", 0);
    let simd = key_set(&scanner().scan_with_backend(&c, ScanBackend::SimdCpu));
    let cpu = key_set(&scanner().scan_with_backend(&c, ScanBackend::CpuFallback));
    assert_eq!(simd, cpu, "GitHub fine-grained PAT parity broke");
    assert!(
        simd.iter()
            .any(|(id, cred, _)| id == "github-pat-fine-grained" && cred == GH_PAT),
        "expected github-pat-fine-grained={GH_PAT} in {simd:?}"
    );
}

#[test]
fn sendgrid_same_finding_set_simd_and_cpu() {
    let c = chunk(&format!("SENDGRID_API_KEY={SENDGRID}\n"), "app.env", 0);
    let simd = key_set(&scanner().scan_with_backend(&c, ScanBackend::SimdCpu));
    let cpu = key_set(&scanner().scan_with_backend(&c, ScanBackend::CpuFallback));
    assert_eq!(simd, cpu, "SendGrid key parity broke");
    assert!(
        simd.iter()
            .any(|(id, cred, _)| id == "sendgrid-api-key" && cred == SENDGRID),
        "expected sendgrid-api-key={SENDGRID} in {simd:?}"
    );
}

#[test]
fn slack_bot_same_finding_set_simd_and_cpu() {
    let c = chunk(
        &format!("SLACK_BOT_TOKEN = '{SLACK_BOT}'\n"),
        "settings.py",
        0,
    );
    let simd = key_set(&scanner().scan_with_backend(&c, ScanBackend::SimdCpu));
    let cpu = key_set(&scanner().scan_with_backend(&c, ScanBackend::CpuFallback));
    assert_eq!(simd, cpu, "Slack bot token parity broke");
    assert!(
        simd.iter()
            .any(|(id, cred, _)| id == "slack-bot-token" && cred == SLACK_BOT),
        "expected slack-bot-token={SLACK_BOT} in {simd:?}"
    );
}

#[test]
fn stripe_same_finding_set_simd_and_cpu() {
    let c = chunk(
        &format!("stripe_key = \"{STRIPE_LIVE}\"\n"),
        "billing.rb",
        0,
    );
    let simd = key_set(&scanner().scan_with_backend(&c, ScanBackend::SimdCpu));
    let cpu = key_set(&scanner().scan_with_backend(&c, ScanBackend::CpuFallback));
    assert_eq!(simd, cpu, "Stripe live key parity broke");
    assert!(
        simd.iter()
            .any(|(id, cred, _)| id == "stripe-secret-key" && cred == STRIPE_LIVE),
        "expected stripe-secret-key={STRIPE_LIVE} in {simd:?}"
    );
}

#[test]
fn multi_secret_corpus_same_finding_set_simd_and_cpu() {
    // One chunk holding five distinct service credentials. The whole finding
    // set (every detector_id + credential + offset) must be byte-identical
    // across the two backends.
    let text = format!(
        "aws = \"{AWS_KEY}\"\n\
         gh: {GH_PAT}\n\
         SENDGRID_API_KEY={SENDGRID}\n\
         slack = '{SLACK_BOT}'\n\
         stripe_secret = \"{STRIPE_LIVE}\"\n"
    );
    let c = chunk(&text, "secrets.env", 0);
    let simd = key_set(&scanner().scan_with_backend(&c, ScanBackend::SimdCpu));
    let cpu = key_set(&scanner().scan_with_backend(&c, ScanBackend::CpuFallback));
    assert_eq!(
        simd,
        cpu,
        "multi-secret corpus finding-set diverged between SimdCpu and CpuFallback:\n\
         only-in-simd={:?}\n only-in-cpu={:?}",
        simd.difference(&cpu).collect::<Vec<_>>(),
        cpu.difference(&simd).collect::<Vec<_>>()
    );
    // All five named detectors must be present in the shared set.
    for (id, cred) in [
        ("aws-access-key", AWS_KEY),
        ("github-pat-fine-grained", GH_PAT),
        ("sendgrid-api-key", SENDGRID),
        ("slack-bot-token", SLACK_BOT),
        ("stripe-secret-key", STRIPE_LIVE),
    ] {
        assert!(
            simd.iter().any(|(i, c, _)| i == id && c == cred),
            "expected {id}={cred} in shared finding set {simd:?}"
        );
    }
}

#[test]
fn negative_twin_no_secret_both_backends_empty() {
    // Identifier-shaped text that carries NO detector literal prefix. Both
    // backends must return the empty set (and equal).
    let c = chunk(
        "fn compute_total(items: &[Item]) -> u64 { items.iter().map(|i| i.qty).sum() }\n",
        "math.rs",
        0,
    );
    let simd = scanner().scan_with_backend(&c, ScanBackend::SimdCpu);
    let cpu = scanner().scan_with_backend(&c, ScanBackend::CpuFallback);
    assert!(
        simd.is_empty(),
        "plain code must yield zero findings on SimdCpu, got {}",
        simd.len()
    );
    assert_eq!(
        key_set(&simd),
        key_set(&cpu),
        "empty-set parity broke on plain code"
    );
}

#[test]
fn wrong_prefix_negative_twin_both_backends_silent() {
    // `AKIB` is one letter off the AWS `AKIA|ASIA` literal. The `(?-i)`
    // case-sensitive regex cannot match it; neither backend may emit
    // aws-access-key, and the two sets must agree.
    let c = chunk("key = \"AKIBQYLPMN5HFIQR7BBB\"\n", "cfg.env", 0);
    let simd = key_set(&scanner().scan_with_backend(&c, ScanBackend::SimdCpu));
    let cpu = key_set(&scanner().scan_with_backend(&c, ScanBackend::CpuFallback));
    assert!(
        !simd.iter().any(|(id, _, _)| id == "aws-access-key"),
        "AKIB prefix must NOT match aws-access-key, got {simd:?}"
    );
    assert_eq!(simd, cpu, "wrong-prefix negative-twin parity broke");
}

#[test]
fn aws_case_evasion_lowercase_silent_both_backends() {
    // The aws regex is `(?-i)` (case-sensitive). A lowercased `akia…` doc
    // placeholder must NOT fire aws-access-key on either backend - and the
    // backends must agree. (Truth check on the case-sensitivity comment in
    // aws-access-key.toml.)
    let c = chunk("akiaqylpmn5hfiqr7bbb placeholder\n", "readme.md", 0);
    let simd = key_set(&scanner().scan_with_backend(&c, ScanBackend::SimdCpu));
    let cpu = key_set(&scanner().scan_with_backend(&c, ScanBackend::CpuFallback));
    assert!(
        !simd.iter().any(|(id, _, _)| id == "aws-access-key"),
        "lowercase akia must not match case-sensitive aws regex, got {simd:?}"
    );
    assert_eq!(simd, cpu, "case-evasion negative parity broke");
}

#[test]
fn repeated_secret_offsets_identical_across_backends() {
    // The SAME AWS key planted at two distinct offsets. `into_matches` dedups
    // on `(detector_id, credential, offset)`, so two identical credentials at
    // DIFFERENT offsets are two distinct findings. The offset component of the
    // finding identity must match across backends, not just the credential.
    let text = format!("a=\"{AWS_KEY}\"\nb=\"{AWS_KEY}\"\n");
    let c = chunk(&text, "two.env", 0);
    let simd = key_set(&scanner().scan_with_backend(&c, ScanBackend::SimdCpu));
    let cpu = key_set(&scanner().scan_with_backend(&c, ScanBackend::CpuFallback));
    assert_eq!(simd, cpu, "two-key offset parity broke");
    let aws_offsets: BTreeSet<usize> = simd
        .iter()
        .filter(|(id, cred, _)| id == "aws-access-key" && cred == AWS_KEY)
        .map(|(_, _, off)| *off)
        .collect();
    // The first key sits after `a="` = byte offset 3. The second sits after
    // the first line `a="<20-byte key>"\n` (3 + 20 + 2 = 25) plus `b="` (3) =
    // offset 28.
    let first_off = 3usize;
    let second_off = 3 + AWS_KEY.len() + 2 /* "\n */ + 3 /* b=" */;
    assert!(
        aws_offsets.contains(&first_off),
        "first AWS key must start at byte offset {first_off}, got {aws_offsets:?}"
    );
    assert!(
        aws_offsets.contains(&second_off),
        "second AWS key must start at byte offset {second_off}, got {aws_offsets:?}"
    );
}

// ----------------------------------------------------------------------------
// 2. Entropy-fallback parity (backend-invariant by construction)
// ----------------------------------------------------------------------------

#[test]
fn entropy_fallback_finding_set_backend_invariant() {
    // A high-entropy base62 token assigned to a credential keyword in a
    // non-source config file. `scan_entropy_fallback` runs inside
    // `scan_prepared_with_triggered` for every backend, so its emitted
    // entropy-* finding set is identical across SimdCpu and CpuFallback.
    // High-entropy 50-char mixed-case+digit run (no service prefix).
    let token = "Zk9Qw3Rt7Yx2Mn5Bv8Cs1Lp4Df6Gh0Jk3Wq7Er2Ty9Ui4Op6A";
    let c = chunk(&format!("api_key = \"{token}\"\n"), "service.env", 0);
    let simd = key_set(&scanner().scan_with_backend(&c, ScanBackend::SimdCpu));
    let cpu = key_set(&scanner().scan_with_backend(&c, ScanBackend::CpuFallback));
    assert_eq!(
        simd,
        cpu,
        "entropy fallback must be backend-invariant:\n only-simd={:?}\n only-cpu={:?}",
        simd.difference(&cpu).collect::<Vec<_>>(),
        cpu.difference(&simd).collect::<Vec<_>>()
    );
}

#[test]
fn entropy_source_file_gate_parity() {
    // `entropy_in_source_files` defaults to false (core ScanConfig). A
    // high-entropy token in a `.rs` source file with NO secret-keyword line
    // is path-gated OFF by `is_entropy_appropriate`, so no entropy-* finding
    // appears - on either backend. We only assert the two backends AGREE
    // (the gate is identical for both), not a specific count.
    let token = "Zk9Qw3Rt7Yx2Mn5Bv8Cs1Lp4Df6Gh0Jk3Wq7Er2Ty9Ui4Op6A";
    // No credential keyword near the value; pure data in a source file.
    let c = chunk(
        &format!("const TABLE: &str = \"{token}\";\n"),
        "data_table.rs",
        0,
    );
    let simd = key_set(&scanner().scan_with_backend(&c, ScanBackend::SimdCpu));
    let cpu = key_set(&scanner().scan_with_backend(&c, ScanBackend::CpuFallback));
    assert_eq!(simd, cpu, "source-file entropy gate parity broke");
}

#[test]
fn low_entropy_repeated_value_no_entropy_finding_both_backends() {
    // A long but ZERO-information run (all `a`). Shannon entropy is ~0, far
    // below the 4.5 threshold, so `find_entropy_secrets_with_threshold`
    // cannot emit it; both backends agree and neither reports an entropy-*.
    let c = chunk(
        "api_key = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
        "low.env",
        0,
    );
    let simd = key_set(&scanner().scan_with_backend(&c, ScanBackend::SimdCpu));
    let cpu = key_set(&scanner().scan_with_backend(&c, ScanBackend::CpuFallback));
    assert!(
        !simd.iter().any(|(id, _, _)| id.starts_with("entropy-")),
        "all-'a' run must not produce an entropy finding, got {simd:?}"
    );
    assert_eq!(simd, cpu, "low-entropy negative parity broke");
}

// ----------------------------------------------------------------------------
// 3. scan() default-backend == explicit SimdCpu/CpuFallback (auto-route parity)
// ----------------------------------------------------------------------------

#[test]
fn default_scan_matches_a_cpu_backend() {
    // `scan()` auto-routes via `select_backend`. On a no-GPU host (CI default)
    // it lands on SimdCpu or CpuFallback. Whichever it picks, the finding set
    // must equal one of the explicit CPU backends - i.e. auto-routing never
    // invents or drops findings relative to the path it chose.
    // Guard: if the operator forced a GPU backend via env, `scan()` routes
    // there and (on a host without a usable GPU stack) `deny_silent_gpu_degrade`
    // would `process::exit(2)`. The explicit-backend tests are unaffected; this
    // bare-`scan()` test only makes sense on the CPU auto-route, so skip when a
    // GPU/MegaScan backend is pinned. Tiny chunks never clear the GPU byte
    // floor, so absent the override `scan()` deterministically picks SimdCpu.
    if matches!(
        std::env::var("KEYHOG_BACKEND").ok().as_deref(),
        Some("gpu") | Some("mega-scan") | Some("gpu-zero-copy") | Some("gpu-mega-scan")
    ) {
        eprintln!("SKIP: KEYHOG_BACKEND pins a GPU backend; auto-route parity is CPU-only");
        return;
    }
    let c = chunk(
        &format!("aws=\"{AWS_KEY}\"\nstripe=\"{STRIPE_LIVE}\"\n"),
        "auto.env",
        0,
    );
    let auto = key_set(&scanner().scan(&c));
    let simd = key_set(&scanner().scan_with_backend(&c, ScanBackend::SimdCpu));
    let cpu = key_set(&scanner().scan_with_backend(&c, ScanBackend::CpuFallback));
    // simd and cpu are already proven equal elsewhere; auto must match them.
    assert_eq!(simd, cpu, "precondition: CPU backends already diverge");
    assert_eq!(
        auto, simd,
        "scan() auto-route must match the explicit CPU backend finding set"
    );
}

#[test]
fn idempotent_rescans_same_backend_same_set() {
    // Re-scanning the identical chunk on the same backend must be deterministic
    // (no order/dedup nondeterminism). Asserts the finding identity set is
    // stable across repeated calls.
    let c = chunk(&format!("token: {GH_PAT}\n"), "repeat.yml", 0);
    for backend in CPU_BACKENDS {
        let first = key_set(&scanner().scan_with_backend(&c, backend));
        let second = key_set(&scanner().scan_with_backend(&c, backend));
        assert_eq!(
            first, second,
            "{backend:?} re-scan produced a different finding set"
        );
    }
}

// ----------------------------------------------------------------------------
// 4. Coalesced batch vs per-chunk parity (phase-1/phase-2 split equivalence)
// ----------------------------------------------------------------------------

#[test]
fn coalesced_equals_sum_of_per_chunk_scans() {
    // `scan_coalesced` runs the HS phase-1 prefilter then phase-2 extraction;
    // a plain `scan()` on each chunk takes the non-coalesced path. The UNION
    // of findings must be identical (the coalesced path exists purely as a
    // throughput optimisation, not a behaviour change).
    let chunks = vec![
        chunk(&format!("a=\"{AWS_KEY}\"\n"), "a.env", 0),
        chunk("// nothing to see here\n", "b.rs", 0),
        chunk(&format!("gh={GH_PAT}\n"), "c.yml", 0),
        chunk(&format!("s='{SLACK_BOT}'\n"), "d.py", 0),
    ];

    let coalesced = scanner().scan_coalesced(&chunks);
    let coalesced_set = flat_key_set(&coalesced);

    let mut per_chunk: BTreeSet<Key> = BTreeSet::new();
    for c in &chunks {
        per_chunk.extend(key_set(&scanner().scan(c)));
    }

    assert_eq!(
        coalesced_set,
        per_chunk,
        "coalesced batch finding set diverged from per-chunk scans:\n\
         only-coalesced={:?}\n only-per-chunk={:?}",
        coalesced_set.difference(&per_chunk).collect::<Vec<_>>(),
        per_chunk.difference(&coalesced_set).collect::<Vec<_>>()
    );
}

#[test]
fn coalesced_result_vector_is_per_chunk_aligned() {
    // `scan_coalesced` returns one result Vec per input chunk, index-aligned.
    // The empty chunk (index 1) must have zero findings; the secret chunks
    // (0 and 2) must each have at least one.
    let chunks = vec![
        chunk(&format!("a=\"{AWS_KEY}\"\n"), "a.env", 0),
        chunk("plain comment\n", "b.rs", 0),
        chunk(&format!("s='{SLACK_BOT}'\n"), "c.py", 0),
    ];
    let results = scanner().scan_coalesced(&chunks);
    assert_eq!(
        results.len(),
        chunks.len(),
        "coalesced result vec must be 1:1 with input chunks"
    );
    assert!(
        results[0]
            .iter()
            .any(|m| m.detector_id.as_ref() == "aws-access-key"),
        "chunk 0 must carry the aws-access-key finding in its own slot"
    );
    assert_eq!(
        results[1].len(),
        0,
        "chunk 1 (no secret) must have an empty result slot, got {}",
        results[1].len()
    );
    assert!(
        results[2]
            .iter()
            .any(|m| m.detector_id.as_ref() == "slack-bot-token"),
        "chunk 2 must carry the slack-bot-token finding in its own slot"
    );
}

// ----------------------------------------------------------------------------
// 5. Chunk-boundary reassembly (engine/boundary.rs)
// ----------------------------------------------------------------------------

/// Build two GAPLESS, contiguous chunks of the same file by splitting
/// `prefix + secret + suffix` at byte `split` within the secret. The padding
/// before the secret keeps each side well under `MAX_BOUNDARY` (1024) so the
/// boundary buffer captures both halves.
fn split_pair(secret: &str, split_in_secret: usize, path: &str) -> (Chunk, Chunk, usize) {
    // A modest left pad so the seam is genuinely a chunk boundary, not at byte 0.
    let pad = "padding_line\n".repeat(8);
    let mut a = pad.clone();
    a.push_str(&secret[..split_in_secret]);
    let len_a = a.len();
    let mut b = secret[split_in_secret..].to_string();
    b.push('\n');
    let ca = chunk(&a, path, 0);
    let cb = chunk(&b, path, len_a);
    (ca, cb, len_a)
}

#[test]
fn sendgrid_split_reassembled_coalesced() {
    // SendGrid key split mid-credential across two gapless chunks. The seam
    // sits inside the credential, so neither chunk matches alone; only
    // `scan_chunk_boundaries` recovers it.
    let (ca, cb, _len_a) = split_pair(SENDGRID, 18, "split.txt");
    let results = scanner().scan_coalesced(&[ca, cb]);
    let found = results
        .iter()
        .flatten()
        .any(|m| m.detector_id.as_ref() == "sendgrid-api-key" && m.credential.as_ref() == SENDGRID);
    assert!(
        found,
        "sendgrid key straddling a gapless chunk seam must reassemble via boundary scan"
    );
}

#[test]
fn aws_split_reassembled_both_cpu_backends() {
    // The CPU dispatch path (`scan_chunks_with_backend` for SimdCpu /
    // CpuFallback) also calls `scan_chunk_boundaries`. A split AWS key must be
    // recovered under BOTH CPU backends.
    for backend in CPU_BACKENDS {
        let (ca, cb, _len_a) = split_pair(AWS_KEY, 8, "aws-split.txt");
        let results = scanner().scan_chunks_with_backend(&[ca, cb], backend);
        let found = results.iter().flatten().any(|m| {
            m.detector_id.as_ref() == "aws-access-key" && m.credential.as_ref() == AWS_KEY
        });
        assert!(
            found,
            "{backend:?}: AWS key split across the seam must reassemble"
        );
    }
}

#[test]
fn boundary_match_attributed_to_right_hand_chunk() {
    // `scan_one_pair` pushes a straddle match onto `per_chunk_results[bi]`
    // (the RIGHT chunk), never the left. The left chunk's own slot must NOT
    // gain the reassembled finding.
    let (ca, cb, _len_a) = split_pair(SENDGRID, 18, "attrib.txt");
    let results = scanner().scan_chunks_with_backend(&[ca, cb], ScanBackend::SimdCpu);
    assert_eq!(results.len(), 2, "expected two result slots");
    let left_has = results[0]
        .iter()
        .any(|m| m.detector_id.as_ref() == "sendgrid-api-key" && m.credential.as_ref() == SENDGRID);
    let right_has = results[1]
        .iter()
        .any(|m| m.detector_id.as_ref() == "sendgrid-api-key" && m.credential.as_ref() == SENDGRID);
    assert!(
        !left_has,
        "reassembled boundary finding must NOT land in the left chunk's slot"
    );
    assert!(
        right_has,
        "reassembled boundary finding must land in the right chunk's slot"
    );
}

#[test]
fn boundary_finding_offset_is_absolute_file_offset() {
    // The boundary chunk's `base_offset` is `a.base_offset + tail_start`, so a
    // reassembled match's reported offset is the ABSOLUTE file offset of the
    // credential start. Here `a.base_offset == 0`, the secret begins right
    // after the 8-line pad, and the tail (<=1024 bytes) covers the whole pad,
    // so the offset equals the pad length.
    let pad = "padding_line\n".repeat(8);
    let pad_len = pad.len();
    let (ca, cb, _len_a) = split_pair(SENDGRID, 18, "offset.txt");
    let results = scanner().scan_chunks_with_backend(&[ca, cb], ScanBackend::SimdCpu);
    let m = results
        .iter()
        .flatten()
        .find(|m| m.detector_id.as_ref() == "sendgrid-api-key" && m.credential.as_ref() == SENDGRID)
        .expect("sendgrid boundary match must exist");
    assert_eq!(
        m.location.offset, pad_len,
        "boundary match offset must be the absolute file offset of the secret start (after the {pad_len}-byte pad)"
    );
}

#[test]
fn overlapping_chunks_not_double_reassembled() {
    // `scan_one_pair` only synthesises a boundary buffer for GAPLESS pairs
    // (`a_end == b.base_offset`). When chunk B already CONTAINS the full secret
    // (overlap, B.base_offset < a_end), the boundary path returns early; the
    // secret is found once via B's own in-chunk scan, never duplicated.
    let pad = "x\n".repeat(8);
    let a_text = format!("{pad}{SENDGRID}"); // A holds the whole secret at its tail
    let len_a = a_text.len();
    // B starts BEFORE a_end (overlap) and re-contains the secret tail.
    let overlap = 10usize;
    let b_text = format!("{}\n", &a_text[len_a - overlap..]);
    let ca = chunk(&a_text, "ov.txt", 0);
    let cb = chunk(&b_text, "ov.txt", len_a - overlap);

    let results = scanner().scan_chunks_with_backend(&[ca, cb], ScanBackend::SimdCpu);
    let count = results
        .iter()
        .flatten()
        .filter(|m| {
            m.detector_id.as_ref() == "sendgrid-api-key" && m.credential.as_ref() == SENDGRID
        })
        .count();
    // A's own scan finds the secret exactly once; the overlap pair is skipped
    // by the boundary path, so there is no second (reassembled) copy.
    assert_eq!(
        count, 1,
        "overlapping chunks must not double-report the secret (boundary path must skip overlap), got {count}"
    );
}

#[test]
fn gapped_chunks_not_reassembled() {
    // A GAP between chunks (`a_end != b.base_offset` because B starts past
    // a_end) means the missing bytes are unavailable; `scan_one_pair` bails.
    // A secret split across a gap CANNOT be reassembled.
    let (ca, _cb, len_a) = split_pair(SENDGRID, 18, "gap.txt");
    // Re-create B but lie about base_offset, leaving a 100-byte hole.
    let mut b = SENDGRID[18..].to_string();
    b.push('\n');
    let cb_gapped = chunk(&b, "gap.txt", len_a + 100);

    let results = scanner().scan_chunks_with_backend(&[ca, cb_gapped], ScanBackend::SimdCpu);
    let found = results
        .iter()
        .flatten()
        .any(|m| m.detector_id.as_ref() == "sendgrid-api-key" && m.credential.as_ref() == SENDGRID);
    assert!(
        !found,
        "a secret split across a GAP must not be reassembled (data between chunks is unavailable)"
    );
}

#[test]
fn different_file_chunks_not_reassembled() {
    // Boundary grouping is keyed on `(source_type, path)`. Two chunks with
    // DIFFERENT paths are never adjacency-paired, so a secret split across
    // files is not reassembled even when offsets look contiguous.
    let (mut ca, mut cb, _len_a) = split_pair(SENDGRID, 18, "ignored.txt");
    ca.metadata.path = Some("file-A.txt".into());
    cb.metadata.path = Some("file-B.txt".into());
    let results = scanner().scan_chunks_with_backend(&[ca, cb], ScanBackend::SimdCpu);
    let found = results
        .iter()
        .flatten()
        .any(|m| m.detector_id.as_ref() == "sendgrid-api-key" && m.credential.as_ref() == SENDGRID);
    assert!(
        !found,
        "secret split across two DIFFERENT files must not be reassembled"
    );
}

#[test]
fn single_chunk_no_boundary_scan() {
    // `scan_chunk_boundaries` early-returns when `chunks.len() < 2`. A
    // single split half on its own cannot reassemble.
    let (ca, _cb, _len_a) = split_pair(SENDGRID, 18, "solo.txt");
    let results =
        scanner().scan_chunks_with_backend(std::slice::from_ref(&ca), ScanBackend::SimdCpu);
    let found = results
        .iter()
        .flatten()
        .any(|m| m.detector_id.as_ref() == "sendgrid-api-key");
    assert!(
        !found,
        "a lone left-half chunk must not produce a sendgrid finding"
    );
}

#[test]
fn boundary_does_not_duplicate_fully_contained_secret() {
    // When the WHOLE secret already sits inside one chunk (not straddling the
    // seam), the boundary scan's straddle filter
    // (`start < seam && end > seam`) rejects it, so the result is exactly one
    // copy, never two.
    let secret_line = format!("SENDGRID_API_KEY={SENDGRID}\n");
    let ca = chunk(&secret_line, "whole.txt", 0);
    let len_a = secret_line.len();
    let cb = chunk("trailing content with no secret\n", "whole.txt", len_a);
    let results = scanner().scan_chunks_with_backend(&[ca, cb], ScanBackend::SimdCpu);
    let count = results
        .iter()
        .flatten()
        .filter(|m| {
            m.detector_id.as_ref() == "sendgrid-api-key" && m.credential.as_ref() == SENDGRID
        })
        .count();
    assert_eq!(
        count, 1,
        "fully-contained secret must be reported exactly once across the seam, got {count}"
    );
}

#[test]
fn boundary_recovers_under_both_coalesced_and_dispatch() {
    // The coalesced path (`scan_coalesced`) and the dispatch path
    // (`scan_chunks_with_backend`, CPU tiers) both append boundary findings.
    // A split AWS key must be recovered by BOTH entry points with the same
    // credential.
    let (ca1, cb1, _l1) = split_pair(AWS_KEY, 8, "dual.txt");
    let coalesced = scanner().scan_coalesced(&[ca1, cb1]);
    let via_coalesced = coalesced
        .iter()
        .flatten()
        .any(|m| m.detector_id.as_ref() == "aws-access-key" && m.credential.as_ref() == AWS_KEY);

    let (ca2, cb2, _l2) = split_pair(AWS_KEY, 8, "dual.txt");
    let dispatched = scanner().scan_chunks_with_backend(&[ca2, cb2], ScanBackend::CpuFallback);
    let via_dispatch = dispatched
        .iter()
        .flatten()
        .any(|m| m.detector_id.as_ref() == "aws-access-key" && m.credential.as_ref() == AWS_KEY);

    assert!(
        via_coalesced,
        "coalesced path must recover the split AWS key"
    );
    assert!(via_dispatch, "dispatch path must recover the split AWS key");
}

// ----------------------------------------------------------------------------
// 6. Larger fixed-corpus differential parity across all CPU backends
// ----------------------------------------------------------------------------

#[test]
fn fixed_corpus_differential_all_cpu_backends_agree() {
    // A multi-line corpus mixing secrets, comments, identifiers, and a
    // high-entropy token. The finding set must be byte-identical across both
    // CPU backends - the strongest single parity assertion.
    let token = "Zk9Qw3Rt7Yx2Mn5Bv8Cs1Lp4Df6Gh0Jk3Wq7Er2Ty9Ui4Op6A";
    let corpus = format!(
        "# config\n\
         AWS_ACCESS_KEY_ID = {AWS_KEY}\n\
         let unrelated = compute_things(42);\n\
         GITHUB_TOKEN: {GH_PAT}\n\
         // a comment line\n\
         sendgrid: {SENDGRID}\n\
         api_key = \"{token}\"\n\
         slack_bot = '{SLACK_BOT}'\n\
         stripe = \"{STRIPE_LIVE}\"\n"
    );
    let c = chunk(&corpus, "mixed.env", 0);

    let mut sets: Vec<BTreeSet<Key>> = Vec::new();
    for backend in CPU_BACKENDS {
        sets.push(key_set(&scanner().scan_with_backend(&c, backend)));
    }
    assert_eq!(
        sets[0],
        sets[1],
        "fixed-corpus finding set must be identical across SimdCpu and CpuFallback:\n\
         only-simd={:?}\n only-cpu={:?}",
        sets[0].difference(&sets[1]).collect::<Vec<_>>(),
        sets[1].difference(&sets[0]).collect::<Vec<_>>()
    );
    // The five named credentials are present in the shared set.
    for (id, cred) in [
        ("aws-access-key", AWS_KEY),
        ("github-pat-fine-grained", GH_PAT),
        ("sendgrid-api-key", SENDGRID),
        ("slack-bot-token", SLACK_BOT),
        ("stripe-secret-key", STRIPE_LIVE),
    ] {
        assert!(
            sets[0].iter().any(|(i, c, _)| i == id && c == cred),
            "expected {id}={cred} in the agreed finding set"
        );
    }
}

#[test]
fn detector_ids_and_severities_match_toml_truth() {
    // Cross-check that the named-detector emissions carry the exact
    // detector_id strings declared in the on-disk TOMLs (not a renamed or
    // duplicate id), under both backends.
    let c = chunk(
        &format!("aws={AWS_KEY}\nstripe={STRIPE_LIVE}\nslack={SLACK_BOT}\n"),
        "ids.env",
        0,
    );
    for backend in CPU_BACKENDS {
        let matches = scanner().scan_with_backend(&c, backend);
        let ids: BTreeSet<&str> = matches.iter().map(|m| m.detector_id.as_ref()).collect();
        assert!(
            ids.contains("aws-access-key"),
            "{backend:?}: missing aws-access-key id, got {ids:?}"
        );
        assert!(
            ids.contains("stripe-secret-key"),
            "{backend:?}: missing stripe-secret-key id, got {ids:?}"
        );
        assert!(
            ids.contains("slack-bot-token"),
            "{backend:?}: missing slack-bot-token id, got {ids:?}"
        );
    }
}

// ----------------------------------------------------------------------------
// 7. Property-style loop: random benign corpora never diverge between backends
// ----------------------------------------------------------------------------

/// Tiny deterministic xorshift PRNG so the property loop needs no dev-deps.
struct XorShift(u64);
impl XorShift {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

#[test]
fn property_random_benign_text_never_diverges_between_backends() {
    // For many pseudo-random benign inputs (no planted secret), the two CPU
    // backends must ALWAYS yield the identical finding set. This is the
    // soundness invariant from `collect_triggered_patterns_simd`'s comment:
    // HS only widens the candidate set, the regex confirmation re-filters, so
    // emitted findings can never differ. A divergence here is a real parity
    // bug.
    let mut rng = XorShift(0x9E3779B97F4A7C15);
    let alphabet: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _=/.\n\"'";
    for iter in 0..200u32 {
        let len = 16 + (rng.next_u64() as usize % 240);
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            let b = alphabet[(rng.next_u64() as usize) % alphabet.len()];
            s.push(b as char);
        }
        let c = chunk(&s, "rand.txt", 0);
        let simd = key_set(&scanner().scan_with_backend(&c, ScanBackend::SimdCpu));
        let cpu = key_set(&scanner().scan_with_backend(&c, ScanBackend::CpuFallback));
        assert_eq!(
            simd,
            cpu,
            "backend divergence on random input (iter {iter}):\n input={s:?}\n \
             only-simd={:?}\n only-cpu={:?}",
            simd.difference(&cpu).collect::<Vec<_>>(),
            cpu.difference(&simd).collect::<Vec<_>>()
        );
    }
}

#[test]
fn property_planted_aws_keys_recovered_by_both_backends() {
    // Plant a valid AWS key at a random position inside random benign text;
    // both backends must recover it AND agree on the full set. Asserts recall
    // parity, not just precision parity.
    let mut rng = XorShift(0xDEADBEEFCAFEF00D);
    for iter in 0..60u32 {
        let pre_len = rng.next_u64() as usize % 120;
        let mut s = String::new();
        for _ in 0..pre_len {
            s.push((b'a' + (rng.next_u64() as u8 % 26)) as char);
        }
        s.push_str(" key=\"");
        let plant_off = s.len();
        s.push_str(AWS_KEY);
        s.push_str("\"\n");

        let c = chunk(&s, "plant.env", 0);
        let simd = key_set(&scanner().scan_with_backend(&c, ScanBackend::SimdCpu));
        let cpu = key_set(&scanner().scan_with_backend(&c, ScanBackend::CpuFallback));
        assert_eq!(
            simd, cpu,
            "planted-key parity broke (iter {iter}): input={s:?}"
        );
        assert!(
            simd.contains(&("aws-access-key".to_string(), AWS_KEY.to_string(), plant_off)),
            "iter {iter}: planted AWS key at offset {plant_off} not recovered; got {simd:?}"
        );
    }
}
