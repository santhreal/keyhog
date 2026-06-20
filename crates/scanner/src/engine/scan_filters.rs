/// Fast check for secret-related keywords in file content.
/// Used to gate the multiline fallback - only files that mention
/// secret/key/token/password are worth reassembling.
///
/// Used by coalesced SIMD and GPU phase2 no-hit routing to avoid full phase-2
/// scans on chunks that cannot plausibly contain split or prefix-known secrets.
///
/// Single-pass Aho-Corasick over all distinctive prefixes - replaces the
/// previous loop of N independent `memmem` scans (each O(n)) which traversed
/// the chunk N times. With the AC automaton the scan is O(n) total, with
/// one memory walk and shared cache lines.
//
// `any(simd, gpu)`: invoked only from `should_scan_no_hit_chunk`, the
// no-phase-1-trigger admission gate on the coalesced (`simd`) /
// region-presence (`gpu`) phase-2 tail. The no-`simd`-no-`gpu` AC+phase-2 path scans every
// chunk whole and never routes through that gate, so this filter has no caller
// there — gated to match (Law 11).
#[cfg(any(feature = "simd", feature = "gpu"))]
pub(super) fn has_secret_keyword_fast(data: &[u8]) -> bool {
    use aho_corasick::AhoCorasick;
    use std::sync::LazyLock;
    // Hold an `Option` instead of `.expect()`-unwrapping at LazyLock-init
    // time: a panic in a static initializer poisons the LazyLock for the
    // rest of the process and kills every subsequent prefilter call across
    // all threads. On the (build-invariant-violating) `None` path the
    // consumer returns `true` — scan the chunk unconditionally, so recall is
    // preserved — but Law 10 forbids doing that SILENTLY, so the init closure
    // warns loudly exactly once via `prefilter_degrade`.
    static AC: LazyLock<Option<AhoCorasick>> = LazyLock::new(|| {
        // Distinctive enough to be real secrets AND commonly split across
        // lines in source code. The previous 5-entry list missed every
        // GitHub variant after `ghp_` (ghs_, gho_, ghu_, ghr_), every
        // Stripe live key family except `sk_live_`, every modern OpenAI
        // org/proj key past `sk-proj-`, plus the high-volume HF/Anthropic/
        // GCP service-key prefixes that show up split across lines in
        // copy-pasted .env files. Avoid short prefixes (AKIA, eyJ) that
        // appear in fixtures.
        match AhoCorasick::new([
            // OpenAI
            "sk-proj-",
            "sk-svcacct-",
            "sk-admin-",
            // Stripe
            "sk_live_",
            "sk_test_",
            "rk_live_",
            "pk_live_",
            // GitHub (all installation variants)
            "ghp_",
            "ghs_",
            "gho_",
            "ghu_",
            "ghr_",
            "github_pat_",
            // Slack
            "xoxb-",
            "xoxp-",
            "xoxa-",
            "xoxr-",
            "xoxs-",
            "xapp-",
            // Anthropic
            "sk-ant-",
            // HuggingFace
            "hf_",
            // GCP service account email shard (rarely splits, but cheap)
            ".iam.gserviceaccount.com",
            // GitLab
            "glpat-",
            // npm
            "npm_",
            // Heroku UUID-style key family
            "HRKU-",
        ]) {
            Ok(ac) => Some(ac),
            Err(e) => {
                crate::prefilter_degrade::warn_prefilter_disabled(
                    "multiline secret-keyword gate (has_secret_keyword_fast)",
                    &e,
                );
                None
            }
        }
    });
    // Fail-closed (Law 10): `None` → scan the chunk unconditionally rather than
    // skip it. The warning above already surfaced the degradation once.
    AC.as_ref().is_none_or(|ac| ac.find(data).is_some())
}

pub(super) const GENERIC_ASSIGNMENT_KEYWORDS: &[&str] = &[
    "secret",
    "password",
    "passwd",
    "pwd",
    // Bare `pass` (covers `*_PASS=`, the dominant CredData credential-env
    // pattern). This is only the line PREFILTER; the GENERIC_RE bridge in
    // phase2_generic.rs applies a whole-word left boundary so `bypass=` /
    // `compass=` are not promoted to findings. `pass` substring-covers the
    // `password`/`passwd`/`passphrase` lines above too — those entries are kept
    // for self-documentation.
    "pass",
    "token",
    "webhook_url",
    "webhook-url",
    "webhook.url",
    "apikey",
    "api_key",
    "api-key",
    "api.key",
    "auth",
    "auth_token",
    "auth-token",
    "auth.token",
    "auth_key",
    "auth-key",
    "auth.key",
    "credential",
    "private_key",
    "private-key",
    "private.key",
    "signing_key",
    "signing-key",
    "signing.key",
    "encryption_key",
    "encryption-key",
    "encryption.key",
    "access_key",
    "access-key",
    "access.key",
    "client_secret",
    "client-secret",
    "client.secret",
    "app_secret",
    "app-secret",
    "app.secret",
    "master_key",
    "master-key",
    "master.key",
    "license_key",
    "license-key",
    "license.key",
];

/// Check for generic `secret=`, `password:`, `token=` etc. keywords.
/// Broader than `has_secret_keyword_fast` (which is for multiline only).
///
/// Same single-pass AC strategy as `has_secret_keyword_fast`, but with the
/// case-insensitive variants folded into one automaton - `aho-corasick`'s
/// `ascii_case_insensitive` builder option matches both `secret` and
/// `SECRET` from a single literal at scan-time, halving the pattern count.
///
//
// `any(simd, gpu)`: like `has_secret_keyword_fast`, this is consumed only by
// `should_scan_no_hit_chunk` on the coalesced/region-presence phase-2 tail;
// gated to match its caller so no-`simd`-no-`gpu` builds stay warning-clean (Law 11).
#[cfg(any(feature = "simd", feature = "gpu"))]
pub(super) fn has_generic_assignment_keyword(data: &[u8]) -> bool {
    use aho_corasick::AhoCorasick;
    use std::sync::LazyLock;
    // See `has_secret_keyword_fast` for the rationale; same fail-closed
    // (`true` on init failure) so the prefilter never causes an FN by
    // dropping a chunk, and the same loud one-shot warning (Law 10) so the
    // degradation is never silent.
    static AC: LazyLock<Option<AhoCorasick>> = LazyLock::new(|| {
        match AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(GENERIC_ASSIGNMENT_KEYWORDS.iter().copied())
        {
            Ok(ac) => Some(ac),
            Err(e) => {
                crate::prefilter_degrade::warn_prefilter_disabled(
                    "generic-assignment keyword gate (has_generic_assignment_keyword)",
                    &e,
                );
                None
            }
        }
    });
    AC.as_ref().is_none_or(|ac| ac.find(data).is_some())
}

/// Single-pass scan for a contiguous run of credential-value bytes (including
/// common token separators and symbolic password punctuation).
/// of length >= `MIN_ENTROPY_RUN`. The keyword-gated fallback drop in
/// `scan_coalesced` (no-HS-hit branch) historically required the chunk
/// to contain a generic-assignment / secret keyword before routing
/// through `scan_inner` — chunks of pure entropy with NO keyword anchor
/// (the `generic-high-entropy-string` corpus shape) silently bailed,
/// pinning that category's recall at 0.36 on the SecretBench mirror.
///
/// `MIN_ENTROPY_RUN` is set to 32 chars so the gate stays cheap and
/// rarely trips on natural code: function/class names cap around 24
/// chars, UUIDs are 36 chars *with dashes* (longest base62 run = 12),
/// and the longest English word is 28 chars. Real secrets at this
/// threshold are credentials (32-char hex APIs, 40-char base62 tokens,
/// symbolic passwords, 64-char SHA hex, base64 blobs). Hash/UUID-shaped FPs
/// are still suppressed downstream by the bare/prefixed hash gates and
/// `is_uuid_v4_shape`, so trip-firing the gate does NOT add FPs - it just
/// admits the chunk to the entropy fallback for inspection.
//
// `any(simd, gpu)`: both callers live behind these features — the
// `should_scan_no_hit_chunk` admission gate (`any(simd, gpu)`) and the entropy
// fallback's cheap precheck (`#[cfg(simd)]` in `phase2_entropy.rs`). Their
// union is `any(simd, gpu)`; the no-`simd`-no-`gpu` path has neither, so gating
// here keeps that profile warning-clean (Law 11).
#[cfg(any(feature = "simd", feature = "gpu"))]
pub(super) fn has_high_entropy_run_fast(data: &[u8]) -> bool {
    has_high_entropy_run_at_least(data, DEFAULT_ENTROPY_RUN_BYTES)
}

#[cfg(any(feature = "simd", feature = "gpu"))]
pub(super) const DEFAULT_ENTROPY_RUN_BYTES: usize = 32;

#[cfg(any(feature = "simd", feature = "gpu"))]
pub(super) fn has_high_entropy_run_at_least(data: &[u8], min_run: usize) -> bool {
    let min_run = min_run.max(1);
    let mut run = 0usize;
    for &b in data {
        if is_entropy_candidate_byte(b) {
            run += 1;
            if run >= min_run {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

#[cfg(any(feature = "simd", feature = "gpu"))]
fn is_entropy_candidate_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'_'
                | b'+'
                | b'/'
                | b'='
                | b'.'
                | b':'
                | b'!'
                | b'@'
                | b'#'
                | b'$'
                | b'%'
                | b'^'
                | b'&'
                | b'*'
        )
}

/// The compiled default for the Tier-A `entropy_threshold` knob
/// (`keyhog_core::ScanConfig::default().entropy_threshold == 4.5`,
/// documented in `crates/cli/src/config.rs` and `.keyhog.toml.example`).
///
/// At this resolved value the generic gate uses ONLY the per-detector /
/// per-length base floors below, so the shipped recall/precision tuning (and
/// every benchmark pinned to the default) is byte-for-byte unchanged. The
/// operator knob only *raises* the floor above the base when set above this
/// default — see [`generic_entropy_floor`].
const DEFAULT_GENERIC_ENTROPY_THRESHOLD: f64 = 4.5;

/// SINGLE source of truth for the generic-detector entropy gate.
///
/// Two inputs decide whether a generic / weakly-anchored value carries enough
/// randomness to report:
///
///   1. A per-detector, per-length BASE floor. Different secret formats have
///      inherently different entropy profiles, so a blanket 3.5 floor causes
///      false negatives on UUID-style and short fixed-alphabet tokens:
///        - Random hex tokens (npm): ~3.7-4.0
///        - Base64 tokens (JWTs):    ~5.0-5.5
///        - UUID-based keys (Heroku):~3.0-3.3
///        - Short API keys:          ~3.2-3.8
///      These base floors are tuned for recall at the DEFAULT threshold and
///      must not change there.
///
///   2. The operator's resolved Tier-A `entropy_threshold` knob
///      (`ScannerConfig.entropy_threshold`, fed from `--entropy-threshold` /
///      `.keyhog.toml`). The documented semantics are "5.5: Conservative
///      (fewer findings)" — raising the knob must TIGHTEN the gate. We honor
///      that by lifting the effective floor to at least the operator's chosen
///      bits/byte once it exceeds the compiled default, so a value whose
///      entropy is below the operator threshold is suppressed. At/below the
///      default the base floor wins untouched (no-op), preserving shipped
///      behavior and benchmark parity.
///
/// This is the ONE function both the named-detector generic path
/// (`engine/process.rs`) and the `generic-secret` fallback
/// (`engine/phase2_generic.rs`) call, replacing the two divergent hardcoded
/// floor tables that previously encoded the same decision with different magic
/// numbers and ignored the knob entirely.
pub(super) fn generic_entropy_floor(
    entropy_threshold: f64,
    detector_id: &str,
    credential_len: usize,
) -> f64 {
    let base: f64 = match detector_id {
        // Short tokens with restricted alphabets need a STRICTER floor to avoid
        // admitting low-diversity identifiers. Must precede the `<= 40` arm:
        // guard arms evaluate top-to-bottom, so listing `<= 40` first would
        // subsume this (every len<=24 is also <=40) and make 3.0 dead code.
        "generic-api-key" if credential_len <= 24 => 3.0,
        // UUID-based tokens (25..=40) have lower entropy due to hex + dashes.
        "generic-api-key" if credential_len <= 40 => 2.8,
        // Long random strings need higher entropy to distinguish from code
        "generic-api-key" => 3.5,
        // Password fields can be anything
        "generic-password" => 2.5,
        // Database connection strings have structure
        "generic-database-url" => 2.0,
        // `generic-secret` (the `SECRET_NAME = "value"` phase-2 bridge). These three
        // per-length floors are the values the phase-2 path historically baked
        // in (2.8 / 3.2 / 3.5); kept identical so default behavior is unchanged.
        "generic-secret" if credential_len <= 24 => 2.8,
        "generic-secret" if credential_len <= 40 => 3.2,
        "generic-secret" => 3.5,
        // Keyword-anchored generic bridge (`PASSWORD=`, `*_PASS=`, `secret:`,
        // `api_key=` ...). The credential KEYWORD in the key is itself strong
        // evidence, so the entropy bar is far lower than the bare
        // `generic-secret` path: real CredData passwords (`gjbubxsu`, `krbykalt`)
        // sit at ~2.0-2.8 bits and were lost wholesale to the 2.8/3.2/3.5 floor,
        // pinning real-world recall near 0.09. Precision on this relaxed surface
        // is carried by the MoE (retrained on these candidates) and the shape
        // filters, NOT by entropy. Honors the operator's `--entropy-threshold`
        // exactly like the other arms (the `base.max(threshold)` below).
        "generic-keyword-secret" => 1.5,
        // Default: original threshold
        _ => 3.5,
    };

    // Honor the operator knob: a threshold above the compiled default lifts the
    // floor to that bits/byte value (never below the recall-tuned base). A NaN
    // threshold (config sanitization already clamps it, but be defensive) or a
    // value at/under the default leaves `base` untouched.
    if entropy_threshold.is_finite() && entropy_threshold > DEFAULT_GENERIC_ENTROPY_THRESHOLD {
        base.max(entropy_threshold)
    } else {
        base
    }
}

pub(super) fn looks_like_variable_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    // Pure ASCII check - byte ops are ~4x faster than .chars().all()
    // because they skip UTF-8 decode and char boundary tracking.
    bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'_')
}

pub(super) fn extend_known_prefix_credential<'a>(
    data: &'a str,
    credential: &'a str,
    match_end: usize,
) -> (&'a str, usize) {
    let (credential, match_end) = if crate::confidence::known_prefix_confidence_floor(credential)
        .is_some()
    {
        let bytes = data.as_bytes();
        let mut end = match_end;
        while end < bytes.len() && is_provider_token_byte(bytes[end]) {
            end += 1;
        }

        if end == match_end || !data.is_char_boundary(end) {
            (credential, match_end)
        } else {
            // Slice from the CREDENTIAL's own start, not `match_start`. For a
            // grouped detector `KEYWORD[=:\s"']+(VALUE)` the whole regex span
            // starts at the keyword, not the secret. `credential` is a subslice
            // of `data` (extract.rs builds it as `&search_text[range]`, and
            // `data == search_text` here), so its byte offset within `data` is
            // the pointer delta. Fall back to the unextended credential if that
            // invariant ever fails to hold (defensive; never on the real path).
            let cred_start = (credential.as_ptr() as usize).wrapping_sub(data.as_ptr() as usize);
            if cred_start <= match_end && end <= bytes.len() && data.is_char_boundary(cred_start) {
                (&data[cred_start..end], end)
            } else {
                (credential, match_end)
            }
        }
    } else {
        (credential, match_end)
    };

    extend_base64_padding(data, credential, match_end)
}

/// Swallow up to two trailing `=` when the captured body is base64-shaped.
/// Regexes often end with `=?` or `{20,}=?` and drop the second padding
/// char on values like `YWJj…vcA==` - `splitio-api-key` and friends.
fn extend_base64_padding<'a>(
    data: &'a str,
    credential: &'a str,
    match_end: usize,
) -> (&'a str, usize) {
    if !credential
        .bytes()
        .all(crate::decode::is_base64_candidate_byte)
    {
        return (credential, match_end);
    }
    let bytes = data.as_bytes();
    let mut end = match_end;
    let mut pad = 0u8;
    while end < bytes.len() && bytes[end] == b'=' && pad < 2 {
        end += 1;
        pad += 1;
    }
    if pad > 0 && data.is_char_boundary(end) {
        // Slice from the credential's own start (subslice of `data`) so base64
        // padding recovery on a grouped detector never prepends the keyword to
        // the credential.
        let cred_start = (credential.as_ptr() as usize).wrapping_sub(data.as_ptr() as usize);
        if cred_start <= match_end && data.is_char_boundary(cred_start) {
            (&data[cred_start..end], end)
        } else {
            (credential, match_end)
        }
    } else {
        (credential, match_end)
    }
}

fn is_provider_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

/// Compute the two per-pattern-constant confidence signals (`keyword_nearby`,
/// `sensitive_file`). Extracted so `extract_grouped_matches`,
/// `extract_plain_matches`, and the shared-anchor path share one lazy
/// `OnceCell` init closure body (Rust can't `impl FnOnce<>` to share inline).
/// Lives here (not `scan.rs`) to keep that file under the standard 500-LOC cap.
pub(super) fn compute_pattern_signals(
    detector: &keyhog_core::DetectorSpec,
    chunk: &keyhog_core::Chunk,
) -> (bool, bool) {
    let kw = detector
        .keywords
        .iter()
        .any(|keyword| chunk.data.contains(keyword.as_str()));
    let sf = chunk
        .metadata
        .path
        .as_deref()
        .map(crate::confidence::is_sensitive_path)
        .unwrap_or(false); // LAW10: empty/absent => documented numeric/sentinel default, recall-safe
    (kw, sf)
}
