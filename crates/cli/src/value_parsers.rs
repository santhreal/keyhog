//! CLI value parsers for typed command-line options.

/// Build a uniform "unparseable typed value" rejection. clap already prefixes
/// the offending input and the flag name (`invalid value '<got>' for
/// '<--flag>'`), so this states only what was *expected*: the accepted
/// range/form plus a concrete valid example. That turns a bare "not a valid
/// number" — which leaves the user guessing the bounds — into a message that is
/// itself the fix. Centralizing the wording keeps every numeric parser's
/// parse-failure branch consistent instead of drifting across a dozen
/// hand-written strings.
fn unparseable(kind: &str, accepted: &str, example: &str) -> String {
    format!("not a valid {kind}. Expected {accepted}; example: {example}")
}

/// Build a uniform "parsed, but out of range" rejection: it names the violated
/// bound and a concrete in-range example so the message states the fix, not
/// just the constraint. Used by the lower-bound (`>= 1`) parsers.
fn out_of_range(constraint: &str, example: &str) -> String {
    format!("{constraint}; example: {example}")
}

/// Accepted-form phrase shared by every `>= 1` integer parser's parse-failure
/// message. One owner so the wording cannot drift between them.
const POSITIVE_INTEGER_ACCEPTED: &str = "a positive integer (>= 1)";

/// Shared "parse a `>= 1` integer, reject 0" body for the positive count/timeout
/// knobs. `T: FromStr + Default + PartialEq` covers both the `usize` and `u64`
/// callers (`Default` is `0` for every integer type, so `val == T::default()` is
/// the zero test). Each wrapper supplies only its parse-failure `accepted` phrase,
/// its out-of-range `constraint` phrase (which names its own flag/unit), and a
/// concrete `example` — the parse + zero-check now has exactly ONE home instead of
/// six byte-identical copies. Mirrors `parse_unit_interval` for the `[0,1]` knobs.
fn parse_positive_int<T>(
    s: &str,
    accepted: &str,
    constraint: &str,
    example: &str,
) -> Result<T, String>
where
    T: std::str::FromStr + Default + PartialEq,
{
    let val: T = s
        .parse()
        .map_err(|_| unparseable("integer", accepted, example))?;
    if val == T::default() {
        Err(out_of_range(constraint, example))
    } else {
        Ok(val)
    }
}

/// Shared parser for the `[0.0, 1.0]` closed-interval "confidence-style" knobs
/// (`min_confidence`, `ml_weight`) that are configurable on BOTH surfaces — the
/// CLI flag AND the `.keyhog.toml` key. `key_label` is the BARE key name (no
/// `--`) so the single message reads correctly on either surface (the config
/// merge reuses these validators via `parse_config_*`). NaN and ±Inf are
/// rejected because `RangeInclusive::contains` is `false` for every non-finite
/// value, so a poisoned score can never slip through as "always/never passes"
/// (the CLI-003 class of bug). One definitional home for the parse + bound +
/// non-finite handling; each per-knob function only supplies its key and example.
fn parse_unit_interval(s: &str, key_label: &str, example: &str) -> Result<f64, String> {
    let val: f64 = s
        .parse()
        .map_err(|_| unparseable("decimal", "a value in [0.0, 1.0]", example))?;
    if (0.0..=1.0).contains(&val) {
        Ok(val)
    } else {
        Err(out_of_range(
            &format!("{key_label} must be between 0.0 and 1.0"),
            example,
        ))
    }
}

pub(crate) fn parse_min_confidence(s: &str) -> Result<f64, String> {
    parse_unit_interval(s, "min_confidence", "0.85")
}

/// `--ml-weight W` / config `ml_weight`: the model-score blend weight, a finite
/// f64 in `[0.0, 1.0]`. A value above 1.0 over-weights the model and a negative
/// one inverts it; NaN would silently poison every confidence. Shares
/// `parse_unit_interval` with `min_confidence` and (like it) is reused for the
/// `.keyhog.toml` `ml_weight` key via `parse_config_ml_weight`, which is why the
/// message names the bare key rather than the `--ml-weight` flag.
pub(crate) fn parse_ml_weight(s: &str) -> Result<f64, String> {
    parse_unit_interval(s, "ml_weight", "0.5")
}

/// `--entropy-bpe-max-bytes-per-token RATIO`: a finite, strictly positive
/// bytes-per-token ceiling. Large finite values are intentionally valid because
/// they are the documented way to disable the precision gate for a scan. Keep
/// this parser shared with `.keyhog.toml` so neither input surface can silently
/// normalize an invalid operator request into a different policy.
pub(crate) fn parse_entropy_bpe_max_bytes_per_token(s: &str) -> Result<f64, String> {
    let value: f64 = s
        .parse()
        .map_err(|_| unparseable("decimal", "a finite value greater than 0.0", "2.2"))?;
    if value.is_finite() && value > 0.0 {
        Ok(value)
    } else {
        Err(out_of_range(
            "entropy_bpe_max_bytes_per_token must be finite and greater than 0.0",
            "2.2",
        ))
    }
}

/// `--entropy-threshold BITS`: Shannon entropy over bytes is mathematically
/// bounded to `[0, 8]`. Reject non-finite and out-of-range operator input at the
/// boundary instead of letting the defensive scanner sanitizer silently replace
/// or clamp it to a different policy.
pub(crate) fn parse_entropy_threshold(s: &str) -> Result<f64, String> {
    let value: f64 = s
        .parse()
        .map_err(|_| unparseable("decimal", "a value in [0.0, 8.0]", "4.5"))?;
    if (0.0..=8.0).contains(&value) {
        Ok(value)
    } else {
        Err(out_of_range(
            "entropy_threshold must be a finite value between 0.0 and 8.0",
            "4.5",
        ))
    }
}

/// `--verify-rate RPS`: must be finite, > 0, and <= 10_000 (a sanity
/// cap that comfortably covers every real-world API; rejects accidental
/// `--verify-rate 1e308` typos that would otherwise be silently clamped
/// to 1 rps deep inside the limiter).
pub(crate) fn parse_verify_rate(s: &str) -> Result<f64, String> {
    let val: f64 = s
        .parse()
        .map_err(|_| unparseable("number", "a positive rate in (0, 10000] rps", "50"))?;
    if !val.is_finite() {
        return Err(format!("--verify-rate must be a finite number, got {val}"));
    }
    if val <= 0.0 {
        return Err(format!(
            "--verify-rate must be > 0 rps, got {val} \
             (use --no-verify to disable verification entirely)"
        ));
    }
    if val > 10_000.0 {
        return Err(format!(
            "--verify-rate {val} exceeds the 10_000 rps sanity cap; \
             no real provider permits that rate from a single IP"
        ));
    }
    Ok(val)
}

/// `--ml-threshold T`: must be a finite f64 in `[0.0, 1.0]`. NaN
/// silently becoming "every prediction passes" was the CLI-003 bug.
pub(crate) fn parse_ml_threshold(s: &str) -> Result<f64, String> {
    let val: f64 = s
        .parse()
        .map_err(|_| unparseable("decimal", "a value in [0.0, 1.0]", "0.5"))?;
    if !val.is_finite() {
        return Err(format!(
            "--ml-threshold must be a finite number (no NaN/Inf), got {val}"
        ));
    }
    if !(0.0..=1.0).contains(&val) {
        return Err(out_of_range(
            "--ml-threshold must be between 0.0 and 1.0",
            "0.5",
        ));
    }
    Ok(val)
}

pub(crate) fn parse_decode_depth(s: &str) -> Result<usize, String> {
    let limit = keyhog_core::max_decode_depth_limit();
    let val: usize = s
        .parse()
        .map_err(|_| unparseable("integer", &format!("an integer in [1, {limit}]"), "3"))?;
    if (1..=limit).contains(&val) {
        Ok(val)
    } else {
        Err(out_of_range(
            &format!("decode depth must be between 1 and {limit}"),
            "3",
        ))
    }
}

pub(crate) fn parse_min_secret_len(s: &str) -> Result<usize, String> {
    parse_positive_int(
        s,
        POSITIVE_INTEGER_ACCEPTED,
        "--min-secret-len must be >= 1",
        "16",
    )
}

pub(crate) fn parse_positive_thread_count(s: &str) -> Result<usize, String> {
    parse_positive_int(s, POSITIVE_INTEGER_ACCEPTED, "--threads must be >= 1", "4")
}

// Gate = the UNION of every caller's feature (args/limits.rs): `limit_git_chunks`
// (git), `limit_cloud_max_objects` (s3/gcs/azure), `limit_hosted_git_pages`
// (github/gitlab/bitbucket). Gating this to `git` alone made `--features s3` /
// `--features github` (no git) fail with `parse_positive_limit_count` not found
// — the value-parser is referenced by their clap args but was cfg'd out.
#[cfg(any(
    feature = "git",
    feature = "s3",
    feature = "gcs",
    feature = "azure",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket"
))]
pub(crate) fn parse_positive_limit_count(s: &str) -> Result<usize, String> {
    parse_positive_int(
        s,
        POSITIVE_INTEGER_ACCEPTED,
        "limit count must be >= 1",
        "100",
    )
}

pub(crate) fn parse_positive_usize(s: &str) -> Result<usize, String> {
    parse_positive_int(s, POSITIVE_INTEGER_ACCEPTED, "value must be >= 1", "1")
}

pub(crate) fn parse_daemon_request_timeout_secs(s: &str) -> Result<u64, String> {
    parse_positive_int(
        s,
        "a positive number of seconds (>= 1)",
        "--request-timeout-secs must be >= 1",
        "30",
    )
}

pub(crate) fn parse_positive_millis(s: &str) -> Result<u64, String> {
    parse_positive_int(
        s,
        "a positive number of milliseconds (>= 1)",
        "millisecond timeout must be >= 1",
        "500",
    )
}

pub(crate) fn parse_byte_size(s: &str) -> Result<usize, String> {
    let trimmed = s.trim();
    // Empty input keeps the historical Ok(0) contract - clap callers
    // that accept an optional size flag rely on it. Only inputs that
    // are POSITIVELY malformed (bare numbers, overflow, bad unit)
    // should error.
    if trimmed.is_empty() {
        return Ok(0);
    }
    let split_idx = trimmed
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(trimmed.len()); // LAW10: search/boundary miss => span end (whole remainder), recall-safe boundary default
    let (num_part, suffix) = trimmed.split_at(split_idx);

    let suffix_upper = suffix.trim().to_ascii_uppercase();
    let multiplier: u64 = match suffix_upper.as_str() {
        "" => {
            // Bare numbers like "10" are ambiguous with the GB-scale
            // defaults the rest of the CLI uses (`50G`). The test
            // fixtures explicitly assert this must error rather than
            // silently mean bytes.
            return Err(format!(
                "byte size '{trimmed}' is missing a unit. Use `B`, `K`/`KB`, `M`/`MB`, `G`/`GB`, or `T`/`TB`."
            ));
        }
        "B" => 1,
        "K" | "KB" | "KIB" => 1024,
        "M" | "MB" | "MIB" => 1024 * 1024,
        "G" | "GB" | "GIB" => 1024 * 1024 * 1024,
        "T" | "TB" | "TIB" => 1024_u64.pow(4),
        other => {
            return Err(format!(
                "unknown size suffix '{other}'. Supported: B, K/KB, M/MB, G/GB, T/TB"
            ));
        }
    };

    // Parse the number. Try integer first (most common, lossless,
    // overflows cleanly to Err on numbers wider than u64). Fall back
    // to f64 for fractional inputs like "1.5G".
    if let Ok(n_int) = num_part.parse::<u64>() {
        // LAW10: optional exact integer path; fractional inputs are validated by the finite f64 path below.
        // Overflow-safe integer multiply. The previous `as usize`
        // path silently saturated to usize::MAX for `u64::MAX B`,
        // which the test fixtures explicitly assert must error.
        let bytes = n_int.checked_mul(multiplier).ok_or_else(|| {
            format!(
                "byte size '{trimmed}' overflows u64 ({} * {} bytes)",
                n_int, multiplier
            )
        })?;
        // Sanity cap: real disk/RAM sizes are < 1 EiB even on the
        // largest known machines, and inputs beyond `usize::MAX / 2`
        // are almost certainly typos or attacks (the test fixtures
        // assert `u64::MAX B` must error, which it does at this gate).
        // Half of usize::MAX leaves headroom for downstream code that
        // adds offsets without overflow checks.
        let cap = usize::MAX / 2;
        if bytes as u128 > cap as u128 {
            return Err(format!(
                "byte size '{trimmed}' exceeds the {cap}-byte sanity cap"
            ));
        }
        usize::try_from(bytes).map_err(|_| {
            format!(
                "byte size '{trimmed}' overflows usize (max {} bytes on this platform)",
                usize::MAX
            )
        })
    } else {
        let n: f64 = num_part
            .parse()
            .map_err(|e| format!("bad number '{num_part}': {e}"))?;
        if !n.is_finite() || n < 0.0 {
            return Err(format!(
                "byte size must be a finite, non-negative number, got: {num_part}"
            ));
        }
        let bytes_f = n * multiplier as f64;
        // f64 can't represent usize::MAX exactly on 64-bit (rounds up
        // to 2^64), so the strict ceiling for a safe `as usize` cast
        // is `bytes_f < 2^64`.
        let max_safe = 2.0_f64.powi(64);
        if !bytes_f.is_finite() || bytes_f < 0.0 || bytes_f >= max_safe {
            return Err(format!(
                "byte size '{trimmed}' overflows usize (max {} bytes)",
                usize::MAX
            ));
        }
        Ok(bytes_f as usize)
    }
}

/// `keyhog detectors [list]`: the optional positional verb. `detectors`
/// already lists by default, so the only accepted verb is the explicit,
/// historically-documented `list` (case-insensitive) - it makes
/// `keyhog detectors list` a clean no-op alias for `keyhog detectors`
/// instead of a clap `unexpected argument 'list'` error. Any other token is a
/// typo and must be rejected loudly rather than silently swallowed, so the
/// operator gets a precise message instead of a misparsed flag value.
pub(crate) fn parse_detectors_verb(s: &str) -> Result<String, String> {
    if s.eq_ignore_ascii_case("list") {
        Ok("list".to_string())
    } else {
        Err(format!(
            "unknown verb '{s}'. `keyhog detectors` lists detectors by default; \
             the only accepted positional verb is `list`. Use \
             `keyhog detectors --detectors <DIR>` (optionally `--search`, \
             `--audit`, `--fix`, `--json`)."
        ))
    }
}

/// Accepted-spelling description for [`parse_severity_filter`], surfaced in
/// config rejection messages. One owner so the accepted list cannot drift from
/// the match arms below or get re-pasted per call site.
pub(crate) const SEVERITY_ACCEPTED: &str = "expected one of info, low, medium, high, critical";

/// Parse a severity string into the CLI filter enum. Shared by the flat
/// top-level `severity` field and the `[scan]` nested table in `.keyhog.toml`
/// so both surfaces accept identical spellings (one source of truth).
pub(crate) fn parse_severity_filter(s: &str) -> Option<crate::args::SeverityFilter> {
    use crate::args::SeverityFilter as S;
    match s.to_lowercase().as_str() {
        "info" => Some(S::Info),
        "low" => Some(S::Low),
        "medium" => Some(S::Medium),
        "high" => Some(S::High),
        "critical" => Some(S::Critical),
        _ => None,
    }
}

/// Accepted-spelling description for [`parse_output_format`]. One owner (see
/// [`SEVERITY_ACCEPTED`]).
pub(crate) const OUTPUT_FORMAT_ACCEPTED: &str =
    "expected one of text, json, jsonl, sarif, csv, github-annotations, gitlab-sast, html, junit";

/// Parse an output-format string. Shared by the flat `format` field and `[scan]`.
pub(crate) fn parse_output_format(s: &str) -> Option<crate::args::OutputFormat> {
    use crate::args::OutputFormat as F;
    match s.to_lowercase().as_str() {
        "text" => Some(F::Text),
        "json" => Some(F::Json),
        "jsonl" => Some(F::Jsonl),
        "sarif" => Some(F::Sarif),
        "csv" => Some(F::Csv),
        "github-annotations" | "github_annotations" => Some(F::GithubAnnotations),
        "gitlab-sast" | "gitlab_sast" => Some(F::GitlabSast),
        "html" => Some(F::Html),
        "junit" => Some(F::Junit),
        _ => None,
    }
}

/// Accepted-spelling description for [`parse_dedup_scope`]. One owner (see
/// [`SEVERITY_ACCEPTED`]).
pub(crate) const DEDUP_SCOPE_ACCEPTED: &str = "expected one of credential, file, none";

/// Parse a dedup-scope string. Shared by the flat `dedup` field and `[scan]`.
pub(crate) fn parse_dedup_scope(s: &str) -> Option<crate::args::CliDedupScope> {
    use crate::args::CliDedupScope as D;
    match s.to_lowercase().as_str() {
        "credential" => Some(D::Credential),
        "file" => Some(D::File),
        "none" => Some(D::None),
        _ => None,
    }
}
