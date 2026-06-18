//! CLI value parsers for typed command-line options.

pub fn parse_min_confidence(s: &str) -> Result<f64, String> {
    let val: f64 = s
        .parse()
        .map_err(|_| format!("'{}' is not a valid floating point number", s))?;
    if (0.0..=1.0).contains(&val) {
        Ok(val)
    } else {
        Err(format!(
            "min_confidence must be between 0.0 and 1.0, got {}",
            val
        ))
    }
}

/// `--verify-rate RPS`: must be finite, > 0, and <= 10_000 (a sanity
/// cap that comfortably covers every real-world API; rejects accidental
/// `--verify-rate 1e308` typos that would otherwise be silently clamped
/// to 1 rps deep inside the limiter).
pub fn parse_verify_rate(s: &str) -> Result<f64, String> {
    let val: f64 = s
        .parse()
        .map_err(|_| format!("'{s}' is not a valid floating point number"))?;
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
pub fn parse_ml_threshold(s: &str) -> Result<f64, String> {
    let val: f64 = s
        .parse()
        .map_err(|_| format!("'{s}' is not a valid floating point number"))?;
    if !val.is_finite() {
        return Err(format!(
            "--ml-threshold must be a finite number (no NaN/Inf), got {val}"
        ));
    }
    if !(0.0..=1.0).contains(&val) {
        return Err(format!(
            "--ml-threshold must be between 0.0 and 1.0, got {val}"
        ));
    }
    Ok(val)
}

pub fn parse_decode_depth(s: &str) -> Result<usize, String> {
    let val: usize = s
        .parse()
        .map_err(|_| format!("'{}' is not a valid positive integer", s))?;
    let limit = keyhog_core::config::max_decode_depth_limit();
    if (1..=limit).contains(&val) {
        Ok(val)
    } else {
        Err(format!("decode depth must be between 1 and {limit}, got {val}"))
    }
}

pub fn parse_positive_thread_count(s: &str) -> Result<usize, String> {
    let val: usize = s
        .parse()
        .map_err(|_| format!("'{s}' is not a valid positive integer"))?;
    if val == 0 {
        Err("--threads must be greater than zero".to_string())
    } else {
        Ok(val)
    }
}

pub fn parse_byte_size(s: &str) -> Result<usize, String> {
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
        .unwrap_or(trimmed.len());
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
            ))
        }
    };

    // Parse the number. Try integer first (most common, lossless,
    // overflows cleanly to Err on numbers wider than u64). Fall back
    // to f64 for fractional inputs like "1.5G".
    if let Ok(n_int) = num_part.parse::<u64>() {
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
pub fn parse_detectors_verb(s: &str) -> Result<String, String> {
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

/// Parse a severity string into the CLI filter enum. Shared by the flat
/// top-level `severity` field and the `[scan]` nested table in `.keyhog.toml`
/// so both surfaces accept identical spellings (one source of truth).
pub fn parse_severity_filter(s: &str) -> Option<crate::args::SeverityFilter> {
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

/// Parse an output-format string. Shared by the flat `format` field and `[scan]`.
pub fn parse_output_format(s: &str) -> Option<crate::args::OutputFormat> {
    use crate::args::OutputFormat as F;
    match s.to_lowercase().as_str() {
        "json" => Some(F::Json),
        "jsonl" => Some(F::Jsonl),
        "sarif" => Some(F::Sarif),
        "text" => Some(F::Text),
        _ => None,
    }
}

/// Parse a dedup-scope string. Shared by the flat `dedup` field and `[scan]`.
pub fn parse_dedup_scope(s: &str) -> Option<crate::args::CliDedupScope> {
    use crate::args::CliDedupScope as D;
    match s.to_lowercase().as_str() {
        "credential" => Some(D::Credential),
        "file" => Some(D::File),
        "none" => Some(D::None),
        _ => None,
    }
}
