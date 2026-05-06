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

pub fn parse_decode_depth(s: &str) -> Result<usize, String> {
    let val: usize = s
        .parse()
        .map_err(|_| format!("'{}' is not a valid positive integer", s))?;
    if (1..=10).contains(&val) {
        Ok(val)
    } else {
        Err(format!(
            "decode depth must be between 1 and 10, got {}",
            val
        ))
    }
}

pub fn parse_byte_size(s: &str) -> Result<usize, String> {
    let trimmed = s.trim();
    // Empty input keeps the historical Ok(0) contract — clap callers
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
                "byte size '{trimmed}' is missing a unit — use `B`, `K`/`KB`, `M`/`MB`, `G`/`GB`, or `T`/`TB`."
            ));
        }
        "B" => 1,
        "K" | "KB" | "KIB" => 1024,
        "M" | "MB" | "MIB" => 1024 * 1024,
        "G" | "GB" | "GIB" => 1024 * 1024 * 1024,
        "T" | "TB" | "TIB" => 1024_u64.pow(4),
        other => {
            return Err(format!(
                "unknown size suffix '{other}' — supported: B, K/KB, M/MB, G/GB, T/TB"
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
