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
    let s = s.trim().to_uppercase();
    if s.is_empty() {
        return Ok(0);
    }

    let (val_str, multiplier) = if s.ends_with("GB") {
        (&s[..s.len() - 2], 1024 * 1024 * 1024)
    } else if s.ends_with('G') {
        (&s[..s.len() - 1], 1024 * 1024 * 1024)
    } else if s.ends_with("MB") {
        (&s[..s.len() - 2], 1024 * 1024)
    } else if s.ends_with('M') {
        (&s[..s.len() - 1], 1024 * 1024)
    } else if s.ends_with("KB") {
        (&s[..s.len() - 2], 1024)
    } else if s.ends_with('K') {
        (&s[..s.len() - 1], 1024)
    } else if s.ends_with('B') {
        (&s[..s.len() - 1], 1)
    } else {
        return Err(format!(
            "invalid byte size '{}': missing unit suffix (use B, KB, MB, or GB)",
            s
        ));
    };

    let val: usize = val_str
        .trim()
        .parse()
        .map_err(|_| format!("invalid byte size: {}", s))?;
    let result = val
        .checked_mul(multiplier)
        .ok_or_else(|| format!("byte size overflow: {}", s))?;
    const MAX_REASONABLE_BYTES: usize = 1024 * 1024 * 1024 * 1024;
    if result > MAX_REASONABLE_BYTES {
        return Err(format!("byte size too large: {} (max 1TB)", s));
    }
    Ok(result)
}
