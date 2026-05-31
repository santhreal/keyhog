use super::ExtractedPair;

/// Parse Terraform / HCL `variable "<name>" { default = "<value>" }`
/// blocks, flat `.tfvars` assignments, and simple `locals { x = "v" }`
/// assignment shapes into `(context, value)` pairs.
pub fn parse_hcl(text: &str) -> Vec<ExtractedPair> {
    let mut pairs = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        let trimmed = line.trim_start();
        if let Some((var_name, _start_line)) = parse_variable_header(trimmed) {
            let mut depth = 1usize;
            let mut consumed = 1usize;
            for offset in 1..MAX_VARIABLE_BLOCK_LINES {
                if index + offset >= lines.len() {
                    break;
                }
                let inner = lines[index + offset];
                let body = inner.trim();
                if body.contains('{') {
                    depth += body.matches('{').count();
                }
                if body.contains('}') {
                    depth = depth.saturating_sub(body.matches('}').count());
                    if depth == 0 {
                        consumed = offset + 1;
                        break;
                    }
                }
                if let Some(value) = parse_hcl_default(body) {
                    if !value.is_empty() {
                        pairs.push(ExtractedPair {
                            context: var_name.clone(),
                            value,
                            line: index + offset + 1,
                        });
                    }
                }
            }
            index += consumed;
            continue;
        }
        if let Some((name, value)) = parse_hcl_assignment(trimmed) {
            if !name.is_empty() && !value.is_empty() {
                pairs.push(ExtractedPair {
                    context: name,
                    value,
                    line: index + 1,
                });
            }
        }
        index += 1;
    }
    pairs
}

/// Real terraform blocks are short; cap the lookahead so malformed files do not
/// run into the next block indefinitely.
const MAX_VARIABLE_BLOCK_LINES: usize = 16;

fn parse_variable_header(line: &str) -> Option<(String, usize)> {
    let rest = line.strip_prefix("variable")?;
    if !rest.starts_with(|c: char| c.is_ascii_whitespace()) {
        return None;
    }
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    let name = &rest[..end];
    if name.is_empty() {
        return None;
    }
    Some((name.to_string(), 0))
}

fn parse_hcl_default(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let rest = trimmed.strip_prefix("default")?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    extract_quoted_value(rest)
}

fn parse_hcl_assignment(line: &str) -> Option<(String, String)> {
    if line.starts_with('#') || line.starts_with("//") || line.ends_with('{') || !line.contains('=')
    {
        return None;
    }
    for kw in [
        "variable",
        "locals",
        "resource",
        "module",
        "provider",
        "data",
        "output",
        "terraform",
    ] {
        if line.starts_with(kw)
            && line[kw.len()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_whitespace() || c == '{')
        {
            return None;
        }
    }
    let (name_part, value_part) = line.split_once('=')?;
    let name = name_part.trim();
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return None;
    }
    let value = extract_quoted_value(value_part.trim_start())?;
    Some((name.to_string(), value))
}

fn extract_quoted_value(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let quote = bytes[0];
    if !matches!(quote, b'"' | b'\'' | b'`') {
        return None;
    }
    let body = &s[1..];
    let end = body.find(quote as char)?;
    Some(body[..end].to_string())
}
