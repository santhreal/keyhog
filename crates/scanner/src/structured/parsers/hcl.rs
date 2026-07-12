use super::ExtractedPair;

/// Parse Terraform / HCL `variable "<name>" { default = "<value>" }`
/// blocks, flat `.tfvars` assignments, and simple `locals { x = "v" }`
/// assignment shapes into `(context, value)` pairs.
pub(crate) fn parse_hcl(text: &str) -> Vec<ExtractedPair> {
    let mut pairs = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut index = 0;
    let mut in_block_comment = false;
    while index < lines.len() {
        let line = lines[index];
        let code_line = strip_hcl_comments(line, &mut in_block_comment);
        let trimmed = code_line.trim_start();
        if let Some(var_name) = parse_variable_header(trimmed) {
            let (header_opens, header_closes) = brace_delta_outside_strings_and_comments(trimmed);
            let mut depth = header_opens.saturating_sub(header_closes);
            let mut consumed = 1usize;
            let mut default_composite_depth: Option<usize> = None;
            if let Some(HclValue::Scalar(value)) = parse_hcl_default_in_fragment(trimmed) {
                if !value.is_empty() {
                    pairs.push(ExtractedPair {
                        context: var_name.clone(),
                        value,
                        line: index + 1,
                    });
                }
            }
            if depth == 0 {
                index += consumed;
                continue;
            }
            let mut offset = 1usize;
            let mut structural_lines = 0usize;
            while structural_lines < MAX_VARIABLE_BLOCK_LINES && index + offset < lines.len() {
                let line_index = index + offset;
                let inner = lines[line_index];
                let inner_code = strip_hcl_comments(inner, &mut in_block_comment);
                let body = inner_code.trim();
                consumed = offset + 1;

                if let Some(value) = parse_hcl_default(body) {
                    match value {
                        HclValue::Scalar(value) => {
                            if !value.is_empty() {
                                pairs.push(ExtractedPair {
                                    context: var_name.clone(),
                                    value,
                                    line: line_index + 1,
                                });
                            }
                        }
                        HclValue::HeredocStart(marker) => {
                            if let Some((value, next_index)) =
                                collect_heredoc(&lines, line_index + 1, &marker)
                            {
                                if !value.is_empty() {
                                    pairs.push(ExtractedPair {
                                        context: var_name.clone(),
                                        value,
                                        line: line_index + 2,
                                    });
                                }
                                consumed = next_index.saturating_sub(index);
                                offset = next_index.saturating_sub(index);
                                continue;
                            }
                        }
                        HclValue::CompositeStart => {
                            default_composite_depth = Some(0);
                        }
                    }
                } else if default_composite_depth.is_some() {
                    if let Some((name, value)) = parse_hcl_assignment(body) {
                        match value {
                            HclValue::Scalar(value) => {
                                if !name.is_empty() && !value.is_empty() {
                                    pairs.push(ExtractedPair {
                                        context: format!("{var_name}.{name}"),
                                        value,
                                        line: line_index + 1,
                                    });
                                }
                            }
                            HclValue::HeredocStart(marker) => {
                                if let Some((value, next_index)) =
                                    collect_heredoc(&lines, line_index + 1, &marker)
                                {
                                    if !name.is_empty() && !value.is_empty() {
                                        pairs.push(ExtractedPair {
                                            context: format!("{var_name}.{name}"),
                                            value,
                                            line: line_index + 2,
                                        });
                                    }
                                    consumed = next_index.saturating_sub(index);
                                    offset = next_index.saturating_sub(index);
                                    continue;
                                }
                            }
                            HclValue::CompositeStart => {}
                        }
                    }
                }

                let (opens, closes) = brace_delta_outside_strings_and_comments(body);
                if let Some(composite_depth) = default_composite_depth.as_mut() {
                    *composite_depth = composite_depth.saturating_add(opens);
                    *composite_depth = composite_depth.saturating_sub(closes);
                    if *composite_depth == 0 {
                        default_composite_depth = None;
                    }
                }
                depth = depth.saturating_add(opens);
                depth = depth.saturating_sub(closes);
                if depth == 0 {
                    break;
                }
                structural_lines += 1;
                offset += 1;
            }
            index += consumed;
            continue;
        }
        if let Some((name, value)) = parse_hcl_assignment(trimmed) {
            match value {
                HclValue::Scalar(value) => {
                    if !name.is_empty() && !value.is_empty() {
                        pairs.push(ExtractedPair {
                            context: name,
                            value,
                            line: index + 1,
                        });
                    }
                }
                HclValue::HeredocStart(marker) => {
                    if let Some((value, next_index)) = collect_heredoc(&lines, index + 1, &marker) {
                        if !name.is_empty() && !value.is_empty() {
                            pairs.push(ExtractedPair {
                                context: name,
                                value,
                                line: index + 2,
                            });
                        }
                        index = next_index;
                        continue;
                    }
                }
                HclValue::CompositeStart => {}
            }
        }
        index += 1;
    }
    pairs
}

/// Real terraform blocks are short; cap the lookahead so malformed files do not
/// run into the next block indefinitely.
const MAX_VARIABLE_BLOCK_LINES: usize = 16;
const MAX_HEREDOC_LINES: usize = 512;

enum HclValue {
    Scalar(String),
    HeredocStart(String),
    CompositeStart,
}

fn collect_heredoc(lines: &[&str], content_start: usize, marker: &str) -> Option<(String, usize)> {
    let mut value = String::new();
    let end = lines.len().min(content_start + MAX_HEREDOC_LINES);
    for cursor in content_start..end {
        if lines[cursor].trim() == marker {
            return Some((value, cursor + 1));
        }
        if !value.is_empty() {
            value.push('\n');
        }
        value.push_str(lines[cursor]);
    }
    None
}

/// True when `s` is a non-empty HCL identifier: every character is ASCII
/// alphanumeric, `_`, or `-`. One owner for the char-class shared by variable
/// names, assignment LHS keys, and heredoc markers — so the three call sites
/// can never drift on what counts as a valid identifier.
fn is_hcl_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn parse_variable_header(line: &str) -> Option<String> {
    let rest = line.strip_prefix("variable")?;
    if !rest.starts_with(|c: char| c.is_ascii_whitespace()) {
        return None;
    }
    let rest = rest.trim_start();
    let name = if let Some(quoted) = rest.strip_prefix('"') {
        let end = find_unescaped_quote(quoted, b'"')?;
        &quoted[..end]
    } else {
        rest.split(|c: char| c.is_ascii_whitespace() || c == '{')
            .next()?
    };
    if !is_hcl_identifier(name) {
        return None;
    }
    Some(name.to_string())
}

fn parse_hcl_default(line: &str) -> Option<HclValue> {
    let stripped = strip_hcl_line_comment(line);
    let trimmed = stripped.trim_start();
    let rest = trimmed.strip_prefix("default")?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    parse_hcl_value(rest)
}

fn parse_hcl_default_in_fragment(fragment: &str) -> Option<HclValue> {
    let mut search_start = 0usize;
    while search_start < fragment.len() {
        let pos = search_start + fragment[search_start..].find("default")?;
        let before_ok = pos == 0
            || fragment[..pos]
                .chars()
                .last()
                .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '-');
        let after = &fragment[pos + "default".len()..];
        let after_ok = after
            .chars()
            .next()
            .is_some_and(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '-');
        if before_ok && after_ok {
            if let Some(value) = parse_hcl_default(&fragment[pos..]) {
                return Some(value);
            }
        }
        search_start = pos + "default".len();
    }
    None
}

fn parse_hcl_assignment(line: &str) -> Option<(String, HclValue)> {
    let stripped = strip_hcl_line_comment(line);
    let line = stripped.trim();
    if line.starts_with('#') || line.starts_with("//") || !line.contains('=') {
        return None;
    }
    if let Some((name_part, value_part)) = line.split_once('=') {
        let name = name_part.trim();
        if !is_hcl_identifier(name) {
            return None;
        }
        let value = parse_hcl_value(value_part.trim_start())?;
        return Some((name.to_string(), value));
    }
    None
}

fn parse_hcl_value(s: &str) -> Option<HclValue> {
    if let Some(value) = extract_quoted_value(s) {
        return Some(HclValue::Scalar(value));
    }
    if let Some(marker) = parse_heredoc_marker(s) {
        return Some(HclValue::HeredocStart(marker));
    }
    let trimmed = s.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return Some(HclValue::CompositeStart);
    }
    None
}

fn parse_heredoc_marker(s: &str) -> Option<String> {
    let rest = s.trim_start().strip_prefix("<<")?;
    let rest = match rest.strip_prefix('-') {
        Some(trimmed) => trimmed,
        None => rest,
    }
    .trim_start();
    let marker = rest
        .split(|c: char| c.is_ascii_whitespace())
        .next()?
        .trim_matches('"')
        .trim_matches('\'');
    if !is_hcl_identifier(marker) {
        return None;
    }
    Some(marker.to_string())
}

/// Strip `#` / `//` line comments AND inline `/* … */` block comments from a
/// SINGLE HCL line, returning the code with every comment span removed.
///
/// This is a thin single-line driver over the ONE comment-stripping owner
/// (`strip_hcl_comments`), invoked with a throwaway block-comment flag. Running
/// the shared state machine is what makes an inline block comment that opens AND
/// closes on the same line parse correctly: `a = 1 /* note */ b = 2` yields
/// `a = 1  b = 2`, preserving `b = 2`.
///
/// The previous hand-rolled body duplicated the `#`/`//`/quote logic but DIVERGED
/// on `/*`: it returned `&line[..index]`, truncating the whole line at the block
/// comment's open and silently dropping every assignment after it. Two comment
/// parsers that disagree on one token is a ONE-PLACE violation and a latent
/// recall bug (it was masked only because every current caller happens to receive
/// input already stripped by `strip_hcl_comments` upstream — a future raw-input
/// caller would have lost data). Routing through the single owner removes the
/// divergence outright: there is now exactly one HCL comment grammar.
///
/// Returns `String` (not `&str`) because correct inline-block stripping deletes
/// interior bytes, which no single sub-slice of the input can express.
///
/// `pub(crate)` (like [`parse_hcl`]) so `structured_hcl_parser_contract.rs` can
/// drive it directly through its `include!` of this source and lock that it never
/// re-diverges from [`strip_hcl_comments`].
pub(crate) fn strip_hcl_line_comment(line: &str) -> String {
    let mut in_block_comment = false;
    strip_hcl_comments(line, &mut in_block_comment)
}

/// The ONE HCL comment-stripping owner: removes `#` / `//` line comments and
/// `/* … */` block comments (tracking block state across lines via
/// `in_block_comment`), quote-aware so comment tokens inside strings are kept.
/// `pub(crate)` so the parser-contract test can differentially lock the
/// single-line driver [`strip_hcl_line_comment`] against it.
pub(crate) fn strip_hcl_comments(line: &str, in_block_comment: &mut bool) -> String {
    let bytes = line.as_bytes();
    let mut out = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut segment_start = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        if *in_block_comment {
            if bytes.get(index) == Some(&b'*') && bytes.get(index + 1) == Some(&b'/') {
                *in_block_comment = false;
                index += 2;
                segment_start = index;
            } else {
                index += 1;
            }
            continue;
        }

        let byte = bytes[index];
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active_quote {
                quote = None;
            }
            index += 1;
            continue;
        }

        match byte {
            b'"' | b'\'' | b'`' => quote = Some(byte),
            b'#' => {
                out.push_str(&line[segment_start..index]);
                return out;
            }
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                out.push_str(&line[segment_start..index]);
                return out;
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                out.push_str(&line[segment_start..index]);
                *in_block_comment = true;
                index += 2;
                segment_start = index;
                continue;
            }
            _ => {}
        }
        index += 1;
    }
    if !*in_block_comment {
        out.push_str(&line[segment_start..]);
    }
    out
}

fn brace_delta_outside_strings_and_comments(line: &str) -> (usize, usize) {
    let code = strip_hcl_line_comment(line);
    let bytes = code.as_bytes();
    let mut quote = None;
    let mut escaped = false;
    let mut opens = 0usize;
    let mut closes = 0usize;
    for byte in bytes.iter().copied() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active_quote {
                quote = None;
            }
            continue;
        }
        match byte {
            b'"' | b'\'' | b'`' => quote = Some(byte),
            b'{' => opens += 1,
            b'}' => closes += 1,
            _ => {}
        }
    }
    (opens, closes)
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
    let end = find_unescaped_quote(body, quote)?;
    Some(body[..end].to_string())
}

fn find_unescaped_quote(body: &str, quote: u8) -> Option<usize> {
    let bytes = body.as_bytes();
    let mut escaped = false;
    let mut interpolation_depth = 0usize;
    let mut interpolation_quote = None;
    let mut offset = 0usize;
    while offset < bytes.len() {
        let byte = bytes[offset];
        if escaped {
            escaped = false;
            offset += 1;
            continue;
        }
        if byte == b'\\' {
            escaped = true;
            offset += 1;
            continue;
        }
        if let Some(active_quote) = interpolation_quote {
            if byte == active_quote {
                interpolation_quote = None;
            }
            offset += 1;
            continue;
        }
        if interpolation_depth > 0 {
            match byte {
                b'"' | b'\'' => interpolation_quote = Some(byte),
                b'{' => interpolation_depth += 1,
                b'}' => interpolation_depth = interpolation_depth.saturating_sub(1),
                _ => {}
            }
            offset += 1;
            continue;
        }
        if byte == b'$' && bytes.get(offset + 1) == Some(&b'{') {
            interpolation_depth = 1;
            offset += 2;
            continue;
        }
        if byte == quote {
            return Some(offset);
        }
        offset += 1;
    }
    None
}
