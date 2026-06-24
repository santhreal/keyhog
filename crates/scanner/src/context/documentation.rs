use super::inference::has_assignment_operator;

const DOCSTRING_TOGGLE_REMAINDER: usize = 2;
const DOCSTRING_TOGGLE_MATCH: usize = 1;

/// Mark lines that appear to be documentation or docstrings.
pub(crate) fn documentation_line_flags(lines: &[&str]) -> Vec<bool> {
    let mut flags = vec![false; lines.len()];
    let mut in_markdown_code_block = false;
    let mut in_docstring = false;

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let is_fence = trimmed.starts_with("```");
        let docstring_segment = before_line_comment(trimmed);
        let triple_count = docstring_delimiter_count(docstring_segment);
        let self_contained_docstring = !in_docstring
            && triple_count >= DOCSTRING_TOGGLE_REMAINDER
            && triple_count % DOCSTRING_TOGGLE_REMAINDER == 0
            && opens_docstring(docstring_segment);
        if is_fence || in_markdown_code_block || in_docstring || self_contained_docstring {
            flags[idx] = true;
        }

        if is_fence {
            in_markdown_code_block = !in_markdown_code_block;
        }
        if triple_count % DOCSTRING_TOGGLE_REMAINDER == DOCSTRING_TOGGLE_MATCH {
            if in_docstring {
                if closes_docstring(docstring_segment) {
                    in_docstring = false;
                }
            } else {
                in_docstring = opens_docstring(docstring_segment);
            }
        }
    }

    flags
}

fn docstring_delimiter_count(segment: &str) -> usize {
    segment.matches("\"\"\"").count() + segment.matches("'''").count()
}

fn before_line_comment(trimmed: &str) -> &str {
    let bytes = trimmed.as_bytes();
    let mut regular_quote = None;
    let mut escaped = false;
    let mut idx = 0;

    while idx < bytes.len() {
        let byte = bytes[idx];
        if escaped {
            escaped = false;
            idx += 1;
            continue;
        }
        if regular_quote.is_some() && byte == b'\\' {
            escaped = true;
            idx += 1;
            continue;
        }
        if let Some(quote) = regular_quote {
            if byte == quote {
                regular_quote = None;
            }
            idx += 1;
            continue;
        }
        if is_triple_quote_at(bytes, idx) {
            idx += 3;
            continue;
        }
        if byte == b'/' && bytes.get(idx + 1).copied() == Some(b'/') {
            return &trimmed[..idx];
        }
        if byte == b'"' || byte == b'\'' {
            regular_quote = Some(byte);
        }
        idx += 1;
    }

    trimmed
}

fn is_triple_quote_at(bytes: &[u8], idx: usize) -> bool {
    let Some([first, second, third]) = bytes.get(idx..idx + 3) else {
        return false;
    };
    (first == second && second == third) && (*first == b'"' || *first == b'\'')
}

/// Decide whether an odd triple-quote on this line genuinely OPENS a multi-line
/// docstring, versus being incidental `"""`/`'''` noise that must not flip the
/// rest of the chunk into documentation mode.
///
/// A real docstring/multiline-string opener sits at a string-OPENING position:
///   1. it is not preceded by an assignment operator (`x = """data` is runtime
///      string data, classified as code — preserves the existing contract); and
///   2. the bytes before the triple-quote are not themselves inside an
///      unterminated regular quote.
///
/// A single `"""` buried in quote noise — e.g. `key " : """ : ' ": "  SECRET`
/// in a randomized config dump or a log line — is NOT a docstring opener. The
/// old `count % 2` heuristic toggled on it and then silently suppressed every
/// credential below it (a 0.3x multiplier + hard-suppress). Failing to open
/// here can only REDUCE suppression, so it preserves recall and never adds a
/// false suppression: a genuine opener with unbalanced regular quotes before
/// its delimiter would be a Python syntax error and does not occur in practice.
fn opens_docstring(trimmed: &str) -> bool {
    let Some(pos) = first_docstring_delimiter(trimmed) else {
        return false;
    };
    let before = &trimmed[..pos];
    if has_assignment_operator(before) {
        return false;
    }
    has_balanced_regular_quotes(before)
}

fn closes_docstring(trimmed: &str) -> bool {
    let Some(pos) = first_docstring_delimiter(trimmed) else {
        return false;
    };
    !has_assignment_operator(&trimmed[..pos])
}

fn first_docstring_delimiter(trimmed: &str) -> Option<usize> {
    trimmed.find("\"\"\"").or_else(|| trimmed.find("'''"))
}

/// True when `segment` holds an even number of each regular quote, i.e. scanning
/// it leaves us OUTSIDE any `"…"`/`'…'` string — the only position from which a
/// following triple-quote can open a docstring.
fn has_balanced_regular_quotes(segment: &str) -> bool {
    let double = segment.bytes().filter(|&b| b == b'"').count();
    let single = segment.bytes().filter(|&b| b == b'\'').count();
    double % 2 == 0 && single % 2 == 0
}
