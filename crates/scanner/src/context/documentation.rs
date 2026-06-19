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
        let triple_count = trimmed.matches("\"\"\"").count() + trimmed.matches("'''").count();
        if is_fence || in_markdown_code_block || in_docstring {
            flags[idx] = true;
        }

        if is_fence {
            in_markdown_code_block = !in_markdown_code_block;
        }
        if triple_count % DOCSTRING_TOGGLE_REMAINDER == DOCSTRING_TOGGLE_MATCH {
            if in_docstring {
                in_docstring = false;
            } else {
                in_docstring = opens_docstring(trimmed);
            }
        }
    }

    flags
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
    let Some(pos) = trimmed.find("\"\"\"").or_else(|| trimmed.find("'''")) else {
        return false;
    };
    let before = &trimmed[..pos];
    if has_assignment_operator(before) {
        return false;
    }
    has_balanced_regular_quotes(before)
}

/// True when `segment` holds an even number of each regular quote, i.e. scanning
/// it leaves us OUTSIDE any `"…"`/`'…'` string — the only position from which a
/// following triple-quote can open a docstring.
fn has_balanced_regular_quotes(segment: &str) -> bool {
    let double = segment.bytes().filter(|&b| b == b'"').count();
    let single = segment.bytes().filter(|&b| b == b'\'').count();
    double % 2 == 0 && single % 2 == 0
}
