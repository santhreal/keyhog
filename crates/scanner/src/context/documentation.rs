use super::inference::has_assignment_operator;

const DOCSTRING_TOGGLE_REMAINDER: usize = 2;
const DOCSTRING_TOGGLE_MATCH: usize = 1;

/// Mark lines that appear to be documentation or docstrings.
pub fn documentation_line_flags(lines: &[&str]) -> Vec<bool> {
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
                let is_assignment = trimmed
                    .find("\"\"\"")
                    .or_else(|| trimmed.find("'''"))
                    .is_some_and(|pos| has_assignment_operator(&trimmed[..pos]));
                in_docstring = !is_assignment;
            }
        }
    }

    flags
}
