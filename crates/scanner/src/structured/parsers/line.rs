pub(super) fn find_line_number(text: &str, needle: &str) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let pos = text.find(needle)?;
    let line = text[..pos].chars().filter(|&c| c == '\n').count() + 1;
    Some(line)
}
