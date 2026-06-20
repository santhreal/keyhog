//! Line slicing and source-coordinate recovery for generic assignment findings.

pub(super) fn source_offset_for_line_value(
    source: &str,
    one_based_line: usize,
    value: &str,
) -> usize {
    let mut line_start = 0usize;
    for (line_idx, line) in source.split('\n').enumerate() {
        if line_idx + 1 == one_based_line {
            return line
                .find(value)
                .map_or(line_start, |column| line_start + column);
        }
        line_start += line.len() + 1;
    }
    source.len()
}

pub(super) fn line_at_index<'a>(
    text: &'a str,
    line_offsets: &[usize],
    line_idx: usize,
) -> Option<&'a str> {
    let start = *line_offsets.get(line_idx)?;
    let mut end = if let Some(next_line_start) = line_offsets.get(line_idx + 1) {
        *next_line_start
    } else {
        // Last line has no following offset; the source length is its exact end.
        text.len()
    };
    let bytes = text.as_bytes();
    if end > start && bytes.get(end - 1).copied() == Some(b'\n') {
        end -= 1;
    }
    if end > start && bytes.get(end - 1).copied() == Some(b'\r') {
        end -= 1;
    }
    text.get(start..end)
}
