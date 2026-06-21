use aho_corasick::AhoCorasick;
use std::collections::HashMap;

pub(super) fn find_line_number(text: &str, needle: &str) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let pos = text.find(needle)?;
    // '\n' (0x0A) is ASCII and never a UTF-8 continuation byte, so counting
    // newline BYTES equals counting newline chars — without decoding UTF-8.
    let line = memchr::memchr_iter(b'\n', &text.as_bytes()[..pos]).count() + 1;
    Some(line)
}

pub(super) fn resolve_line_numbers(text: &str, needles: &[&str]) -> Vec<usize> {
    let mut lines = vec![1; needles.len()];
    if text.is_empty() || needles.is_empty() {
        return lines;
    }

    let mut pattern_ids: HashMap<&str, usize> = HashMap::with_capacity(needles.len());
    let mut patterns: Vec<&str> = Vec::new();
    let mut pattern_slots: Vec<Vec<usize>> = Vec::new();
    for (slot, needle) in needles.iter().copied().enumerate() {
        if needle.is_empty() {
            continue;
        }
        match pattern_ids.get(needle).copied() {
            Some(pattern_id) => pattern_slots[pattern_id].push(slot),
            None => {
                let pattern_id = patterns.len();
                patterns.push(needle);
                pattern_ids.insert(needle, pattern_id);
                pattern_slots.push(vec![slot]);
            }
        }
    }

    if patterns.is_empty() {
        return lines;
    }

    let ac = match AhoCorasick::new(patterns.iter().copied()) {
        Ok(ac) => ac,
        Err(error) => {
            tracing::warn!(
                target: "keyhog::structured",
                %error,
                pattern_count = patterns.len(),
                "structured JSON line locator could not build; extracted pairs retain line 1 attribution"
            );
            return lines;
        }
    };

    let line_starts = build_line_starts(text);
    let mut found = vec![false; patterns.len()];
    let mut remaining = patterns.len();
    for mat in ac.find_overlapping_iter(text) {
        let pattern_id = mat.pattern().as_usize();
        if found[pattern_id] {
            continue;
        }
        found[pattern_id] = true;
        remaining -= 1;
        let line = line_number_for_offset(&line_starts, mat.start());
        for slot in &pattern_slots[pattern_id] {
            lines[*slot] = line;
        }
        if remaining == 0 {
            break;
        }
    }

    lines
}

fn build_line_starts(text: &str) -> Vec<usize> {
    let bytes = text.as_bytes();
    let mut starts = Vec::with_capacity(bytes.len() / 40 + 1);
    starts.push(0);
    for pos in memchr::memchr_iter(b'\n', bytes) {
        starts.push(pos + 1);
    }
    starts
}

fn line_number_for_offset(line_starts: &[usize], offset: usize) -> usize {
    line_starts.partition_point(|&start| start <= offset)
}
