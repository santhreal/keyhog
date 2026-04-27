//! Inline suppression handling for CLI findings.

use keyhog_core::RawMatch;
use std::collections::HashMap;

const INLINE_SUPPRESSION_DIRECTIVE: &str = "keyhog:ignore";
const DETECTOR_DIRECTIVE_PREFIX: &str = "detector=";
const INLINE_COMMENT_MARKERS: &[&str] = &["//", "#", "--", "/*", "<!--"];

pub fn filter_inline_suppressions(matches: Vec<RawMatch>) -> Vec<RawMatch> {
    use std::io::BufRead;

    let mut files_to_matches: HashMap<String, Vec<RawMatch>> = HashMap::new();
    let mut non_file_matches = Vec::new();

    for m in matches {
        if m.location.source.as_ref() == "filesystem" {
            if let Some(path) = m.location.file_path.clone() {
                files_to_matches
                    .entry(path.to_string())
                    .or_default()
                    .push(m);
                continue;
            }
        }
        non_file_matches.push(m);
    }

    let mut filtered_matches = non_file_matches;
    for (path, mut file_matches) in files_to_matches {
        file_matches.sort_by_key(|m| m.location.line.unwrap_or(0));

        if let Ok(file) = std::fs::File::open(&path) {
            let reader = std::io::BufReader::new(file);
            let mut lines = reader.lines();
            let mut current_line_num = 1;
            let mut prev_line = String::new();
            let mut current_line = String::new();

            for m in file_matches {
                let Some(target_line) = m.location.line else {
                    filtered_matches.push(m);
                    continue;
                };

                while current_line_num <= target_line {
                    if let Some(Ok(line)) = lines.next() {
                        prev_line = std::mem::replace(&mut current_line, line);
                        current_line_num += 1;
                    } else {
                        break;
                    }
                }

                if !is_inline_suppressed_buffered(&prev_line, &current_line, &m.detector_id) {
                    filtered_matches.push(m);
                }
            }
        } else {
            filtered_matches.extend(file_matches);
        }
    }

    filtered_matches
}

fn is_inline_suppressed_buffered(prev_line: &str, current_line: &str, detector_id: &str) -> bool {
    line_has_inline_suppression(prev_line, detector_id)
        || line_has_inline_suppression(current_line, detector_id)
}

fn line_has_inline_suppression(line: &str, detector_id: &str) -> bool {
    let Some(directive) = inline_suppression_directive(line) else {
        return false;
    };
    let detector = detector_id.to_ascii_lowercase();
    match directive
        .split(|ch: char| ch.is_whitespace() || matches!(ch, ',' | ';'))
        .find_map(|token| token.strip_prefix(DETECTOR_DIRECTIVE_PREFIX))
    {
        Some(expected) => expected == detector,
        None => true,
    }
}

fn inline_suppression_directive(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let directive = comment_segments(&lower).find_map(extract_directive_from_comment);
    directive
}

fn comment_segments(line: &str) -> impl Iterator<Item = &str> {
    INLINE_COMMENT_MARKERS
        .iter()
        .filter_map(|marker| line.find(marker).map(|index| &line[index + marker.len()..]))
}

fn extract_directive_from_comment(comment: &str) -> Option<String> {
    let directive_index = comment.find(INLINE_SUPPRESSION_DIRECTIVE)?;
    if comment[..directive_index]
        .chars()
        .any(|character| !character.is_whitespace())
    {
        return None;
    }
    let directive = &comment[directive_index..];
    let token_end = directive
        .find(char::is_whitespace)
        .map_or(directive.len(), |index| index);
    if &directive[..token_end] != INLINE_SUPPRESSION_DIRECTIVE {
        return None;
    }
    Some(directive.to_string())
}
