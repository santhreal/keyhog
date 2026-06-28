use aho_corasick::AhoCorasick;
use std::collections::HashMap;

use super::ExtractedPair;

pub(super) enum LineAnchor {
    Value,
    Owned(String),
}

pub(super) struct PendingExtractedPair {
    context: String,
    value: String,
    line_anchor: LineAnchor,
    fallback_anchor: Option<LineAnchor>,
}

impl PendingExtractedPair {
    pub(super) fn value_anchor(context: impl Into<String>, value: String) -> Self {
        Self {
            context: context.into(),
            value,
            line_anchor: LineAnchor::Value,
            fallback_anchor: None,
        }
    }

    pub(super) fn owned_anchor(
        context: impl Into<String>,
        value: String,
        line_anchor: String,
    ) -> Self {
        Self {
            context: context.into(),
            value,
            line_anchor: LineAnchor::Owned(line_anchor),
            fallback_anchor: None,
        }
    }

    pub(super) fn owned_anchor_with_fallback(
        context: impl Into<String>,
        value: String,
        line_anchor: String,
        fallback_anchor: String,
    ) -> Self {
        Self {
            context: context.into(),
            value,
            line_anchor: LineAnchor::Owned(line_anchor),
            fallback_anchor: Some(LineAnchor::Owned(fallback_anchor)),
        }
    }

    fn line_anchor(&self) -> &str {
        anchor_value(&self.line_anchor, &self.value)
    }

    fn fallback_anchor(&self) -> Option<&str> {
        self.fallback_anchor
            .as_ref()
            .map(|anchor| anchor_value(anchor, &self.value))
    }
}

fn anchor_value<'a>(anchor: &'a LineAnchor, value: &'a str) -> &'a str {
    match anchor {
        LineAnchor::Value => value,
        LineAnchor::Owned(anchor) => anchor,
    }
}

pub(super) fn resolve_line_number_options(text: &str, needles: &[&str]) -> Vec<Option<usize>> {
    let mut lines = vec![None; needles.len()];
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

    let line_starts = crate::compute_line_offsets(text);
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
            lines[*slot] = Some(line);
        }
        if remaining == 0 {
            break;
        }
    }

    lines
}

pub(super) fn finalize_pending_pairs(
    text: &str,
    pending: Vec<PendingExtractedPair>,
) -> Vec<ExtractedPair> {
    let mut anchors = Vec::with_capacity(pending.len() * 2);
    let mut anchor_slots = Vec::with_capacity(pending.len());
    for pending_pair in &pending {
        let primary_slot = anchors.len();
        anchors.push(pending_pair.line_anchor());
        let fallback_slot = match pending_pair.fallback_anchor() {
            Some(anchor) => {
                let slot = anchors.len();
                anchors.push(anchor);
                Some(slot)
            }
            None => None,
        };
        anchor_slots.push((primary_slot, fallback_slot));
    }

    let lines = resolve_line_number_options(text, &anchors);
    let mut pairs = Vec::with_capacity(pending.len());
    for (pending_pair, (primary_slot, fallback_slot)) in pending.into_iter().zip(anchor_slots) {
        let line = lines
            .get(primary_slot)
            .and_then(|line| *line)
            .or_else(|| fallback_slot.and_then(|slot| lines.get(slot).and_then(|line| *line)))
            .unwrap_or(1); // LAW10: line anchor not located => placeholder line for REPORTING only; extracted value is still emitted, recall-safe
        pairs.push(ExtractedPair {
            context: pending_pair.context,
            value: pending_pair.value,
            line,
        });
    }
    pairs
}

fn line_number_for_offset(line_starts: &[usize], offset: usize) -> usize {
    line_starts.partition_point(|&start| start <= offset)
}
