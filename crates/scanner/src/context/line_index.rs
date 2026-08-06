use super::documentation::DocumentationClassifier;

const DOCUMENTATION_WORD_BITS: usize = u64::BITS as usize;
const MAX_CONTEXT_WINDOW_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LineIndexOverflow;

/// Compact line starts and documentation classification for one preprocessed chunk.
pub(crate) struct LineContextIndex {
    starts: Box<[u32]>,
    line_count: u32,
    documentation: Box<[u64]>,
}

impl LineContextIndex {
    pub(crate) fn try_new(text: &str) -> Result<Self, LineIndexOverflow> {
        checked_text_len(text.len())?;
        let estimated_lines = text.len() / 40 + 1;
        let mut starts = Vec::with_capacity(estimated_lines);
        starts.push(0);
        for newline in memchr::memchr_iter(b'\n', text.as_bytes()) {
            starts.push(u32::try_from(newline + 1).map_err(|_| LineIndexOverflow)?);
        }

        let mut documentation = vec![0u64; starts.len().div_ceil(DOCUMENTATION_WORD_BITS)];
        let mut classifier = DocumentationClassifier::new();
        for line_idx in 0..visible_line_count(text, &starts) {
            let line = line_from_starts(text, &starts, line_idx)
                .expect("line starts built from the same text must remain in bounds");
            if classifier.classify(line) {
                documentation[line_idx / DOCUMENTATION_WORD_BITS] |=
                    1u64 << (line_idx % DOCUMENTATION_WORD_BITS);
            }
        }

        let line_count =
            u32::try_from(visible_line_count(text, &starts)).map_err(|_| LineIndexOverflow)?;
        Ok(Self {
            starts: starts.into_boxed_slice(),
            documentation: documentation.into_boxed_slice(),
            line_count,
        })
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.starts.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.line_count == 0
    }

    pub(crate) fn line_count(&self) -> usize {
        self.line_count as usize
    }

    pub(crate) fn line_start(&self, line_idx: usize) -> Option<usize> {
        self.starts.get(line_idx).map(|&offset| offset as usize)
    }

    pub(crate) fn line<'a>(&self, text: &'a str, line_idx: usize) -> Option<&'a str> {
        line_from_starts(text, &self.starts, line_idx)
    }

    pub(crate) fn lines<'text>(&self, text: &'text str) -> LineIter<'_, 'text> {
        LineIter {
            index: self,
            text,
            next: 0,
            end: self.line_count(),
        }
    }
    pub(crate) fn view<'a>(&'a self, text: &'a str) -> IndexedLines<'a> {
        IndexedLines { index: self, text }
    }

    /// Return the 1-based line number containing `offset`.
    pub(crate) fn line_number_for_offset(&self, offset: usize) -> usize {
        self.starts
            .partition_point(|&start| start as usize <= offset)
    }

    pub(crate) fn line_index_for_offset(&self, offset: usize) -> usize {
        self.line_number_for_offset(offset).saturating_sub(1)
    }

    pub(crate) fn is_documentation(&self, line_idx: usize) -> bool {
        self.documentation
            .get(line_idx / DOCUMENTATION_WORD_BITS)
            .is_some_and(|word| word & (1u64 << (line_idx % DOCUMENTATION_WORD_BITS)) != 0)
    }

    /// Borrow a bounded `[line - radius, line + radius]` window without allocation.
    pub(crate) fn context_window<'a>(&self, text: &'a str, line: usize, radius: usize) -> &'a str {
        let start_line = line.saturating_sub(radius).saturating_sub(1);
        let Some(start) = self.line_start(start_line) else {
            return "";
        };
        if start > text.len() {
            return "";
        }
        let window_lines = radius.saturating_mul(2).saturating_add(1);
        let end_line = start_line.saturating_add(window_lines);
        let uncapped_end = self
            .line_start(end_line)
            .map_or(text.len(), |next| next.saturating_sub(1));
        let mut end = uncapped_end
            .min(start.saturating_add(MAX_CONTEXT_WINDOW_BYTES))
            .min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        &text[start..end]
    }

    #[cfg(test)]
    pub(crate) fn storage_bytes(&self) -> usize {
        self.starts.len() * std::mem::size_of::<u32>()
            + self.documentation.len() * std::mem::size_of::<u64>()
            + std::mem::size_of::<u32>()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct IndexedLines<'a> {
    index: &'a LineContextIndex,
    text: &'a str,
}

pub(crate) trait LineSource {
    fn line_count(&self) -> usize;
    fn line_at(&self, line_idx: usize) -> Option<&str>;
}

impl LineSource for IndexedLines<'_> {
    fn line_count(&self) -> usize {
        self.index.line_count()
    }

    fn line_at(&self, line_idx: usize) -> Option<&str> {
        self.index.line(self.text, line_idx)
    }
}

impl LineSource for [&str] {
    fn line_count(&self) -> usize {
        self.len()
    }

    fn line_at(&self, line_idx: usize) -> Option<&str> {
        self.get(line_idx).copied()
    }
}

pub(crate) struct LineIter<'index, 'text> {
    index: &'index LineContextIndex,
    text: &'text str,
    next: usize,
    end: usize,
}

impl<'text> Iterator for LineIter<'_, 'text> {
    type Item = &'text str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.end {
            return None;
        }
        let line = self.index.line(self.text, self.next);
        self.next += 1;
        line
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.end - self.next;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for LineIter<'_, '_> {}

fn checked_text_len(len: usize) -> Result<(), LineIndexOverflow> {
    u32::try_from(len)
        .map(|_| ())
        .map_err(|_| LineIndexOverflow)
}

fn visible_line_count(text: &str, starts: &[u32]) -> usize {
    if text.is_empty() {
        0
    } else if starts
        .last()
        .is_some_and(|&start| start as usize == text.len())
    {
        starts.len() - 1
    } else {
        starts.len()
    }
}

fn line_from_starts<'a>(text: &'a str, starts: &[u32], line_idx: usize) -> Option<&'a str> {
    let start = *starts.get(line_idx)? as usize;
    if start >= text.len() {
        return None;
    }
    let has_next = line_idx + 1 < starts.len();
    let end = if has_next {
        (starts[line_idx + 1] as usize).saturating_sub(1)
    } else {
        text.len()
    };
    let mut line = text.get(start..end)?;
    if has_next && line.as_bytes().last() == Some(&b'\r') {
        line = &line[..line.len() - 1];
    }
    Some(line)
}

#[cfg(test)]
#[path = "../../tests/unit/context_line_index.rs"]
mod tests;
