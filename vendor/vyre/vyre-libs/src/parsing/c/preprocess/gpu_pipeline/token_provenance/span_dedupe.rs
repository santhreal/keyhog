use super::*;
use std::hash::Hash;

const INLINE_SPANS: usize = 8;

pub(crate) struct SpanDedupe<T>
where
    T: Copy + Eq + Hash,
{
    inline: SmallVec<[(T, T); 8]>,
    overflow: Option<HashSet<(T, T)>>,
}

impl<T> SpanDedupe<T>
where
    T: Copy + Eq + Hash,
{
    pub(crate) fn from_iter(spans: impl IntoIterator<Item = (T, T)>) -> Self {
        let mut dedupe = Self {
            inline: SmallVec::new(),
            overflow: None,
        };
        for span in spans {
            dedupe.insert(span);
        }
        dedupe
    }

    pub(crate) fn insert(&mut self, span: (T, T)) -> bool {
        if let Some(overflow) = &mut self.overflow {
            return overflow.insert(span);
        }
        if self.inline.contains(&span) {
            return false;
        }
        if self.inline.len() < INLINE_SPANS {
            self.inline.push(span);
            return true;
        }
        let mut overflow = HashSet::default();
        overflow.reserve(self.inline.len() * 2);
        overflow.extend(self.inline.iter().copied());
        let inserted = overflow.insert(span);
        self.overflow = Some(overflow);
        inserted
    }
}
