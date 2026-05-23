//! Heap-backed LRU index shared by GPU preprocessor resident caches.

use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;

#[derive(Debug)]
pub(super) struct LruIndex<K> {
    heap: BinaryHeap<Reverse<LruTouch<K>>>,
    serial: u64,
}

#[derive(Debug)]
struct LruTouch<K> {
    last_access: u64,
    serial: u64,
    key: K,
}

impl<K> PartialEq for LruTouch<K> {
    fn eq(&self, other: &Self) -> bool {
        self.last_access == other.last_access && self.serial == other.serial
    }
}

impl<K> Eq for LruTouch<K> {}

impl<K> Ord for LruTouch<K> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.last_access
            .cmp(&other.last_access)
            .then_with(|| self.serial.cmp(&other.serial))
    }
}

impl<K> PartialOrd for LruTouch<K> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<K> LruIndex<K> {
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            heap: BinaryHeap::with_capacity(capacity),
            serial: 0,
        }
    }

    pub(super) fn record(&mut self, key: K, last_access: u64) {
        let serial = self.next_serial();
        self.heap.push(Reverse(LruTouch {
            last_access,
            serial,
            key,
        }));
    }

    pub(super) fn pop_valid<F>(&mut self, mut is_current: F) -> Option<K>
    where
        F: FnMut(&K, u64) -> bool,
    {
        while let Some(Reverse(touch)) = self.heap.pop() {
            if is_current(&touch.key, touch.last_access) {
                return Some(touch.key);
            }
        }
        None
    }

    pub(super) fn compact_if_needed<I>(&mut self, live_entries: usize, entries: I)
    where
        I: IntoIterator<Item = (K, u64)>,
    {
        if self.heap.len() <= live_entries.saturating_mul(4).max(8) {
            return;
        }
        self.heap.clear();
        self.heap.reserve(live_entries);
        for (key, last_access) in entries {
            self.record(key, last_access);
        }
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.heap.len()
    }

    fn next_serial(&mut self) -> u64 {
        self.serial = self.serial.checked_add(1).unwrap_or_else(|| {
            panic!(
                "vyre-libs gpu preprocessor LRU index serial overflowed. Fix: recreate process-local preprocessor caches before continuing an unbounded translation-unit stream."
            )
        });
        self.serial
    }
}
