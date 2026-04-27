use rustc_hash::FxHashMap;

/// Default maximum number of live nodes retained by an [`IntrusiveLru`].
pub const DEFAULT_INTRUSIVE_LRU_CAPACITY: usize = 65_536;

/// Intrusive doubly-linked LRU over a slab allocator.
///
/// O(1) record, remove, and hottest/coldest iteration.
pub struct IntrusiveLru<K, V> {
    nodes: Vec<Node<K, V>>,
    indices: FxHashMap<K, usize>,
    free: Vec<usize>,
    head: Option<usize>,
    tail: Option<usize>,
    capacity: usize,
}

struct Node<K, V> {
    key: K,
    value: V,
    prev: Option<usize>,
    next: Option<usize>,
    active: bool,
}

impl<K, V> IntrusiveLru<K, V>
where
    K: std::hash::Hash + Eq + Copy,
    V: Default,
{
    /// Create an LRU with the default live-node capacity.
    #[inline]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_INTRUSIVE_LRU_CAPACITY)
    }

    /// Create an LRU with a fixed live-node capacity.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        // Defensive: a capacity of 0 would make the LRU unusable; clamp to 1
        // so callers that compute capacity from external config never panic.
        let capacity = capacity.max(1);
        Self {
            nodes: Vec::with_capacity(capacity.min(1024)),
            indices: FxHashMap::default(),
            free: Vec::new(),
            head: None,
            tail: None,
            capacity,
        }
    }

    /// Ensure a node exists for `key` and return a mutable value reference.
    #[inline]
    pub fn ensure(&mut self, key: K) -> &mut V {
        if let Some(&index) = self.indices.get(&key) {
            return &mut self.nodes[index].value;
        }
        let index = self.alloc_node(key);
        &mut self.nodes[index].value
    }

    /// Move `key` to the front if it is present.
    #[inline]
    pub fn touch(&mut self, key: K) {
        if let Some(&index) = self.indices.get(&key) {
            self.move_to_front(index);
        }
    }

    /// Remove a key if it is present.
    #[inline]
    pub fn remove(&mut self, key: &K) {
        let Some(index) = self.indices.remove(key) else {
            return;
        };
        self.detach(index);
        let node = &mut self.nodes[index];
        node.active = false;
        self.free.push(index);
    }

    /// Return the value for `key` if it is currently active.
    #[inline]
    pub fn get(&self, key: &K) -> Option<&V> {
        let &index = self.indices.get(key)?;
        let node = &self.nodes[index];
        node.active.then_some(&node.value)
    }

    /// Return the `n` hottest keys in most-recent-first order.
    #[inline]
    pub fn hottest(&self, n: usize) -> Vec<K> {
        self.iter_hottest().map(|(key, _)| *key).take(n).collect()
    }

    /// Iterate entries from most recent to least recent.
    #[inline]
    pub fn iter_hottest(&self) -> impl Iterator<Item = (&K, &V)> + '_ {
        let mut current = self.head;
        std::iter::from_fn(move || {
            let index = current?;
            let node = &self.nodes[index];
            current = node.next;
            Some((&node.key, &node.value))
        })
    }

    /// Iterate entries from least recent to most recent.
    #[inline]
    pub fn iter_coldest(&self) -> impl Iterator<Item = (&K, &V)> + '_ {
        let mut current = self.tail;
        std::iter::from_fn(move || {
            let index = current?;
            let node = &self.nodes[index];
            current = node.prev;
            Some((&node.key, &node.value))
        })
    }

    fn alloc_node(&mut self, key: K) -> usize {
        if self.indices.len() == self.capacity {
            if let Some(coldest) = self.tail {
                let evicted_key = self.nodes[coldest].key;
                self.remove(&evicted_key);
            }
        }
        let index = if let Some(index) = self.free.pop() {
            self.nodes[index] = Node {
                key,
                value: V::default(),
                prev: None,
                next: None,
                active: true,
            };
            index
        } else {
            self.nodes.push(Node {
                key,
                value: V::default(),
                prev: None,
                next: None,
                active: true,
            });
            self.nodes.len() - 1
        };
        self.indices.insert(key, index);
        self.attach_front(index);
        index
    }

    fn move_to_front(&mut self, index: usize) {
        if self.head == Some(index) {
            return;
        }
        self.detach(index);
        self.attach_front(index);
    }

    fn attach_front(&mut self, index: usize) {
        self.nodes[index].prev = None;
        self.nodes[index].next = self.head;
        if let Some(head) = self.head {
            self.nodes[head].prev = Some(index);
        } else {
            self.tail = Some(index);
        }
        self.head = Some(index);
    }

    fn detach(&mut self, index: usize) {
        let prev = self.nodes[index].prev;
        let next = self.nodes[index].next;
        if let Some(prev) = prev {
            self.nodes[prev].next = next;
        } else if self.head == Some(index) {
            self.head = next;
        }
        if let Some(next) = next {
            self.nodes[next].prev = prev;
        } else if self.tail == Some(index) {
            self.tail = prev;
        }
        self.nodes[index].prev = None;
        self.nodes[index].next = None;
    }
}

impl<K, V> Default for IntrusiveLru<K, V>
where
    K: std::hash::Hash + Eq + Copy,
    V: Default,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Metadata attached to each LRU node inside [`AccessTracker`].
#[derive(Debug, Clone, Copy, Default)]
pub struct AccessMeta {
    /// Number of recorded accesses.
    pub frequency: u32,
    /// Entry size in bytes.
    pub size: u64,
    /// Monotonic tick recorded for the last access.
    pub last_access: u64,
}

/// Tracks access patterns for cache entries.
#[non_exhaustive]
pub struct AccessTracker {
    lru: IntrusiveLru<u64, AccessMeta>,
    tick: u64,
}

impl AccessTracker {
    /// Create a new empty tracker.
    #[inline]
    pub fn new() -> Self {
        Self {
            lru: IntrusiveLru::new(),
            tick: 0,
        }
    }

    /// Record an access for the given key.
    #[inline]
    pub fn record(&mut self, key: u64) {
        self.tick = self.tick.saturating_add(1);
        let meta = self.lru.ensure(key);
        meta.frequency = meta.frequency.saturating_add(1);
        meta.last_access = self.tick;
        self.lru.touch(key);
    }

    /// Return the `n` hottest keys in most-recent-first order.
    #[inline]
    pub fn hot_set(&self, n: usize) -> Vec<u64> {
        self.lru.hottest(n)
    }

    #[inline]
    pub(crate) fn set_size(&mut self, key: u64, size: u64) {
        self.lru.ensure(key).size = size;
    }

    #[inline]
    pub(crate) fn remove(&mut self, key: u64) {
        self.lru.remove(&key);
    }

    #[inline]
    pub(crate) fn get_meta(&self, key: u64) -> Option<&AccessMeta> {
        self.lru.get(&key)
    }

    /// Return access statistics for a key.
    #[inline]
    pub fn stats(&self, key: u64) -> Option<crate::runtime::cache::AccessStats> {
        let meta = self.get_meta(key)?;
        // O(1) relative-recency via monotonic tick counter instead of O(N)
        // linear scan through the intrusive list.
        Some(crate::runtime::cache::AccessStats {
            frequency: meta.frequency,
            last_access: meta.last_access,
            size: meta.size,
        })
    }
}

impl Default for AccessTracker {
    fn default() -> Self {
        Self::new()
    }
}
