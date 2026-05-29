//! Backend-neutral monotonic ordering helpers for staging hot paths.

/// Return whether an iterator's keys are already nondecreasing.
pub fn iter_is_monotonic_by_key<I, K, F>(items: I, mut key: F) -> bool
where
    I: IntoIterator,
    K: Ord,
    F: FnMut(I::Item) -> K,
{
    let mut previous = None;
    for item in items {
        let current = key(item);
        if let Some(previous) = previous {
            if current < previous {
                return false;
            }
        }
        previous = Some(current);
    }
    true
}

/// Sort only when `items` are not already nondecreasing by `key`.
pub fn sort_by_key_if_needed<T, K, F>(items: &mut [T], mut key: F)
where
    K: Ord,
    F: FnMut(&T) -> K,
{
    let mut previous = None;
    for index in 0..items.len() {
        let current = key(&items[index]);
        if let Some(previous) = previous {
            if current < previous {
                items.sort_by_key(key);
                return;
            }
        }
        previous = Some(current);
    }
}

/// Unstable-sort only when `items` are not already nondecreasing by `key`.
pub fn sort_unstable_by_key_if_needed<T, K, F>(items: &mut [T], mut key: F)
where
    K: Ord,
    F: FnMut(&T) -> K,
{
    let mut previous = None;
    for index in 0..items.len() {
        let current = key(&items[index]);
        if let Some(previous) = previous {
            if current < previous {
                items.sort_unstable_by_key(key);
                return;
            }
        }
        previous = Some(current);
    }
}

/// Unstable-sort only when `items` are not already nondecreasing.
pub fn sort_unstable_if_needed<T>(items: &mut [T])
where
    T: Ord,
{
    for index in 1..items.len() {
        if items[index] < items[index - 1] {
            items.sort_unstable();
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::{
        iter_is_monotonic_by_key, sort_by_key_if_needed, sort_unstable_by_key_if_needed,
        sort_unstable_if_needed,
    };

    #[test]
    fn iter_monotonic_by_key_detects_ordered_and_unordered_streams() {
        assert!(iter_is_monotonic_by_key([0, 1, 1, 3], |value| value));
        assert!(!iter_is_monotonic_by_key([0, 2, 1, 3], |value| value));
    }

    #[test]
    fn stable_sort_by_key_skips_already_monotonic_slices() {
        let calls = Cell::new(0usize);
        let mut items = [(0usize, "a"), (1, "b"), (1, "c"), (3, "d")];

        sort_by_key_if_needed(&mut items, |(key, _)| {
            calls.set(calls.get() + 1);
            *key
        });

        assert_eq!(items, [(0, "a"), (1, "b"), (1, "c"), (3, "d")]);
        assert_eq!(
            calls.get(),
            items.len(),
            "Fix: monotonic ordering paths must not invoke the fallback sort."
        );
    }

    #[test]
    fn stable_sort_by_key_sorts_unordered_slices() {
        let mut items = [(2usize, "c"), (0, "a"), (3, "d"), (1, "b")];

        sort_by_key_if_needed(&mut items, |(key, _)| *key);

        assert_eq!(items, [(0, "a"), (1, "b"), (2, "c"), (3, "d")]);
    }

    #[test]
    fn unstable_sort_by_key_skips_already_monotonic_slices() {
        let calls = Cell::new(0usize);
        let mut items = [(0usize, "a"), (1, "b"), (3, "c")];

        sort_unstable_by_key_if_needed(&mut items, |(key, _)| {
            calls.set(calls.get() + 1);
            *key
        });

        assert_eq!(items, [(0, "a"), (1, "b"), (3, "c")]);
        assert_eq!(
            calls.get(),
            items.len(),
            "Fix: monotonic unstable-ordering paths must not invoke the fallback sort."
        );
    }

    #[test]
    fn unstable_sort_by_key_sorts_unordered_slices() {
        let mut items = [(2usize, "c"), (0, "a"), (1, "b")];

        sort_unstable_by_key_if_needed(&mut items, |(key, _)| *key);

        assert_eq!(items, [(0, "a"), (1, "b"), (2, "c")]);
    }

    #[test]
    fn unstable_sort_skips_already_monotonic_slices() {
        let mut items = [0usize, 1, 1, 3];

        sort_unstable_if_needed(&mut items);

        assert_eq!(items, [0, 1, 1, 3]);
    }

    #[test]
    fn unstable_sort_sorts_unordered_slices() {
        let mut items = [2usize, 0, 1];

        sort_unstable_if_needed(&mut items);

        assert_eq!(items, [0, 1, 2]);
    }

    #[test]
    fn generated_ordering_matrix_matches_full_sort_contract() {
        for len in 0..=128 {
            let ordered: Vec<usize> = (0..len).collect();
            let mut reversed: Vec<usize> = (0..len).rev().collect();
            let mut expected = reversed.clone();
            expected.sort_unstable();

            assert!(iter_is_monotonic_by_key(ordered.iter().copied(), |value| {
                value
            }));
            if len > 1 {
                assert!(!iter_is_monotonic_by_key(
                    reversed.iter().copied(),
                    |value| value
                ));
            }

            sort_unstable_if_needed(&mut reversed);
            assert_eq!(reversed, expected);

            let mut keyed: Vec<(usize, usize)> = (0..len).rev().map(|value| (value, len)).collect();
            sort_unstable_by_key_if_needed(&mut keyed, |(key, _)| *key);
            for (expected_key, actual) in keyed.iter().enumerate() {
                assert_eq!(actual.0, expected_key);
                assert_eq!(actual.1, len);
            }
        }
    }
}
