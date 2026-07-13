//! Gate fragment-cache hot-path shape: cache hits must not allocate scoped keys.

use super::support::{read, scanner_src, uncommented_code};

#[test]
fn fragment_cache_uses_borrowed_scoped_key_for_lru_lookup() {
    let prod = uncommented_code(&read(&scanner_src().join("fragment_cache.rs")));

    assert!(
        prod.contains(
            "fn with_scoped_key<R>(prefix: &str, scope: &str, f: impl FnOnce(&str) -> R) -> R"
        ),
        "fragment cache should build a borrowed scoped key through one helper"
    );
    assert!(
        prod.matches("get_or_insert_mut_ref(key, Vec::new)").count() >= 1,
        "every fragment-cache record path must query the LRU by borrowed &str \
         (the borrowed-ref helper must actually be used, not merely defined). \
         The exact path count is not pinned here, a legitimate consolidation of \
         record paths must not trip this gate; the no-owned-key-allocation contract \
         is enforced by the negative assertion below, not by a brittle occurrence count."
    );
    assert!(
        !prod.contains("fn scoped_key(")
            && !prod.contains("get_or_insert_mut(key, Vec::new)")
            && !prod.contains("format!(\"{}\\0{}\"")
            && !prod.contains("format!(\"{prefix}\\0{scope}\")"),
        "fragment cache must not allocate an owned scoped key before every cache lookup"
    );
}

#[test]
fn fragment_cache_eviction_uses_single_key_owner() {
    let prod = uncommented_code(&read(&scanner_src().join("fragment_cache.rs")));

    assert!(
        prod.contains(".min_by_key(|(_, fragment)| fragment_eviction_key(fragment))")
            && prod
                .contains("fn fragment_eviction_key(fragment: &SecretFragment) -> (usize, &[u8])"),
        "fragment eviction ordering should have one named min_by_key owner"
    );
    assert!(
        !prod.contains(".min_by(|(_, a), (_, b)|")
            && !prod.contains(".then_with(|| a.value.as_bytes().cmp(b.value.as_bytes()))"),
        "fragment eviction should not inline tuple comparison in evict_one"
    );
}
