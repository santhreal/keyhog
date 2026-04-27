/// Maximum number of compiled compute pipelines retained by the runtime cache.
pub const MAX_PIPELINE_CACHE_ENTRIES: usize = 1024;

/// Build a deterministic cache key from shader source and entry point.
#[inline]
pub fn cache_key(wgsl_source: &str, entry_point: &str) -> String {
    let mut key = String::with_capacity(wgsl_source.len() + entry_point.len() + 1);
    key.push_str(entry_point);
    key.push('\0');
    key.push_str(wgsl_source);
    key
}
