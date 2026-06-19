pub fn contains_inline_test_module_or_function(src: &str) -> bool {
    let mut saw_test_cfg = false;
    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        if trimmed == "#[test]"
            || trimmed.starts_with("#[tokio::test")
            || trimmed.starts_with("#[proptest]")
        {
            return true;
        }
        if trimmed.starts_with("#[cfg(test)]")
            || trimmed.starts_with("#[cfg(all(test,")
            || trimmed.starts_with("#[cfg(all(test ")
        {
            saw_test_cfg = true;
            continue;
        }
        if saw_test_cfg && trimmed.starts_with("#[") {
            continue;
        }
        if saw_test_cfg
            && (trimmed.starts_with("mod tests") || trimmed.starts_with("pub mod tests"))
        {
            return true;
        }
        saw_test_cfg = false;
    }
    false
}
