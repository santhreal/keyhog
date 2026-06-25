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
        if saw_test_cfg && is_module_decl(trimmed) {
            return true;
        }
        saw_test_cfg = false;
    }
    false
}

fn is_module_decl(trimmed: &str) -> bool {
    if trimmed.starts_with("mod ") {
        return true;
    }
    let Some(after_pub) = trimmed.strip_prefix("pub") else {
        return false;
    };
    let after_pub = after_pub.trim_start();
    if after_pub.starts_with("mod ") {
        return true;
    }
    let Some(after_visibility) = after_pub.strip_prefix('(') else {
        return false;
    };
    let Some((_, after_visibility)) = after_visibility.split_once(')') else {
        return false;
    };
    after_visibility.trim_start().starts_with("mod ")
}

#[cfg(test)]
mod tests {
    use super::contains_inline_test_module_or_function;

    #[test]
    fn cfg_test_module_detection_is_not_name_based() {
        for src in [
            "#[cfg(test)]\nmod spec {}",
            "#[cfg(test)]\npub mod arbitrary_name {}",
            "#[cfg(test)]\npub(crate) mod nested {}",
            "#[cfg(test)]\npub(in crate::tests) mod scoped {}",
            "#[cfg(all(test, feature = \"x\"))]\n#[allow(dead_code)]\nmod with_attr {}",
        ] {
            assert!(
                contains_inline_test_module_or_function(src),
                "inline test module was missed: {src}"
            );
        }
    }

    #[test]
    fn cfg_test_non_module_item_is_not_reported_as_module() {
        assert!(!contains_inline_test_module_or_function(
            "#[cfg(test)]\nconst SAMPLE: &str = \"mod spec\";"
        ));
    }
}
