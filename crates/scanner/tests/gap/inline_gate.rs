pub fn contains_inline_test_module_or_function(src: &str) -> bool {
    let mut saw_test_cfg = false;
    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        if is_block_comment_line(trimmed) {
            continue;
        }
        if is_test_function_attr(trimmed) {
            return true;
        }
        if let Some(after_attr) = strip_test_cfg_attr(trimmed) {
            if is_module_decl(after_attr.trim_start()) {
                return true;
            }
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

fn is_test_function_attr(trimmed: &str) -> bool {
    if let Some(after_attr) = trimmed.strip_prefix("#[test]") {
        return after_attr.is_empty() || after_attr.chars().next().is_some_and(char::is_whitespace);
    }
    trimmed.starts_with("#[tokio::test") || trimmed.starts_with("#[proptest]")
}

fn strip_test_cfg_attr(trimmed: &str) -> Option<&str> {
    if !(trimmed.starts_with("#[cfg(test)]")
        || trimmed.starts_with("#[cfg(all(test,")
        || trimmed.starts_with("#[cfg(all(test "))
    {
        return None;
    }
    let end = trimmed.find(']')?;
    Some(&trimmed[end + 1..])
}

fn is_block_comment_line(trimmed: &str) -> bool {
    trimmed.starts_with("/*") || trimmed.starts_with('*') || trimmed.starts_with("*/")
}

fn is_module_decl(trimmed: &str) -> bool {
    let declaration = if let Some(rest) = strip_keyword(trimmed, "mod") {
        rest
    } else {
        let Some(after_pub) = trimmed.strip_prefix("pub") else {
            return false;
        };
        let after_pub = after_pub.trim_start();
        if let Some(rest) = strip_keyword(after_pub, "mod") {
            rest
        } else {
            let Some(after_visibility) = after_pub.strip_prefix('(') else {
                return false;
            };
            let Some((_, after_visibility)) = after_visibility.split_once(')') else {
                return false;
            };
            let Some(rest) = strip_keyword(after_visibility.trim_start(), "mod") else {
                return false;
            };
            rest
        }
    };
    declaration.contains('{') || !declaration.contains(';')
}

fn strip_keyword<'a>(trimmed: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = trimmed.strip_prefix(keyword)?;
    if rest.chars().next().is_some_and(char::is_whitespace) {
        Some(rest.trim_start())
    } else {
        None
    }
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
            "#[cfg(test)] mod same_line {}",
            "#[cfg(test)]\n/* allowed separator */\nmod after_block_comment {}",
            "#[cfg(test)]\npub(crate) mod\ttabbed {}",
            "#[cfg(test)]\nmod split_across_lines\n{}",
        ] {
            assert!(
                contains_inline_test_module_or_function(src),
                "inline test module was missed: {src}"
            );
        }
    }
    #[test]
    fn external_test_module_is_not_inline() {
        assert!(!contains_inline_test_module_or_function(
            "#[cfg(test)]\n#[path = \"external.rs\"]\nmod external;"
        ));
    }

    #[test]
    fn same_line_test_function_attribute_is_detected() {
        assert!(contains_inline_test_module_or_function(
            "#[test] fn inline_test() {}"
        ));
    }

    #[test]
    fn cfg_test_non_module_item_is_not_reported_as_module() {
        assert!(!contains_inline_test_module_or_function(
            "#[cfg(test)]\nconst SAMPLE: &str = \"mod spec\";"
        ));
    }
}
