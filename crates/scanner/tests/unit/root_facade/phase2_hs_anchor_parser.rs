use crate::engine::hs_prefilter_requires_host_regex_for_test as requires_host_regex;

#[test]
fn hs_prefilter_host_path_is_only_for_real_anchors() {
    for src in [
        r"^sk-[A-Za-z0-9]+",
        r"sk-[A-Za-z0-9]+$",
        r"(?m)^token",
        r"token\\$",
        r"slash\\^anchor",
    ] {
        assert!(requires_host_regex(src), "{src:?} must stay on host regex");
    }
}

#[test]
fn hs_prefilter_keeps_escaped_anchor_literals_on_hs_path() {
    for src in [
        r"literal\^caret",
        r"price\$value",
        r"[\^]caret",
        r"[$]dollar",
        r"[A-Z\]$]+",
    ] {
        assert!(
            !requires_host_regex(src),
            "{src:?} contains no unescaped anchor outside a character class"
        );
    }
}

#[test]
fn hs_prefilter_keeps_character_class_carets_and_dollars_on_hs_path() {
    for src in [
        r"[^A-Za-z0-9_]{3}",
        r"[A-Z^$]{8,16}",
        r"[[:^alpha:]]+",
        r"token[^\n\r]+",
    ] {
        assert!(
            !requires_host_regex(src),
            "{src:?} has only class-local ^/$ syntax"
        );
    }
}
