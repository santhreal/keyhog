use std::collections::HashMap;

mod expr;

use expr::eval_preproc_expr;

const MAX_MACRO_EXPANSION_DEPTH: u32 = 32;

#[derive(Clone, Debug)]
pub(super) struct MacroDef {
    pub(super) params: Option<Vec<String>>,
    pub(super) variadic: Option<String>,
    pub(super) replacement: String,
}

#[derive(Clone, Copy, Debug)]
struct ConditionalFrame {
    parent_active: bool,
    branch_taken: bool,
    current_active: bool,
}

pub(super) fn strip_directive_comments(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'"' | b'\'' => {
                let quote = bytes[i];
                let start = i;
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i = i.saturating_add(2);
                        continue;
                    }
                    if bytes[i] == quote {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                out.push_str(&line[start..i.min(bytes.len())]);
            }
            b'/' if bytes.get(i + 1).copied() == Some(b'/') => break,
            b'/' if bytes.get(i + 1).copied() == Some(b'*') => {
                i += 2;
                while i + 1 < bytes.len()
                    && !(bytes[i] == b'*' && bytes.get(i + 1).copied() == Some(b'/'))
                {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
            }
            _ => {
                out.push(bytes[i] as char);
                i += 1;
            }
        }
    }
    out
}

pub(super) fn is_ident_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

pub(super) fn is_ident_continue(byte: u8) -> bool {
    is_ident_start(byte) || byte.is_ascii_digit()
}

pub(super) fn parse_define(rest: &str) -> Option<(String, MacroDef)> {
    let rest = rest.trim_start();
    let bytes = rest.as_bytes();
    let mut name_end = 0usize;
    if bytes.first().is_none_or(|b| !is_ident_start(*b)) {
        return None;
    }
    while name_end < bytes.len() && is_ident_continue(bytes[name_end]) {
        name_end += 1;
    }
    let name = rest[..name_end].to_string();
    let after_name = &rest[name_end..];
    if let Some(param_tail) = after_name.strip_prefix('(') {
        let close = param_tail.find(')')?;
        let mut params = Vec::new();
        let mut variadic = None;
        for raw_param in param_tail[..close].split(',') {
            let param = raw_param.trim();
            if param.is_empty() {
                continue;
            }
            if param == "..." {
                variadic = Some("__VA_ARGS__".to_string());
            } else if let Some(name) = param.strip_suffix("...") {
                let name = name.trim();
                if !name.is_empty() {
                    variadic = Some(name.to_string());
                }
            } else {
                params.push(param.to_string());
            }
        }
        let replacement = param_tail[close + 1..].trim().to_string();
        Some((
            name,
            MacroDef {
                params: Some(params),
                variadic,
                replacement,
            },
        ))
    } else {
        Some((
            name,
            MacroDef {
                params: None,
                variadic: None,
                replacement: after_name.trim().to_string(),
            },
        ))
    }
}

fn parse_macro_args(src: &str, open_idx: usize) -> Option<(Vec<String>, usize)> {
    let bytes = src.as_bytes();
    if bytes.get(open_idx).copied() != Some(b'(') {
        return None;
    }
    let mut args = Vec::new();
    let mut depth = 0u32;
    let mut start = open_idx + 1;
    let mut i = open_idx + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'"' | b'\'' => {
                let quote = bytes[i];
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i = i.saturating_add(2);
                        continue;
                    }
                    if bytes[i] == quote {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                continue;
            }
            b'(' => depth = depth.saturating_add(1),
            b')' if depth == 0 => {
                args.push(src[start..i].trim().to_string());
                return Some((args, i + 1));
            }
            b')' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                args.push(src[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn stringify_arg(arg: &str) -> String {
    let mut out = String::from("\"");
    for ch in arg.trim().chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn variadic_arg(
    name: &str,
    variadic: Option<&str>,
    params: &[String],
    args: &[String],
) -> Option<String> {
    let variadic_name = variadic?;
    if name != "__VA_ARGS__" && name != variadic_name {
        return None;
    }
    Some(
        args.get(params.len()..)
            .unwrap_or_default()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", "),
    )
}

fn replace_macro_params(
    replacement: &str,
    params: &[String],
    variadic: Option<&str>,
    args: &[String],
) -> String {
    let mut out = String::new();
    let bytes = replacement.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'#'
            && bytes.get(i + 1).copied() != Some(b'#')
            && i.checked_sub(1).and_then(|prev| bytes.get(prev)).copied() != Some(b'#')
        {
            let mut j = i + 1;
            while bytes.get(j).is_some_and(|b| b.is_ascii_whitespace()) {
                j += 1;
            }
            if bytes.get(j).is_some_and(|b| is_ident_start(*b)) {
                let start = j;
                j += 1;
                while bytes.get(j).is_some_and(|b| is_ident_continue(*b)) {
                    j += 1;
                }
                let name = &replacement[start..j];
                if let Some(value) = variadic_arg(name, variadic, params, args) {
                    out.push_str(&stringify_arg(&value));
                    i = j;
                    continue;
                } else if let Some(idx) = params.iter().position(|p| p == name) {
                    out.push_str(&stringify_arg(args.get(idx).map_or("", String::as_str)));
                    i = j;
                    continue;
                }
            }
        }
        if is_ident_start(bytes[i]) {
            let start = i;
            i += 1;
            while i < bytes.len() && is_ident_continue(bytes[i]) {
                i += 1;
            }
            let name = &replacement[start..i];
            if let Some(value) = variadic_arg(name, variadic, params, args) {
                out.push_str(&value);
            } else if let Some(idx) = params.iter().position(|p| p == name) {
                out.push_str(args.get(idx).map_or("", String::as_str));
            } else {
                out.push_str(name);
            }
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    collapse_token_paste(&out)
}

fn collapse_token_paste(src: &str) -> String {
    let mut parts = src.split("##");
    let Some(first) = parts.next() else {
        return String::new();
    };
    let mut out = first.trim_end().to_string();
    for part in parts {
        out.push_str(part.trim());
    }
    out
}

fn expand_line_macros(line: &str, macros: &HashMap<String, MacroDef>, depth: u32) -> String {
    expand_line_macros_inner(line, macros, depth, &[])
}

fn expand_line_macros_inner(
    line: &str,
    macros: &HashMap<String, MacroDef>,
    depth: u32,
    disabled: &[String],
) -> String {
    if depth > MAX_MACRO_EXPANSION_DEPTH {
        return line.to_string();
    }
    let bytes = line.as_bytes();
    let mut out = String::new();
    let mut i = 0usize;
    let mut changed = false;
    let mut next_disabled = disabled.to_vec();
    while i < bytes.len() {
        match bytes[i] {
            b'"' | b'\'' => {
                let quote = bytes[i];
                let start = i;
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i = i.saturating_add(2);
                        continue;
                    }
                    if bytes[i] == quote {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                out.push_str(&line[start..i.min(bytes.len())]);
            }
            b if is_ident_start(b) => {
                let start = i;
                i += 1;
                while i < bytes.len() && is_ident_continue(bytes[i]) {
                    i += 1;
                }
                let name = &line[start..i];
                if disabled.iter().any(|disabled| disabled == name) {
                    out.push_str(name);
                    continue;
                }
                let Some(def) = macros.get(name) else {
                    out.push_str(name);
                    continue;
                };
                match &def.params {
                    None => {
                        out.push_str(&def.replacement);
                        if !next_disabled.iter().any(|disabled| disabled == name) {
                            next_disabled.push(name.to_string());
                        }
                        changed = true;
                    }
                    Some(params) => {
                        let ws_start = i;
                        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                            i += 1;
                        }
                        if bytes.get(i).copied() == Some(b'(') {
                            if let Some((args, end)) = parse_macro_args(line, i) {
                                out.push_str(&replace_macro_params(
                                    &def.replacement,
                                    params,
                                    def.variadic.as_deref(),
                                    &args,
                                ));
                                if !next_disabled.iter().any(|disabled| disabled == name) {
                                    next_disabled.push(name.to_string());
                                }
                                i = end;
                                changed = true;
                            } else {
                                out.push_str(name);
                                out.push_str(&line[ws_start..i]);
                            }
                        } else {
                            out.push_str(name);
                            out.push_str(&line[ws_start..i]);
                        }
                    }
                }
            }
            _ => {
                out.push(bytes[i] as char);
                i += 1;
            }
        }
    }
    if changed {
        expand_line_macros_inner(&out, macros, depth + 1, &next_disabled)
    } else {
        out
    }
}

/// Expand C preprocessor definitions and conditionals in a bounded single pass.
#[must_use]
pub fn expand_preprocessor_macros(source: &str) -> String {
    let mut macros = HashMap::<String, MacroDef>::new();
    let mut conditionals = Vec::<ConditionalFrame>::new();
    let mut out = String::new();

    for raw_line in source.lines() {
        let leading_trimmed = raw_line.trim_start();
        let directive_line = leading_trimmed
            .starts_with('#')
            .then(|| strip_directive_comments(leading_trimmed));
        let trimmed = directive_line.as_deref().unwrap_or(leading_trimmed);
        let active = conditionals.last().is_none_or(|f| f.current_active);
        if let Some(rest) = trimmed.strip_prefix("#define") {
            if active {
                if let Some((name, def)) = parse_define(rest) {
                    macros.insert(name, def);
                }
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("#undef") {
            if active {
                macros.remove(rest.trim());
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("#ifdef") {
            let parent_active = active;
            let cond = macros.contains_key(rest.trim());
            conditionals.push(ConditionalFrame {
                parent_active,
                branch_taken: cond,
                current_active: parent_active && cond,
            });
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("#ifndef") {
            let parent_active = active;
            let cond = !macros.contains_key(rest.trim());
            conditionals.push(ConditionalFrame {
                parent_active,
                branch_taken: cond,
                current_active: parent_active && cond,
            });
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("#if") {
            let parent_active = active;
            let cond = eval_preproc_expr(rest.trim(), &macros);
            conditionals.push(ConditionalFrame {
                parent_active,
                branch_taken: cond,
                current_active: parent_active && cond,
            });
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("#elif") {
            if let Some(frame) = conditionals.last_mut() {
                let cond = !frame.branch_taken && eval_preproc_expr(rest.trim(), &macros);
                frame.current_active = frame.parent_active && cond;
                frame.branch_taken |= cond;
            }
            continue;
        }
        if trimmed.starts_with("#else") {
            if let Some(frame) = conditionals.last_mut() {
                let cond = !frame.branch_taken;
                frame.current_active = frame.parent_active && cond;
                frame.branch_taken = true;
            }
            continue;
        }
        if trimmed.starts_with("#endif") {
            conditionals.pop();
            continue;
        }

        if active {
            out.push_str(&expand_line_macros(raw_line, &macros, 0));
            out.push('\n');
        }
    }

    out
}

pub(super) fn eval_preprocessor_condition(expr: &str, macros: &HashMap<String, MacroDef>) -> bool {
    eval_preproc_expr(expr, macros)
}
