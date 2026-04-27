//! **Host-only** translation-unit preparation (Tier outside `vyre-libs` ops).
//!
//! Resolves `#include` into one character stream and prepends CLI `-D`
//! definitions as `#define` lines so the resident GPU frontend sees one
//! contiguous TU. It never builds a CPU C parse tree.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::api::VyreCompileOptions;

mod preprocess;

pub use preprocess::expand_preprocessor_macros;
use preprocess::{eval_preprocessor_condition, parse_define, strip_directive_comments, MacroDef};

const MAX_INCLUDE_DEPTH: u32 = 64;
const MAX_INCLUDE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
struct IncludeConditionalFrame {
    parent_active: bool,
    branch_taken: bool,
    current_active: bool,
}

/// Prepend `-Dname` / `-Dname=value` as `#define` lines (C preprocessor surface syntax).
#[must_use]
pub fn apply_cli_defines_prefix(source: &str, macros: &[(String, Option<String>)]) -> String {
    if macros.is_empty() {
        return source.to_string();
    }
    let mut out = String::new();
    for (name, val) in macros {
        out.push_str("#define ");
        out.push_str(name);
        if let Some(v) = val {
            out.push(' ');
            out.push_str(v);
        }
        out.push('\n');
    }
    out.push_str(source);
    out
}

fn apply_cli_source_prefix(source: &str, options: &VyreCompileOptions) -> String {
    if options.macros.is_empty()
        && options.undefs.is_empty()
        && options.forced_include_files.is_empty()
    {
        return source.to_string();
    }
    let mut out = String::new();
    for (name, val) in &options.macros {
        out.push_str("#define ");
        out.push_str(name);
        if let Some(v) = val {
            out.push(' ');
            out.push_str(v);
        }
        out.push('\n');
    }
    for name in &options.undefs {
        out.push_str("#undef ");
        out.push_str(name);
        out.push('\n');
    }
    for path in &options.forced_include_files {
        out.push_str("#include \"");
        out.push_str(
            &path
                .to_string_lossy()
                .replace('\\', "\\\\")
                .replace('"', "\\\""),
        );
        out.push_str("\"\n");
    }
    out.push_str(source);
    out
}

fn splice_line_continuations(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    for logical_line in source.split_inclusive('\n') {
        let (line, newline) = line_body_and_newline(logical_line);
        let trimmed_len = line.trim_end_matches([' ', '\t']).len();
        if line[..trimmed_len].ends_with('\\') {
            out.push_str(&line[..trimmed_len - 1]);
        } else {
            out.push_str(line);
            out.push_str(newline);
        }
    }
    out
}

fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

fn expanded_include_dirs(include_dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs = Vec::with_capacity(include_dirs.len().saturating_mul(4));
    for dir in include_dirs {
        push_unique_path(&mut dirs, dir.clone());
        push_unique_path(&mut dirs, dir.join("generated"));
        push_unique_path(&mut dirs, dir.join("uapi"));
        push_unique_path(&mut dirs, dir.join("generated/uapi"));
    }
    dirs
}

fn search_include_file(name: &str, tu_dir: &Path, include_dirs: &[PathBuf]) -> Option<PathBuf> {
    let rel = tu_dir.join(name);
    if rel.is_file() {
        return Some(rel);
    }
    for d in include_dirs {
        let p = d.join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    search_asm_generic_fallback(name, include_dirs)
}

fn search_system_include_file(name: &str, include_dirs: &[PathBuf]) -> Option<PathBuf> {
    for d in include_dirs {
        let p = d.join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    search_asm_generic_fallback(name, include_dirs)
}

fn search_asm_generic_fallback(name: &str, include_dirs: &[PathBuf]) -> Option<PathBuf> {
    let generic = name.strip_prefix("asm/")?;
    let generic_name = Path::new("asm-generic").join(generic);
    include_dirs
        .iter()
        .map(|d| d.join(&generic_name))
        .find(|p| p.is_file())
}

fn parse_directive(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim_start();
    let after_hash = trimmed.strip_prefix('#')?.trim_start();
    let bytes = after_hash.as_bytes();
    let mut end = 0usize;
    while end < bytes.len() && bytes[end].is_ascii_alphabetic() {
        end += 1;
    }
    (end != 0).then(|| (&after_hash[..end], after_hash[end..].trim_start()))
}

fn parse_include_literal(rest: &str) -> Result<Option<(&str, bool)>, String> {
    let trimmed = rest.trim_start();
    if let Some(s) = trimmed.strip_prefix('"') {
        let end = s
            .find('"')
            .ok_or_else(|| "vyre-cc: unterminated #include \"...\"".to_string())?;
        Ok(Some((&s[..end], false)))
    } else if let Some(s) = trimmed.strip_prefix('<') {
        let end = s
            .find('>')
            .ok_or_else(|| "vyre-cc: unterminated #include <...>".to_string())?;
        Ok(Some((&s[..end], true)))
    } else {
        Ok(None)
    }
}

fn line_body_and_newline(line: &str) -> (&str, &str) {
    if let Some(body) = line.strip_suffix('\n') {
        if let Some(body) = body.strip_suffix('\r') {
            (body, "\r\n")
        } else {
            (body, "\n")
        }
    } else {
        (line, "")
    }
}

/// Expand `#include "..."` / `#include <...>` in place (host read). Depth- and size-bounded.
pub fn expand_local_includes(
    source: &str,
    tu_path: &Path,
    include_dirs: &[PathBuf],
    depth: u32,
    stack: &mut Vec<PathBuf>,
) -> Result<String, String> {
    let mut macros = HashMap::new();
    let include_dirs = expanded_include_dirs(include_dirs);
    expand_local_includes_with_state(source, tu_path, &include_dirs, depth, stack, &mut macros)
}

fn expand_local_includes_with_state(
    source: &str,
    tu_path: &Path,
    include_dirs: &[PathBuf],
    depth: u32,
    stack: &mut Vec<PathBuf>,
    macros: &mut HashMap<String, MacroDef>,
) -> Result<String, String> {
    if depth > MAX_INCLUDE_DEPTH {
        return Err(format!(
            "vyre-cc: #include depth exceeded {MAX_INCLUDE_DEPTH} (cycle or deep tree)."
        ));
    }
    let tu_dir = tu_path.parent().unwrap_or_else(|| Path::new("."));
    let mut out = String::with_capacity(source.len().saturating_mul(2));
    let mut conditionals = Vec::<IncludeConditionalFrame>::new();
    for logical_line in source.split_inclusive('\n') {
        let (line, newline) = line_body_and_newline(logical_line);
        let active = conditionals.last().is_none_or(|f| f.current_active);
        let directive_text = strip_directive_comments(line);
        let directive = parse_directive(&directive_text);

        if let Some((name, rest)) = directive {
            match name {
                "define" => {
                    if active {
                        if let Some((name, def)) = parse_define(rest) {
                            macros.insert(name, def);
                        }
                        out.push_str(line);
                        out.push_str(newline);
                    }
                    continue;
                }
                "undef" => {
                    if active {
                        macros.remove(rest.trim());
                        out.push_str(line);
                        out.push_str(newline);
                    }
                    continue;
                }
                "ifdef" => {
                    let parent_active = active;
                    let cond = macros.contains_key(rest.trim());
                    conditionals.push(IncludeConditionalFrame {
                        parent_active,
                        branch_taken: cond,
                        current_active: parent_active && cond,
                    });
                    out.push_str(line);
                    out.push_str(newline);
                    continue;
                }
                "ifndef" => {
                    let parent_active = active;
                    let cond = !macros.contains_key(rest.trim());
                    conditionals.push(IncludeConditionalFrame {
                        parent_active,
                        branch_taken: cond,
                        current_active: parent_active && cond,
                    });
                    out.push_str(line);
                    out.push_str(newline);
                    continue;
                }
                "if" => {
                    let parent_active = active;
                    let cond = eval_preprocessor_condition(rest, macros);
                    conditionals.push(IncludeConditionalFrame {
                        parent_active,
                        branch_taken: cond,
                        current_active: parent_active && cond,
                    });
                    out.push_str(line);
                    out.push_str(newline);
                    continue;
                }
                "elif" => {
                    if let Some(frame) = conditionals.last_mut() {
                        let cond = !frame.branch_taken && eval_preprocessor_condition(rest, macros);
                        frame.current_active = frame.parent_active && cond;
                        frame.branch_taken |= cond;
                    }
                    out.push_str(line);
                    out.push_str(newline);
                    continue;
                }
                "else" => {
                    if let Some(frame) = conditionals.last_mut() {
                        let cond = !frame.branch_taken;
                        frame.current_active = frame.parent_active && cond;
                        frame.branch_taken = true;
                    }
                    out.push_str(line);
                    out.push_str(newline);
                    continue;
                }
                "endif" => {
                    conditionals.pop();
                    out.push_str(line);
                    out.push_str(newline);
                    continue;
                }
                "include" if active => {
                    let Some((path_lit, is_system)) = parse_include_literal(rest)? else {
                        out.push_str(line);
                        out.push_str(newline);
                        continue;
                    };
                    let inc_path = if is_system {
                        search_system_include_file(path_lit, include_dirs).ok_or_else(|| {
                            format!(
                                "vyre-cc: system #include <{path_lit}> not found in -I search path"
                            )
                        })?
                    } else {
                        search_include_file(path_lit, tu_dir, include_dirs).ok_or_else(|| {
                            format!(
                                "vyre-cc: #include \"{path_lit}\" not found (tried TU dir and -I)"
                            )
                        })?
                    };
                    let expanded =
                        expand_one_include(&inc_path, include_dirs, depth, stack, macros)?;
                    if out.len().saturating_add(expanded.len()) > MAX_INCLUDE_BYTES {
                        return Err(format!(
                            "vyre-cc: expanded TU exceeds {MAX_INCLUDE_BYTES} bytes (include bomb guard)."
                        ));
                    }
                    out.push_str(&expanded);
                    if !expanded.ends_with('\n') {
                        out.push('\n');
                    }
                    continue;
                }
                _ => {}
            }
        }

        if active {
            out.push_str(line);
            out.push_str(newline);
        }
    }
    Ok(out)
}

fn expand_one_include(
    inc_path: &Path,
    include_dirs: &[PathBuf],
    depth: u32,
    stack: &mut Vec<PathBuf>,
    macros: &mut HashMap<String, MacroDef>,
) -> Result<String, String> {
    let canon = fs::canonicalize(inc_path).unwrap_or_else(|_| inc_path.to_path_buf());
    let inner_bytes =
        fs::read(inc_path).map_err(|e| format!("read include {}: {e}", inc_path.display()))?;
    let inner = String::from_utf8_lossy(&inner_bytes).into_owned();
    if inner.len() > MAX_INCLUDE_BYTES {
        return Err(format!(
            "vyre-cc: include {} exceeds {MAX_INCLUDE_BYTES} bytes.",
            inc_path.display()
        ));
    }
    stack.push(canon);
    let expanded =
        expand_local_includes_with_state(&inner, inc_path, include_dirs, depth + 1, stack, macros)?;
    stack.pop();
    Ok(expanded)
}

/// Resident frontend prep: `-D` prefix and bounded `#include` expansion only.
///
/// Macro expansion, conditional inclusion, keyword promotion, VAST construction,
/// and semantic lowering belong to the GPU-resident frontend. This function is
/// intentionally limited to file I/O and source concatenation because the 0.6
/// compiler path must not execute C semantics on the host.
pub fn prepare_resident_translation_unit_source(
    tu_path: &Path,
    raw: &str,
    options: &VyreCompileOptions,
) -> Result<String, String> {
    let spliced = splice_line_continuations(raw);
    let prefixed = apply_cli_source_prefix(&spliced, options);
    let mut stack = Vec::new();
    expand_local_includes(&prefixed, tu_path, &options.include_dirs, 0, &mut stack)
}

/// Legacy host prep used by focused preprocessor unit contracts.
///
/// The production compile path uses [`prepare_resident_translation_unit_source`].
pub fn prepare_translation_unit_source(
    tu_path: &Path,
    raw: &str,
    options: &VyreCompileOptions,
) -> Result<String, String> {
    let spliced = splice_line_continuations(raw);
    let prefixed = apply_cli_source_prefix(&spliced, options);
    let mut stack = Vec::new();
    let included = expand_local_includes(&prefixed, tu_path, &options.include_dirs, 0, &mut stack)?;
    Ok(expand_preprocessor_macros(&included))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defines_prefix_inserts_lines() {
        let s = apply_cli_defines_prefix("int x;\n", &[("FOO".into(), Some("1".into()))]);
        assert!(s.starts_with("#define FOO 1\n"));
        assert!(s.contains("int x;"));
    }

    #[test]
    fn include_expansion_inserts_file() {
        let tmp = std::env::temp_dir().join("vyre_cc_tu_host_inc");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let hdr = tmp.join("h.h");
        fs::write(&hdr, "//hdr\n").unwrap();
        let tu = tmp.join("t.c");
        fs::write(&tu, "").unwrap();
        let src = "#include \"h.h\"\nafter";
        let mut stack = Vec::new();
        let out = expand_local_includes(src, &tu, &[], 0, &mut stack).unwrap();
        assert!(out.contains("//hdr"));
        assert!(out.contains("after"));
    }
}
