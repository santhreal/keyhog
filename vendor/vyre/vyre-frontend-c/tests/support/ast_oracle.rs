//! S0  -  AST equivalence oracle support.
//!
//! Two ground truths drive every per-feature parser test:
//!
//! 1. **clang** (subprocess `clang -Xclang -ast-dump=json -fsyntax-only -x c
//!    <file>`). Parses the JSON, filters to nodes whose source location lives
//!    in the user file (not transitively-included headers), and returns a
//!    flat sequence of node kinds.
//! 2. **vyrec** (in-process pipeline via `compile_source`). Reads the typed
//!    VAST section out of the `CompiledObject` and returns a flat sequence
//!    of vyrec-side VAST kind labels.
//!
//! A test asserts the **presence** of expected kinds in either stream.
//! Translation between the two label spaces is intentionally not done here;
//! per-feature tests assert both sides contain whatever they expect, which
//! catches "vyrec emits the right node" regressions without overfitting on
//! a translation table that would rot every time clang renames something.
//!
//! The full structural diff (Phase 2) is open work. This module is the
//! kind-presence layer that unblocks every per-feature ticket.
//!
//! `clang` not being on `PATH` is a release-host configuration failure.
//! Parser parity tests must fail loudly rather than silently dropping the
//! external oracle.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use crate::support::object::{u32_words_from_bytes, CompiledObject, SECTION_VAST, VAST_STRIDE_U32};

/// One clang declaration fact whose primary location belongs to the requested user file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClangDeclarationFact {
    /// clang AST node kind, such as `FunctionDecl`, `TypedefDecl`, or `FieldDecl`.
    pub(crate) kind: String,
    /// Declaration name when clang reports one.
    pub(crate) name: Option<String>,
    /// clang qualified type spelling when present on the declaration node.
    pub(crate) qual_type: Option<String>,
    /// Source file for the declaration location.
    pub(crate) file: String,
    /// One-based declaration line when clang reports one.
    pub(crate) line: Option<u32>,
    /// One-based declaration column when clang reports one.
    pub(crate) column: Option<u32>,
}

/// One clang statement/expression fact whose primary location belongs to the requested user file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClangAstStructureFact {
    /// clang AST node kind, such as `ReturnStmt`, `BinaryOperator`, or `CallExpr`.
    pub(crate) kind: String,
    /// clang qualified type spelling when present on the statement/expression node.
    pub(crate) qual_type: Option<String>,
    /// Referenced declaration name when clang reports one.
    pub(crate) referenced_decl_name: Option<String>,
    /// Source file for the node location.
    pub(crate) file: String,
    /// One-based node line when clang reports one.
    pub(crate) line: Option<u32>,
    /// One-based node column when clang reports one.
    pub(crate) column: Option<u32>,
}

/// One clang type fact extracted from a declaration or expression node in the user file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClangTypeFact {
    /// AST node kind that owns this type fact.
    pub(crate) owner_kind: String,
    /// AST node name when clang reports one.
    pub(crate) owner_name: Option<String>,
    /// clang qualified type spelling.
    pub(crate) qual_type: String,
    /// clang desugared qualified type spelling when present.
    pub(crate) desugared_qual_type: Option<String>,
    /// Whether the type spelling or node metadata indicates a typedef alias.
    pub(crate) uses_typedef: bool,
    /// Whether the type spelling uses `typeof`/`__typeof__`.
    pub(crate) uses_typeof: bool,
    /// Whether the type includes `const`.
    pub(crate) is_const: bool,
    /// Whether the type includes `volatile`.
    pub(crate) is_volatile: bool,
    /// Whether the type includes `restrict`.
    pub(crate) is_restrict: bool,
    /// Number of pointer stars in the qualified type spelling.
    pub(crate) pointer_depth: u32,
    /// Number of array extents in the qualified type spelling.
    pub(crate) array_depth: u32,
    /// Whether this is a function type spelling.
    pub(crate) is_function: bool,
    /// Tag kind detected from the qualified type spelling: `struct`, `union`, or `enum`.
    pub(crate) tag_kind: Option<String>,
    /// Source file for the owner node.
    pub(crate) file: String,
    /// One-based source line when clang reports one.
    pub(crate) line: Option<u32>,
    /// One-based source column when clang reports one.
    pub(crate) column: Option<u32>,
}

/// One clang symbol/scope fact for a declaration in the user file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClangSymbolScopeFact {
    /// clang declaration node kind.
    pub(crate) kind: String,
    /// Declaration name.
    pub(crate) name: String,
    /// clang storage class when present.
    pub(crate) storage_class: Option<String>,
    /// clang previous declaration pointer when this declaration redeclares an earlier one.
    pub(crate) previous_decl: Option<String>,
    /// Owning declaration kind when this declaration is nested.
    pub(crate) owner_kind: Option<String>,
    /// Owning declaration name when this declaration is nested.
    pub(crate) owner_name: Option<String>,
    /// Inferred lexical scope kind.
    pub(crate) scope_kind: String,
    /// Inferred linkage class.
    pub(crate) linkage: String,
    /// Inferred visibility class.
    pub(crate) visibility: String,
    /// Source file for the declaration.
    pub(crate) file: String,
    /// One-based source line when clang reports one.
    pub(crate) line: Option<u32>,
    /// One-based source column when clang reports one.
    pub(crate) column: Option<u32>,
}

/// Run clang and return the kinds of every AST node whose source location is
/// in the requested user file.
///
/// Returns `Err` if clang is not available, exits non-zero, or emits invalid
/// JSON. Callers must treat `Err` as a failed oracle, not a skipped test.
pub(crate) fn clang_user_kinds(c_file: &Path) -> Result<Vec<String>, String> {
    let output = Command::new("clang")
        .args(["-Xclang", "-ast-dump=json", "-fsyntax-only", "-x", "c"])
        .arg(c_file)
        .output()
        .map_err(|e| format!("clang invocation failed: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("clang exited {}: {}", output.status, stderr.trim()));
    }
    let json: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("clang produced non-JSON ast dump: {e}"))?;
    let target = canonical_path(c_file);
    let mut kinds = Vec::new();
    let mut sticky_file: Option<String> = None;
    walk_clang_nodes(&json, &target, &mut sticky_file, &mut kinds);
    Ok(kinds)
}

/// Convenience wrapper for tests that require clang as an external oracle.
pub(crate) fn clang_user_kinds_required(c_file: &Path) -> Vec<String> {
    match clang_user_kinds(c_file) {
        Ok(k) => k,
        Err(why) => panic!(
            "ast_oracle: clang oracle failed for {}: {why}. Fix: install clang or repair clang -Xclang -ast-dump=json parity support.",
            c_file.display()
        ),
    }
}

/// Run clang and return declaration facts whose source location is in the requested user file.
pub(crate) fn clang_user_declarations(c_file: &Path) -> Result<Vec<ClangDeclarationFact>, String> {
    let output = Command::new("clang")
        .args(["-Xclang", "-ast-dump=json", "-fsyntax-only", "-x", "c"])
        .arg(c_file)
        .output()
        .map_err(|e| format!("clang invocation failed: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("clang exited {}: {}", output.status, stderr.trim()));
    }
    let json: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("clang produced non-JSON ast dump: {e}"))?;
    let target = canonical_path(c_file);
    let mut declarations = Vec::new();
    let mut sticky_file: Option<String> = None;
    walk_clang_declarations(&json, &target, &mut sticky_file, &mut declarations);
    Ok(declarations)
}

/// Convenience wrapper for tests that require clang declaration facts.
pub(crate) fn clang_user_declarations_required(c_file: &Path) -> Vec<ClangDeclarationFact> {
    match clang_user_declarations(c_file) {
        Ok(declarations) => declarations,
        Err(why) => panic!(
            "ast_oracle: clang declaration oracle failed for {}: {why}. Fix: install clang or repair clang -Xclang -ast-dump=json declaration extraction.",
            c_file.display()
        ),
    }
}

/// Run clang and return statement/expression structure facts whose source location is in the
/// requested user file.
pub(crate) fn clang_user_structure(c_file: &Path) -> Result<Vec<ClangAstStructureFact>, String> {
    let output = Command::new("clang")
        .args(["-Xclang", "-ast-dump=json", "-fsyntax-only", "-x", "c"])
        .arg(c_file)
        .output()
        .map_err(|e| format!("clang invocation failed: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("clang exited {}: {}", output.status, stderr.trim()));
    }
    let json: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("clang produced non-JSON ast dump: {e}"))?;
    let target = canonical_path(c_file);
    let mut structure = Vec::new();
    let mut sticky_file: Option<String> = None;
    let mut sticky_line: Option<u32> = None;
    walk_clang_structure(
        &json,
        &target,
        &mut sticky_file,
        &mut sticky_line,
        &mut structure,
    );
    Ok(structure)
}

/// Convenience wrapper for tests that require clang statement/expression facts.
pub(crate) fn clang_user_structure_required(c_file: &Path) -> Vec<ClangAstStructureFact> {
    match clang_user_structure(c_file) {
        Ok(structure) => structure,
        Err(why) => panic!(
            "ast_oracle: clang structure oracle failed for {}: {why}. Fix: install clang or repair clang -Xclang -ast-dump=json structure extraction.",
            c_file.display()
        ),
    }
}

/// Run clang and return type facts whose owning AST node location is in the requested user file.
pub(crate) fn clang_user_type_facts(c_file: &Path) -> Result<Vec<ClangTypeFact>, String> {
    let output = Command::new("clang")
        .args(["-Xclang", "-ast-dump=json", "-fsyntax-only", "-x", "c"])
        .arg(c_file)
        .output()
        .map_err(|e| format!("clang invocation failed: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("clang exited {}: {}", output.status, stderr.trim()));
    }
    let json: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("clang produced non-JSON ast dump: {e}"))?;
    let target = canonical_path(c_file);
    let mut facts = Vec::new();
    let mut sticky_file: Option<String> = None;
    let mut sticky_line: Option<u32> = None;
    walk_clang_type_facts(
        &json,
        &target,
        &mut sticky_file,
        &mut sticky_line,
        &mut facts,
    );
    Ok(facts)
}

/// Convenience wrapper for tests that require clang type facts.
pub(crate) fn clang_user_type_facts_required(c_file: &Path) -> Vec<ClangTypeFact> {
    match clang_user_type_facts(c_file) {
        Ok(facts) => facts,
        Err(why) => panic!(
            "ast_oracle: clang type oracle failed for {}: {why}. Fix: install clang or repair clang -Xclang -ast-dump=json type extraction.",
            c_file.display()
        ),
    }
}

/// Run clang and return symbol/scope facts whose declaration location is in the requested user
/// file.
pub(crate) fn clang_user_symbol_scope_facts(
    c_file: &Path,
) -> Result<Vec<ClangSymbolScopeFact>, String> {
    let output = Command::new("clang")
        .args(["-Xclang", "-ast-dump=json", "-fsyntax-only", "-x", "c"])
        .arg(c_file)
        .output()
        .map_err(|e| format!("clang invocation failed: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("clang exited {}: {}", output.status, stderr.trim()));
    }
    let json: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("clang produced non-JSON ast dump: {e}"))?;
    let target = canonical_path(c_file);
    let mut facts = Vec::new();
    let mut sticky_file: Option<String> = None;
    let mut sticky_line: Option<u32> = None;
    let mut owner_stack = Vec::new();
    walk_clang_symbol_scope_facts(
        &json,
        &target,
        &mut sticky_file,
        &mut sticky_line,
        &mut owner_stack,
        &mut facts,
    );
    Ok(facts)
}

/// Convenience wrapper for tests that require clang symbol/scope facts.
pub(crate) fn clang_user_symbol_scope_facts_required(c_file: &Path) -> Vec<ClangSymbolScopeFact> {
    match clang_user_symbol_scope_facts(c_file) {
        Ok(facts) => facts,
        Err(why) => panic!(
            "ast_oracle: clang symbol/scope oracle failed for {}: {why}. Fix: install clang or repair clang -Xclang -ast-dump=json symbol/scope extraction.",
            c_file.display()
        ),
    }
}

fn canonical_path(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Walk clang's `-ast-dump=json` tree and collect kinds for nodes whose
/// `loc.file` (or the inherited `loc.file` from the most recent ancestor that
/// supplied one) matches `target`.
///
/// clang's JSON dump is a tree of objects with shape:
/// ```text
/// { "kind": "FunctionDecl", "loc": {"file":"…","line":N,"col":M}, "inner":[…] }
/// ```
/// The `loc.file` field is omitted on every node that shares the previous
/// node's file  -  `sticky_file` carries that inheritance.
fn walk_clang_nodes(
    node: &Value,
    target: &Path,
    sticky_file: &mut Option<String>,
    kinds: &mut Vec<String>,
) {
    let Some(obj) = node.as_object() else { return };
    let kind = obj.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    let loc_file = obj
        .get("loc")
        .and_then(|loc| loc.as_object())
        .and_then(|loc_obj| loc_obj.get("file"))
        .and_then(|v| v.as_str());
    let range_begin_file = obj
        .get("range")
        .and_then(|range| range.as_object())
        .and_then(|range| range.get("begin"))
        .and_then(|begin| begin.as_object())
        .and_then(|begin| begin.get("file"))
        .and_then(|v| v.as_str());
    if let Some(file) = loc_file.or(range_begin_file) {
        *sticky_file = Some(file.to_string());
    }
    let in_user_file = sticky_file
        .as_deref()
        .map(|f| paths_match(f, target))
        .unwrap_or_else(|| {
            // The TranslationUnitDecl root has no file; we don't count it but
            // we do recurse so its children pick up file inheritance.
            kind == "TranslationUnitDecl"
        });
    let count_self = match kind {
        "" | "TranslationUnitDecl" => false,
        _ => in_user_file,
    };
    if count_self {
        kinds.push(kind.to_string());
    }
    if let Some(inner) = obj.get("inner").and_then(|v| v.as_array()) {
        // Each child resets its own sticky file inheritance from the parent's
        // current value. Carry the parent's sticky_file as the starting point.
        let parent_sticky = sticky_file.clone();
        for child in inner {
            *sticky_file = parent_sticky.clone();
            walk_clang_nodes(child, target, sticky_file, kinds);
        }
        *sticky_file = parent_sticky;
    }
}

fn walk_clang_declarations(
    node: &Value,
    target: &Path,
    sticky_file: &mut Option<String>,
    declarations: &mut Vec<ClangDeclarationFact>,
) {
    let Some(obj) = node.as_object() else { return };
    let kind = obj.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    let loc_file = obj
        .get("loc")
        .and_then(|loc| loc.as_object())
        .and_then(|loc_obj| loc_obj.get("file"))
        .and_then(|v| v.as_str());
    if let Some(file) = loc_file {
        *sticky_file = Some(file.to_string());
    }
    let in_user_file = sticky_file
        .as_deref()
        .map(|f| paths_match(f, target))
        .unwrap_or_else(|| kind == "TranslationUnitDecl");
    let loc = declaration_location(obj, sticky_file.as_deref().unwrap_or_default());
    if in_user_file
        && kind.ends_with("Decl")
        && kind != "TranslationUnitDecl"
        && (loc.1.is_some() || loc.2.is_some())
    {
        declarations.push(ClangDeclarationFact {
            kind: kind.to_string(),
            name: obj
                .get("name")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned),
            qual_type: obj
                .get("type")
                .and_then(|v| v.as_object())
                .and_then(|type_obj| type_obj.get("qualType"))
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned),
            file: loc.0,
            line: loc.1,
            column: loc.2,
        });
    }
    if let Some(inner) = obj.get("inner").and_then(|v| v.as_array()) {
        let parent_sticky = sticky_file.clone();
        for child in inner {
            walk_clang_declarations(child, target, sticky_file, declarations);
        }
        *sticky_file = parent_sticky;
    }
}

fn declaration_location(
    obj: &serde_json::Map<String, Value>,
    sticky_file: &str,
) -> (String, Option<u32>, Option<u32>) {
    let loc_obj = obj.get("loc").and_then(|loc| loc.as_object());
    let range_begin = obj
        .get("range")
        .and_then(|range| range.as_object())
        .and_then(|range| range.get("begin"))
        .and_then(|begin| begin.as_object());
    let file = loc_obj
        .and_then(|loc| loc.get("file"))
        .or_else(|| range_begin.and_then(|begin| begin.get("file")))
        .and_then(|v| v.as_str())
        .unwrap_or(sticky_file)
        .to_string();
    let line = loc_obj
        .and_then(|loc| loc.get("line"))
        .or_else(|| range_begin.and_then(|begin| begin.get("line")))
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok());
    let column = loc_obj
        .and_then(|loc| loc.get("col"))
        .or_else(|| range_begin.and_then(|begin| begin.get("col")))
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok());
    (file, line, column)
}


fn walk_clang_symbol_scope_facts(
    node: &Value,
    target: &Path,
    sticky_file: &mut Option<String>,
    sticky_line: &mut Option<u32>,
    owner_stack: &mut Vec<(String, String)>,
    facts: &mut Vec<ClangSymbolScopeFact>,
) {
    let Some(obj) = node.as_object() else { return };
    let kind = obj.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    update_sticky_source(obj, sticky_file, sticky_line);
    let in_user_file = sticky_file
        .as_deref()
        .map(|f| paths_match(f, target))
        .unwrap_or_else(|| kind == "TranslationUnitDecl");
    let mut loc = declaration_location(obj, sticky_file.as_deref().unwrap_or_default());
    if loc.1.is_none() {
        loc.1 = *sticky_line;
    }
    let name = obj.get("name").and_then(|v| v.as_str());
    if in_user_file
        && kind.ends_with("Decl")
        && kind != "TranslationUnitDecl"
        && (loc.1.is_some() || loc.2.is_some())
        && name.is_some()
    {
        let storage_class = obj
            .get("storageClass")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let (owner_kind, owner_name) = owner_stack
            .last()
            .map(|(owner_kind, owner_name)| (Some(owner_kind.clone()), Some(owner_name.clone())))
            .unwrap_or((None, None));
        let scope_kind = infer_scope_kind(owner_kind.as_deref(), kind);
        facts.push(ClangSymbolScopeFact {
            kind: kind.to_string(),
            name: name.unwrap_or_default().to_string(),
            storage_class: storage_class.clone(),
            previous_decl: obj
                .get("previousDecl")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned),
            owner_kind,
            owner_name,
            scope_kind: scope_kind.to_string(),
            linkage: infer_linkage(kind, storage_class.as_deref(), scope_kind).to_string(),
            visibility: infer_visibility(storage_class.as_deref(), scope_kind).to_string(),
            file: loc.0,
            line: loc.1,
            column: loc.2,
        });
    }
    let push_owner = kind.ends_with("Decl")
        && name.is_some()
        && matches!(kind, "FunctionDecl" | "RecordDecl" | "EnumDecl");
    if push_owner {
        owner_stack.push((kind.to_string(), name.unwrap_or_default().to_string()));
    }
    if let Some(inner) = obj.get("inner").and_then(|v| v.as_array()) {
        let parent_sticky = sticky_file.clone();
        let parent_line = *sticky_line;
        for child in inner {
            walk_clang_symbol_scope_facts(
                child,
                target,
                sticky_file,
                sticky_line,
                owner_stack,
                facts,
            );
        }
        *sticky_file = parent_sticky;
        *sticky_line = parent_line;
    }
    if push_owner {
        owner_stack.pop();
    }
}

fn infer_scope_kind(owner_kind: Option<&str>, declaration_kind: &str) -> &'static str {
    match owner_kind {
        Some("FunctionDecl") => "function",
        Some("RecordDecl") => "aggregate",
        Some("EnumDecl") => "enum",
        Some(_) => "nested",
        None if declaration_kind == "ParmVarDecl" => "prototype",
        None => "file",
    }
}

fn infer_linkage(kind: &str, storage_class: Option<&str>, scope_kind: &str) -> &'static str {
    if scope_kind != "file" {
        return "none";
    }
    match storage_class {
        Some("static") => "internal",
        Some("extern") => "external",
        _ if matches!(kind, "FunctionDecl" | "VarDecl") => "external",
        _ => "none",
    }
}

fn infer_visibility(storage_class: Option<&str>, scope_kind: &str) -> &'static str {
    match (scope_kind, storage_class) {
        ("file", Some("static")) => "translation-unit",
        ("file", _) => "external",
        ("function", _) => "function-local",
        ("aggregate", _) => "aggregate-member",
        ("enum", _) => "enum-member",
        _ => "nested",
    }
}

fn walk_clang_type_facts(
    node: &Value,
    target: &Path,
    sticky_file: &mut Option<String>,
    sticky_line: &mut Option<u32>,
    facts: &mut Vec<ClangTypeFact>,
) {
    let Some(obj) = node.as_object() else { return };
    let kind = obj.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    update_sticky_source(obj, sticky_file, sticky_line);
    let in_user_file = sticky_file
        .as_deref()
        .map(|f| paths_match(f, target))
        .unwrap_or_else(|| kind == "TranslationUnitDecl");
    let mut loc = declaration_location(obj, sticky_file.as_deref().unwrap_or_default());
    if loc.1.is_none() {
        loc.1 = *sticky_line;
    }
    if in_user_file && (loc.1.is_some() || loc.2.is_some()) {
        if let Some(type_obj) = obj.get("type").and_then(|v| v.as_object()) {
            if let Some(qual_type) = type_obj.get("qualType").and_then(|v| v.as_str()) {
                let desugared_qual_type = type_obj
                    .get("desugaredQualType")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned);
                facts.push(type_fact_from_parts(
                    kind,
                    obj.get("name").and_then(|v| v.as_str()),
                    qual_type,
                    desugared_qual_type,
                    type_obj.contains_key("typeAliasDeclId"),
                    loc,
                ));
            }
        } else if let Some(tag_fact) = tag_type_fact_from_node(kind, obj, loc.clone()) {
            facts.push(tag_fact);
        }
    }
    if let Some(inner) = obj.get("inner").and_then(|v| v.as_array()) {
        let parent_sticky = sticky_file.clone();
        let parent_line = *sticky_line;
        for child in inner {
            walk_clang_type_facts(child, target, sticky_file, sticky_line, facts);
        }
        *sticky_file = parent_sticky;
        *sticky_line = parent_line;
    }
}

fn type_fact_from_parts(
    owner_kind: &str,
    owner_name: Option<&str>,
    qual_type: &str,
    desugared_qual_type: Option<String>,
    has_type_alias_id: bool,
    loc: (String, Option<u32>, Option<u32>),
) -> ClangTypeFact {
    let lower = qual_type.to_ascii_lowercase();
    let is_function =
        owner_kind == "FunctionDecl" || (!lower.contains("typeof") && qual_type.contains(" ("));
    let tag_kind = ["struct", "union", "enum"]
        .into_iter()
        .find(|prefix| lower.starts_with(&format!("{prefix} ")))
        .map(ToOwned::to_owned);
    ClangTypeFact {
        owner_kind: owner_kind.to_string(),
        owner_name: owner_name.map(ToOwned::to_owned),
        qual_type: qual_type.to_string(),
        desugared_qual_type,
        uses_typedef: has_type_alias_id || owner_kind == "TypedefDecl",
        uses_typeof: lower.contains("typeof"),
        is_const: lower.split_whitespace().any(|part| part == "const"),
        is_volatile: lower.split_whitespace().any(|part| part == "volatile"),
        is_restrict: lower.split_whitespace().any(|part| part == "restrict"),
        pointer_depth: qual_type.chars().filter(|c| *c == '*').count() as u32,
        array_depth: qual_type.chars().filter(|c| *c == '[').count() as u32,
        is_function,
        tag_kind,
        file: loc.0,
        line: loc.1,
        column: loc.2,
    }
}

fn tag_type_fact_from_node(
    owner_kind: &str,
    obj: &serde_json::Map<String, Value>,
    loc: (String, Option<u32>, Option<u32>),
) -> Option<ClangTypeFact> {
    let tag_kind = match owner_kind {
        "EnumDecl" => "enum",
        "RecordDecl" => obj
            .get("tagUsed")
            .and_then(|v| v.as_str())
            .unwrap_or("struct"),
        _ => return None,
    };
    let name = obj.get("name").and_then(|v| v.as_str())?;
    Some(ClangTypeFact {
        owner_kind: owner_kind.to_string(),
        owner_name: Some(name.to_string()),
        qual_type: format!("{tag_kind} {name}"),
        desugared_qual_type: None,
        uses_typedef: false,
        uses_typeof: false,
        is_const: false,
        is_volatile: false,
        is_restrict: false,
        pointer_depth: 0,
        array_depth: 0,
        is_function: false,
        tag_kind: Some(tag_kind.to_string()),
        file: loc.0,
        line: loc.1,
        column: loc.2,
    })
}

fn walk_clang_structure(
    node: &Value,
    target: &Path,
    sticky_file: &mut Option<String>,
    sticky_line: &mut Option<u32>,
    structure: &mut Vec<ClangAstStructureFact>,
) {
    let Some(obj) = node.as_object() else { return };
    let kind = obj.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    update_sticky_source(obj, sticky_file, sticky_line);
    let in_user_file = sticky_file
        .as_deref()
        .map(|f| paths_match(f, target))
        .unwrap_or_else(|| kind == "TranslationUnitDecl");
    let mut loc = declaration_location(obj, sticky_file.as_deref().unwrap_or_default());
    if loc.1.is_none() {
        loc.1 = *sticky_line;
    }
    if in_user_file && is_statement_or_expression_kind(kind) && (loc.1.is_some() || loc.2.is_some())
    {
        structure.push(ClangAstStructureFact {
            kind: kind.to_string(),
            qual_type: obj
                .get("type")
                .and_then(|v| v.as_object())
                .and_then(|type_obj| type_obj.get("qualType"))
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned),
            referenced_decl_name: obj
                .get("referencedDecl")
                .and_then(|v| v.as_object())
                .and_then(|decl| decl.get("name"))
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned),
            file: loc.0,
            line: loc.1,
            column: loc.2,
        });
    }
    if let Some(inner) = obj.get("inner").and_then(|v| v.as_array()) {
        let parent_sticky = sticky_file.clone();
        let parent_line = *sticky_line;
        for child in inner {
            walk_clang_structure(child, target, sticky_file, sticky_line, structure);
        }
        *sticky_file = parent_sticky;
        *sticky_line = parent_line;
    }
}

fn update_sticky_source(
    obj: &serde_json::Map<String, Value>,
    sticky_file: &mut Option<String>,
    sticky_line: &mut Option<u32>,
) {
    let loc_file = obj
        .get("loc")
        .and_then(|loc| loc.as_object())
        .and_then(|loc_obj| loc_obj.get("file"))
        .and_then(|v| v.as_str());
    let range_begin_file = obj
        .get("range")
        .and_then(|range| range.as_object())
        .and_then(|range| range.get("begin"))
        .and_then(|begin| begin.as_object())
        .and_then(|begin| begin.get("file"))
        .and_then(|v| v.as_str());
    if let Some(file) = loc_file.or(range_begin_file) {
        *sticky_file = Some(file.to_string());
    }
    let explicit_line = obj
        .get("loc")
        .and_then(|loc| loc.as_object())
        .and_then(|loc| loc.get("line"))
        .or_else(|| {
            obj.get("range")
                .and_then(|range| range.as_object())
                .and_then(|range| range.get("begin"))
                .and_then(|begin| begin.as_object())
                .and_then(|begin| begin.get("line"))
        })
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok());
    if explicit_line.is_some() {
        *sticky_line = explicit_line;
    }
}

fn is_statement_or_expression_kind(kind: &str) -> bool {
    kind.ends_with("Stmt")
        || kind.ends_with("Expr")
        || kind.ends_with("Literal")
        || kind.ends_with("Operator")
        || kind == "CompoundAssignOperator"
        || kind == "UnaryOperator"
        || kind == "ArraySubscriptExpr"
}

fn paths_match(loc_file: &str, target: &Path) -> bool {
    let loc_canonical = canonical_path(Path::new(loc_file));
    loc_canonical == target
}

/// Read the typed VAST section out of a `CompiledObject` and return one kind
/// label per node.
///
/// vyrec's VAST is a `u32`-stream with stride 10 words/node; field 0 is the
/// node kind. Empty-kind rows (sentinel zeros from non-emitted slots) are
/// skipped  -  they are not real nodes, just unused capacity in the buffer.
pub(crate) fn vyrec_user_kinds(object: &CompiledObject) -> Vec<String> {
    let bytes = object.section(SECTION_VAST);
    let words = u32_words_from_bytes(bytes);
    let stride = VAST_STRIDE_U32;
    let mut kinds = Vec::new();
    for chunk in words.chunks_exact(stride) {
        let kind = chunk[0];
        if kind == 0 {
            continue;
        }
        kinds.push(vast_kind_label(kind).to_string());
    }
    kinds
}

/// Stable string label for every public C VAST kind. Kept in lock-step with
/// `vyre-libs/src/parsing/c/parse/vast_kinds.rs`. Unknown kinds (e.g. raw
/// token kinds before classification, or new constants Kimi may add) fall
/// through to `Other(<hex>)` so the harness never silently drops information.
pub(crate) fn vast_kind_label(kind: u32) -> String {
    use vyre_libs::parsing::c::parse::vast::{
        C_AST_KIND_ALIGNOF_EXPR, C_AST_KIND_ARRAY_DECL, C_AST_KIND_ARRAY_SUBSCRIPT_EXPR,
        C_AST_KIND_ASM_CLOBBERS_LIST, C_AST_KIND_ASM_GOTO_LABELS, C_AST_KIND_ASM_INPUT_OPERAND,
        C_AST_KIND_ASM_OUTPUT_OPERAND, C_AST_KIND_ASM_QUALIFIER, C_AST_KIND_ASM_TEMPLATE,
        C_AST_KIND_ASSIGN_EXPR, C_AST_KIND_ATTRIBUTE_ALIAS, C_AST_KIND_ATTRIBUTE_ALIGNED,
        C_AST_KIND_ATTRIBUTE_ALWAYS_INLINE, C_AST_KIND_ATTRIBUTE_CLEANUP,
        C_AST_KIND_ATTRIBUTE_COLD, C_AST_KIND_ATTRIBUTE_CONST, C_AST_KIND_ATTRIBUTE_CONSTRUCTOR,
        C_AST_KIND_ATTRIBUTE_DEPRECATED, C_AST_KIND_ATTRIBUTE_DESTRUCTOR,
        C_AST_KIND_ATTRIBUTE_FALLTHROUGH, C_AST_KIND_ATTRIBUTE_FORMAT, C_AST_KIND_ATTRIBUTE_HOT,
        C_AST_KIND_ATTRIBUTE_MODE, C_AST_KIND_ATTRIBUTE_NAKED, C_AST_KIND_ATTRIBUTE_NOINLINE,
        C_AST_KIND_ATTRIBUTE_NORETURN, C_AST_KIND_ATTRIBUTE_PACKED, C_AST_KIND_ATTRIBUTE_PURE,
        C_AST_KIND_ATTRIBUTE_SECTION, C_AST_KIND_ATTRIBUTE_UNUSED, C_AST_KIND_ATTRIBUTE_USED,
        C_AST_KIND_ATTRIBUTE_VISIBILITY, C_AST_KIND_ATTRIBUTE_WEAK, C_AST_KIND_BIT_FIELD_DECL,
        C_AST_KIND_BREAK_STMT, C_AST_KIND_BUILTIN_CHOOSE_EXPR,
        C_AST_KIND_BUILTIN_CLASSIFY_TYPE_EXPR, C_AST_KIND_BUILTIN_CONSTANT_P_EXPR,
        C_AST_KIND_BUILTIN_EXPECT_EXPR, C_AST_KIND_BUILTIN_OBJECT_SIZE_EXPR,
        C_AST_KIND_BUILTIN_OFFSETOF_EXPR, C_AST_KIND_BUILTIN_OVERFLOW_EXPR,
        C_AST_KIND_BUILTIN_PREFETCH_EXPR, C_AST_KIND_BUILTIN_TYPES_COMPATIBLE_P_EXPR,
        C_AST_KIND_BUILTIN_UNREACHABLE_STMT, C_AST_KIND_CASE_STMT, C_AST_KIND_CAST_EXPR,
        C_AST_KIND_COMPOUND_LITERAL_EXPR, C_AST_KIND_CONDITIONAL_EXPR, C_AST_KIND_CONTINUE_STMT,
        C_AST_KIND_DEFAULT_STMT, C_AST_KIND_DO_STMT, C_AST_KIND_ELSE_STMT,
        C_AST_KIND_ENUMERATOR_DECL, C_AST_KIND_ENUM_DECL, C_AST_KIND_FIELD_DECL,
        C_AST_KIND_FOR_STMT, C_AST_KIND_FUNCTION_DECLARATOR, C_AST_KIND_FUNCTION_DEFINITION,
        C_AST_KIND_GENERIC_SELECTION_EXPR, C_AST_KIND_GNU_ATTRIBUTE,
        C_AST_KIND_GNU_LABEL_ADDRESS_EXPR, C_AST_KIND_GNU_LOCAL_LABEL_DECL,
        C_AST_KIND_GNU_STATEMENT_EXPR, C_AST_KIND_GOTO_STMT, C_AST_KIND_IF_STMT,
        C_AST_KIND_INITIALIZER_LIST, C_AST_KIND_INLINE_ASM, C_AST_KIND_LABEL_STMT,
        C_AST_KIND_MEMBER_ACCESS_EXPR, C_AST_KIND_POINTER_DECL, C_AST_KIND_RANGE_DESIGNATOR_EXPR,
        C_AST_KIND_RETURN_STMT, C_AST_KIND_SIZEOF_EXPR, C_AST_KIND_STATIC_ASSERT_DECL,
        C_AST_KIND_STRUCT_DECL, C_AST_KIND_SWITCH_STMT, C_AST_KIND_TYPEDEF_DECL,
        C_AST_KIND_UNARY_EXPR, C_AST_KIND_UNION_DECL, C_AST_KIND_WHILE_STMT,
    };
    let s = match kind {
        // Statements
        C_AST_KIND_IF_STMT => "IfStmt",
        C_AST_KIND_ELSE_STMT => "ElseStmt",
        C_AST_KIND_SWITCH_STMT => "SwitchStmt",
        C_AST_KIND_CASE_STMT => "CaseStmt",
        C_AST_KIND_DEFAULT_STMT => "DefaultStmt",
        C_AST_KIND_FOR_STMT => "ForStmt",
        C_AST_KIND_WHILE_STMT => "WhileStmt",
        C_AST_KIND_DO_STMT => "DoStmt",
        C_AST_KIND_RETURN_STMT => "ReturnStmt",
        C_AST_KIND_BREAK_STMT => "BreakStmt",
        C_AST_KIND_CONTINUE_STMT => "ContinueStmt",
        C_AST_KIND_GOTO_STMT => "GotoStmt",
        C_AST_KIND_LABEL_STMT => "LabelStmt",
        C_AST_KIND_BUILTIN_UNREACHABLE_STMT => "BuiltinUnreachableStmt",
        // Declarations
        C_AST_KIND_STRUCT_DECL => "StructDecl",
        C_AST_KIND_UNION_DECL => "UnionDecl",
        C_AST_KIND_ENUM_DECL => "EnumDecl",
        C_AST_KIND_TYPEDEF_DECL => "TypedefDecl",
        C_AST_KIND_FUNCTION_DEFINITION => "FunctionDefinition",
        C_AST_KIND_FIELD_DECL => "FieldDecl",
        C_AST_KIND_ENUMERATOR_DECL => "EnumeratorDecl",
        C_AST_KIND_BIT_FIELD_DECL => "BitFieldDecl",
        C_AST_KIND_STATIC_ASSERT_DECL => "StaticAssertDecl",
        C_AST_KIND_GNU_LOCAL_LABEL_DECL => "GnuLocalLabelDecl",
        // Declarators
        C_AST_KIND_POINTER_DECL => "PointerDecl",
        C_AST_KIND_ARRAY_DECL => "ArrayDecl",
        C_AST_KIND_FUNCTION_DECLARATOR => "FunctionDeclarator",
        // Expressions
        C_AST_KIND_ASSIGN_EXPR => "AssignExpr",
        C_AST_KIND_MEMBER_ACCESS_EXPR => "MemberAccessExpr",
        C_AST_KIND_SIZEOF_EXPR => "SizeofExpr",
        C_AST_KIND_ALIGNOF_EXPR => "AlignofExpr",
        C_AST_KIND_CONDITIONAL_EXPR => "ConditionalExpr",
        C_AST_KIND_UNARY_EXPR => "UnaryExpr",
        C_AST_KIND_ARRAY_SUBSCRIPT_EXPR => "ArraySubscriptExpr",
        C_AST_KIND_GENERIC_SELECTION_EXPR => "GenericSelectionExpr",
        C_AST_KIND_RANGE_DESIGNATOR_EXPR => "RangeDesignatorExpr",
        C_AST_KIND_CAST_EXPR => "CastExpr",
        C_AST_KIND_COMPOUND_LITERAL_EXPR => "CompoundLiteralExpr",
        C_AST_KIND_INITIALIZER_LIST => "InitializerList",
        C_AST_KIND_GNU_STATEMENT_EXPR => "GnuStatementExpr",
        C_AST_KIND_GNU_LABEL_ADDRESS_EXPR => "GnuLabelAddressExpr",
        // GNU builtins
        C_AST_KIND_BUILTIN_CONSTANT_P_EXPR => "BuiltinConstantPExpr",
        C_AST_KIND_BUILTIN_CHOOSE_EXPR => "BuiltinChooseExpr",
        C_AST_KIND_BUILTIN_TYPES_COMPATIBLE_P_EXPR => "BuiltinTypesCompatiblePExpr",
        C_AST_KIND_BUILTIN_EXPECT_EXPR => "BuiltinExpectExpr",
        C_AST_KIND_BUILTIN_OFFSETOF_EXPR => "BuiltinOffsetofExpr",
        C_AST_KIND_BUILTIN_OBJECT_SIZE_EXPR => "BuiltinObjectSizeExpr",
        C_AST_KIND_BUILTIN_PREFETCH_EXPR => "BuiltinPrefetchExpr",
        C_AST_KIND_BUILTIN_OVERFLOW_EXPR => "BuiltinOverflowExpr",
        C_AST_KIND_BUILTIN_CLASSIFY_TYPE_EXPR => "BuiltinClassifyTypeExpr",
        // Inline asm
        C_AST_KIND_INLINE_ASM => "InlineAsm",
        C_AST_KIND_ASM_TEMPLATE => "AsmTemplate",
        C_AST_KIND_ASM_OUTPUT_OPERAND => "AsmOutputOperand",
        C_AST_KIND_ASM_INPUT_OPERAND => "AsmInputOperand",
        C_AST_KIND_ASM_CLOBBERS_LIST => "AsmClobbersList",
        C_AST_KIND_ASM_GOTO_LABELS => "AsmGotoLabels",
        C_AST_KIND_ASM_QUALIFIER => "AsmQualifier",
        // GNU attributes
        C_AST_KIND_GNU_ATTRIBUTE => "GnuAttribute",
        C_AST_KIND_ATTRIBUTE_SECTION => "AttributeSection",
        C_AST_KIND_ATTRIBUTE_WEAK => "AttributeWeak",
        C_AST_KIND_ATTRIBUTE_ALIAS => "AttributeAlias",
        C_AST_KIND_ATTRIBUTE_ALIGNED => "AttributeAligned",
        C_AST_KIND_ATTRIBUTE_USED => "AttributeUsed",
        C_AST_KIND_ATTRIBUTE_UNUSED => "AttributeUnused",
        C_AST_KIND_ATTRIBUTE_NAKED => "AttributeNaked",
        C_AST_KIND_ATTRIBUTE_VISIBILITY => "AttributeVisibility",
        C_AST_KIND_ATTRIBUTE_PACKED => "AttributePacked",
        C_AST_KIND_ATTRIBUTE_CLEANUP => "AttributeCleanup",
        C_AST_KIND_ATTRIBUTE_CONSTRUCTOR => "AttributeConstructor",
        C_AST_KIND_ATTRIBUTE_DESTRUCTOR => "AttributeDestructor",
        C_AST_KIND_ATTRIBUTE_MODE => "AttributeMode",
        C_AST_KIND_ATTRIBUTE_NOINLINE => "AttributeNoinline",
        C_AST_KIND_ATTRIBUTE_ALWAYS_INLINE => "AttributeAlwaysInline",
        C_AST_KIND_ATTRIBUTE_COLD => "AttributeCold",
        C_AST_KIND_ATTRIBUTE_HOT => "AttributeHot",
        C_AST_KIND_ATTRIBUTE_PURE => "AttributePure",
        C_AST_KIND_ATTRIBUTE_CONST => "AttributeConst",
        C_AST_KIND_ATTRIBUTE_FORMAT => "AttributeFormat",
        C_AST_KIND_ATTRIBUTE_FALLTHROUGH => "AttributeFallthrough",
        C_AST_KIND_ATTRIBUTE_NORETURN => "AttributeNoreturn",
        C_AST_KIND_ATTRIBUTE_DEPRECATED => "AttributeDeprecated",
        _ => return format!("Other(0x{kind:08X})"),
    };
    s.to_string()
}

/// Hard assertion: every kind in `wanted` must appear at least once in `kinds`.
/// Failure message names the missing kind plus the first ten kinds that *did*
/// appear, to make per-feature regressions diagnosable from CI logs.
#[track_caller]
pub(crate) fn assert_kinds_contain(kinds: &[String], wanted: &[&str]) {
    for w in wanted {
        if !kinds.iter().any(|k| k == w) {
            let preview: Vec<&str> = kinds.iter().take(20).map(String::as_str).collect();
            panic!(
                "ast_oracle: expected kind `{w}` not found in {} kinds. First 20: {:?}",
                kinds.len(),
                preview,
            );
        }
    }
}

#[cfg(test)]

mod tests {
    use super::*;

    #[test]
    fn walk_filters_to_user_file_only() {
        let target = PathBuf::from("/tmp/userfile.c");
        let json = serde_json::json!({
            "kind": "TranslationUnitDecl",
            "inner": [
                { "kind": "TypedefDecl", "loc": {"file": "/usr/include/foo.h"} },
                { "kind": "FunctionDecl",
                  "loc": {"file": "/tmp/userfile.c", "line": 1, "col": 1},
                  "inner": [
                      { "kind": "ParmVarDecl",
                        "loc": {"line": 1, "col": 5}
                      },
                      { "kind": "CompoundStmt",
                        "loc": {"line": 1, "col": 30},
                        "inner": [
                            { "kind": "ReturnStmt", "loc": {"line": 2, "col": 5} }
                        ]
                      }
                  ]
                }
            ]
        });
        let mut kinds = Vec::new();
        let mut sticky = None;
        walk_clang_nodes(&json, &target, &mut sticky, &mut kinds);
        assert!(!kinds.contains(&"TypedefDecl".to_string()));
        assert!(kinds.contains(&"FunctionDecl".to_string()));
        assert!(kinds.contains(&"ParmVarDecl".to_string()));
        assert!(kinds.contains(&"ReturnStmt".to_string()));
    }

    #[test]
    fn vast_kind_labels_match_known_constants() {
        use vyre_libs::parsing::c::parse::vast::{
            C_AST_KIND_FUNCTION_DEFINITION, C_AST_KIND_GNU_ATTRIBUTE, C_AST_KIND_IF_STMT,
        };
        assert_eq!(vast_kind_label(C_AST_KIND_IF_STMT), "IfStmt");
        assert_eq!(
            vast_kind_label(C_AST_KIND_FUNCTION_DEFINITION),
            "FunctionDefinition"
        );
        assert_eq!(vast_kind_label(C_AST_KIND_GNU_ATTRIBUTE), "GnuAttribute");
        // Unknown kinds never panic; they fall through to Other(<hex>).
        assert_eq!(vast_kind_label(0xDEAD_BEEF), "Other(0xDEADBEEF)");
    }
}

