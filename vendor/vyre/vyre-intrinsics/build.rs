#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::manual_assert
)]
//! Build-time category-classification gate (F-IR-34).
//!
//! Scans `OpDefRegistration` source blocks across the workspace and panics
//! if any op claims `Category::Composite` (Category A) while also carrying a
//! `naga_wgsl: Some(...)` lowering arm.  That shape is the classification
//! drift this gate exists to prevent: a pure-IR composition that secretly
//! requires a dedicated Naga emitter arm breaks on any backend that lacks
//! that arm.
//!
//! The scan is heuristic (string-based) because it must run before the crate
//! is compiled and cannot depend on `inventory::iter` at build time.  Every
//! `OpDefRegistration` block in the tree follows a consistent layout, so the
//! heuristic is reliable for the current source style.

use std::fs;
use std::path::Path;

fn main() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.parent().unwrap();

    let files = [
        workspace.join("vyre-driver/src/registry/core_indirect.rs"),
        workspace.join("vyre-driver/src/registry/io.rs"),
        workspace.join("vyre-libs/src/math/atomic/atomic_add.rs"),
        workspace.join("vyre-libs/src/math/atomic/atomic_and.rs"),
        workspace.join("vyre-libs/src/math/atomic/atomic_compare_exchange.rs"),
        workspace.join("vyre-libs/src/math/atomic/atomic_exchange.rs"),
        workspace.join("vyre-libs/src/math/atomic/atomic_lru_update.rs"),
        workspace.join("vyre-libs/src/math/atomic/atomic_max.rs"),
        workspace.join("vyre-libs/src/math/atomic/atomic_min.rs"),
        workspace.join("vyre-libs/src/math/atomic/atomic_or.rs"),
        workspace.join("vyre-libs/src/math/atomic/atomic_xor.rs"),
    ];

    for path in &files {
        if !path.exists() {
            continue;
        }
        let src = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read {} for category scan: {e}", path.display()));
        check_file(path, &src);
    }
}

fn check_file(path: &Path, src: &str) {
    let mut cursor = 0;
    while let Some(off) = src[cursor..].find("OpDefRegistration::new") {
        let block_start = cursor + off;
        // Locate the inner `OpDef { ... }` block.
        let Some(opdef_off) = src[block_start..].find("OpDef {") else {
            cursor = block_start + 1;
            continue;
        };
        let opdef_start = block_start + opdef_off;
        let Some(opdef_len) = find_matching_brace(&src[opdef_start..]) else {
            cursor = opdef_start + 1;
            continue;
        };
        let block = &src[opdef_start..opdef_start + opdef_len];

        let is_composite = block.contains("category: Category::Composite");
        let has_naga_some = block.contains("naga_wgsl: Some(");

        if is_composite && has_naga_some {
            panic!(
                "category classification mismatch for op in `{}`: declared Composite (Category A) but lowering table has naga_wgsl: Some(...). Fix: Category A ops must be pure IR composition with no dedicated Naga arm.",
                path.display()
            );
        }

        cursor = opdef_start + opdef_len;
    }
}

fn find_matching_brace(s: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
    }
    None
}
