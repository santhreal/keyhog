#!/usr/bin/env python3
"""Generate one #[test] per file under crates/*/tests/unit/gates/.

Santh STANDARD: one test function per file; filename encodes the invariant.

Run: python3 scripts/generate_micro_gate_tests.py --write
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CRATES = ["core", "scanner", "sources", "verifier", "cli"]
SKIP = {"lib.rs", "mod.rs"}
FILE_CAP = 500


def slug(parts: tuple[str, ...]) -> str:
    s = "_".join(parts)
    s = re.sub(r"[^a-zA-Z0-9]+", "_", s).strip("_").lower()
    return s or "root"


def source_files(crate: str) -> list[Path]:
    root = REPO / "crates" / crate / "src"
    return sorted(p for p in root.rglob("*.rs") if p.name not in SKIP)


def rel_posix(crate: str, src: Path) -> str:
    return src.relative_to(REPO / "crates" / crate / "src").as_posix()


def mod_path(rel: str) -> str:
    return rel.replace("/", "::").removesuffix(".rs")


def emit(crate: str, src: Path, kind: str) -> tuple[str, str]:
    rel = rel_posix(crate, src)
    parts = tuple(rel.removesuffix(".rs").split("/"))
    stem = slug(parts)
    fn = f"{stem}_{kind}"
    mod = mod_path(rel)

    if kind == "non_empty":
        body = f"""//! Gate `{mod}`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn {fn}() {{
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/{rel}");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "{mod}: expected substantive source, got {{}} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "{mod}: todo!/unimplemented! forbidden in non-test source"
    );
}}
"""
    elif kind == "no_inline_tests":
        body = f"""//! Gate `{mod}`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn {fn}() {{
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/{rel}");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "{mod}: move inline tests to crates/{crate}/tests/"
    );
}}
"""
    elif kind == "file_size_cap":
        body = f"""//! Gate `{mod}`: modularity file cap ({FILE_CAP} LOC, advisory warn).

#[test]
fn {fn}() {{
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/{rel}");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    // Advisory cap (Santh STANDARD.md): warn, do not fail CI.
    if lines > {FILE_CAP} {{
        eprintln!("{mod}: {{lines}} lines exceeds {FILE_CAP}-line cap - split module");
    }}
}}
"""
    elif kind == "no_unwrap_expect":
        body = f"""//! Gate `{mod}`: no .unwrap( / .expect( in production source lines.

#[test]
fn {fn}() {{
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/{rel}");
    let src = std::fs::read_to_string(path).expect("source readable");
    let mut offenders: Vec<(usize, &str)> = Vec::new();
    for (i, line) in src.lines().enumerate() {{
        let t = line.trim();
        if t.starts_with("//") || t.contains("#[cfg(test)]") {{
            continue;
        }}
        if t.contains(".unwrap(") || t.contains(".expect(") {{
            offenders.push((i + 1, line));
        }}
    }}
    assert!(
        offenders.is_empty(),
        "{mod}: unwrap/expect in production source at {{:?}}",
        offenders.iter().take(5).collect::<Vec<_>>()
    );
}}
"""
    else:
        raise ValueError(kind)
    return fn, body


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()

    kinds = ("non_empty", "no_inline_tests", "file_size_cap", "no_unwrap_expect")
    planned: list[tuple[Path, str]] = []
    for crate in CRATES:
        for src in source_files(crate):
            for kind in kinds:
                _, body = emit(crate, src, kind)
                fn = f"{slug(tuple(rel_posix(crate, src).removesuffix('.rs').split('/')))}_{kind}"
                out = REPO / "crates" / crate / "tests" / "unit" / "gates" / f"{fn}.rs"
                planned.append((out, body))

    print(f"planned micro gate test files: {len(planned)}")
    if not args.write:
        return

    written = 0
    for out, body in planned:
        out.parent.mkdir(parents=True, exist_ok=True)
        if out.exists():
            continue
        out.write_text(body, encoding="utf-8")
        written += 1

    for crate in CRATES:
        gates_dir = REPO / "crates" / crate / "tests" / "unit" / "gates"
        if not gates_dir.is_dir():
            continue
        mod_path = gates_dir / "mod.rs"
        stems = sorted(p.stem for p in gates_dir.glob("*.rs") if p.name != "mod.rs")
        mod_path.write_text("\n".join(f"pub mod {s};" for s in stems) + "\n", encoding="utf-8")
        unit_mod = REPO / "crates" / crate / "tests" / "unit" / "mod.rs"
        text = unit_mod.read_text(encoding="utf-8")
        if "pub mod gates;" not in text:
            unit_mod.write_text(text.rstrip() + "\npub mod gates;\n", encoding="utf-8")

    print(f"wrote {written} new gate files")


if __name__ == "__main__":
    main()
