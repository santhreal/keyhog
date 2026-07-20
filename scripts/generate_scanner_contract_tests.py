#!/usr/bin/env python3
"""Generate macro-expanded detector contract fixture tests for keyhog-scanner.

Each contract TOML in crates/scanner/tests/contracts/*.toml becomes a set of
independent #[test] functions: one per positive/negative/evasion fixture plus a
schema test.  The runner compiles one shared CompiledScanner (GPU disabled) and
asserts recall/precision per the contract.

Regenerate from repo root:
    python3 scripts/generate_scanner_contract_tests.py
"""

import pathlib
import re
import subprocess
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "crates" / "scanner" / "tests" / "contracts"
OUT = ROOT / "crates" / "scanner" / "tests" / "contract"
OUT_FILE = OUT / "detector_fixtures_generated.rs"

_IDENT_RE = re.compile(r"[^A-Za-z0-9_]+")
_HASH_RUN_RE = re.compile(r"#+")


def safe_name(name: str) -> str:
    """Turn a file stem into a valid Rust identifier."""
    ident = _IDENT_RE.sub("_", name).strip("_")
    if ident and ident[0].isdigit():
        ident = "d_" + ident
    return ident or "contract"


def rust_raw(s: str) -> str:
    """Return a Rust raw string literal with a delimiter width that cannot
    collide with the content."""
    max_hashes = 0
    for match in _HASH_RUN_RE.finditer(s):
        max_hashes = max(max_hashes, len(match.group()))
    n = max_hashes + 1
    hashes = "#" * n
    return f'r{hashes}"{s}"{hashes}'


def rust_str(s: str) -> str:
    """Escape a string for a normal Rust string literal."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")


def fixtures(contract: dict) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    """Return positive, negative, evasion, cve_replay fixture lists."""
    return (
        contract.get("positive") or [],
        contract.get("negative") or [],
        contract.get("evasion") or [],
        contract.get("cve_replay") or [],
    )


def generate() -> str:
    lines: list[str] = [
        "//! Generated detector contract fixture runner.",
        "//!",
        "//! Regenerate: python3 scripts/generate_scanner_contract_tests.py",
        "",
        "use keyhog_core::{Chunk, ChunkMetadata};",
        "use keyhog_scanner::{CompiledScanner, GpuInitPolicy};",
        "use std::sync::LazyLock;",
        "",
        "fn scanner() -> &'static CompiledScanner {",
        "    static SCANNER: LazyLock<CompiledScanner> = LazyLock::new(|| {",
        "        let detectors = keyhog_core::load_detectors(crate::support::paths::detector_dir().as_path())",
        "            .expect(\"load detectors\");",
        "        CompiledScanner::compile_with_gpu_policy(detectors, GpuInitPolicy::ForceDisabled)",
        "            .expect(\"compile scanner without GPU\")",
        "    });",
        "    &SCANNER",
        "}",
        "",
        "macro_rules! positive_fixture {",
        "    ($name:ident, $detector:literal, $text:expr, $credential:expr) => {",
        "        #[test]",
        "        fn $name() {",
        "            let text: &str = $text;",
        "            let chunk = Chunk {",
        "                data: text.into(),",
        "                metadata: ChunkMetadata {",
        "                    source_type: \"contract\".into(),",
        "                    path: Some(concat!($detector, \".txt\").into()),",
        "                    ..Default::default()",
        "                },",
        "            };",
        "            let scanner = scanner();",
        "            scanner.clear_fragment_cache();",
        "            let expected: &str = $credential;",
        "            let matches = scanner.scan(&chunk);",
        "            let found: Vec<&str> = matches",
        "                .iter()",
        "                .map(|m| m.credential.as_ref())",
        "                .collect();",
        "            assert!(",
        "                found.iter().any(|c| *c == expected),",
        "                \"detector {} positive fixture must surface credential {}; text={:?}; credentials found={:?}\",",
        "                $detector, expected, text, found",
        "            );",
        "        }",
        "    };",
        "}",
        "",
        "macro_rules! negative_fixture {",
        "    ($name:ident, $detector:literal, $text:expr) => {",
        "        #[test]",
        "        fn $name() {",
        "            let text: &str = $text;",
        "            let chunk = Chunk {",
        "                data: text.into(),",
        "                metadata: ChunkMetadata {",
        "                    source_type: \"contract\".into(),",
        "                    path: Some(concat!($detector, \".txt\").into()),",
        "                    ..Default::default()",
        "                },",
        "            };",
        "            let scanner = scanner();",
        "            scanner.clear_fragment_cache();",
        "            let matches = scanner.scan(&chunk);",
        "            let detector_ids: Vec<&str> = matches",
        "                .iter()",
        "                .map(|m| m.detector_id.as_ref())",
        "                .collect();",
        "            assert!(",
        "                !detector_ids.iter().any(|id| *id == $detector),",
        "                \"detector {} negative fixture must not fire; text={:?}; detector ids found={:?}\",",
        "                $detector, text, detector_ids",
        "            );",
        "        }",
        "    };",
        "}",
        "",
        "macro_rules! contract_schema {",
        "    ($name:ident, $detector:literal, $service:literal, $severity:literal, $readme_claim:expr) => {",
        "        #[test]",
        "        fn $name() {",
        "            let id: &str = $detector;",
        "            let spec = keyhog_core::detector_spec_by_id(id)",
        "                .expect(\"contract detector must be embedded\");",
        "            assert_eq!(spec.id, id, \"contract detector_id must match embedded spec\");",
        "            assert_eq!(spec.service, $service, \"contract service must match embedded spec\");",
        "            assert_eq!(spec.severity.as_str(), $severity, \"contract severity must match embedded spec\");",
        "            let readme_claim: Option<&str> = $readme_claim;",
        "            if let Some(claimed) = readme_claim {",
        "                assert!(!claimed.is_empty(), \"readme_claim must be non-empty when present\");",
        "            }",
        "        }",
        "    };",
        "}",
        "",
    ]

    paths = sorted(CONTRACTS.glob("*.toml"))
    if not paths:
        raise RuntimeError(f"no contract TOMLs found in {CONTRACTS}")

    for path in paths:
        stem = path.stem
        safe_stem = safe_name(stem)
        raw = path.read_text(encoding="utf-8")
        contract = tomllib.loads(raw)

        detector_id = contract.get("detector_id", stem)
        service = contract.get("service", "")
        severity = contract.get("severity", "")
        readme_claim = contract.get("readme_claim")

        # Schema test per contract
        claim_expr = f'Some("{rust_str(readme_claim)}")' if readme_claim else "None"
        lines.append(
            f'contract_schema!({safe_stem}_schema, "{rust_str(detector_id)}", "{rust_str(service)}", "{rust_str(severity)}", {claim_expr});'
        )

        positives, negatives, evasions, cve_replays = fixtures(contract)

        for idx, fixture in enumerate(positives):
            text = fixture["text"]
            credential = fixture["credential"]
            name = f"{safe_stem}_positive_{idx}"
            lines.append(
                f'positive_fixture!({name}, "{rust_str(detector_id)}", {rust_raw(text)}, {rust_raw(credential)});'
            )

        for idx, fixture in enumerate(negatives):
            text = fixture["text"]
            name = f"{safe_stem}_negative_{idx}"
            lines.append(
                f'negative_fixture!({name}, "{rust_str(detector_id)}", {rust_raw(text)});'
            )

        for idx, fixture in enumerate(evasions):
            text = fixture["text"]
            credential = fixture["credential"]
            name = f"{safe_stem}_evasion_{idx}"
            lines.append(
                f'positive_fixture!({name}, "{rust_str(detector_id)}", {rust_raw(text)}, {rust_raw(credential)});'
            )

        for idx, fixture in enumerate(cve_replays):
            text = fixture["text"]
            credential = fixture["credential"]
            name = f"{safe_stem}_cve_{idx}"
            lines.append(
                f'positive_fixture!({name}, "{rust_str(detector_id)}", {rust_raw(text)}, {rust_raw(credential)});'
            )

    lines.append("")
    return "\n".join(lines)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(generate(), encoding="utf-8")
    subprocess.run(
        ["rustfmt", "--edition", "2021", str(OUT_FILE)],
        check=True,
        cwd=ROOT,
    )
    print("generated:", OUT_FILE)


if __name__ == "__main__":
    main()
