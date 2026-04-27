#!/usr/bin/env python3
"""Fix broken context-anchored detector regex separators in detector TOML files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DETECTORS_DIR = ROOT / "detectors"

SEPARATOR_PAIRS = (
    (r"[_=:\\s\"'']+", r"[_a-zA-Z0-9]*[=:\\s\"'']+"),
    (r"[_=:\\s\"']+", r"[_a-zA-Z0-9]*[=:\\s\"']+"),
)


@dataclass(frozen=True)
class FileFixResult:
    """Summary of replacements applied to a single detector file."""

    path: Path
    replacements: int


def _rewrite_regex_line(line: str) -> tuple[str, int]:
    stripped = line.lstrip()
    if not stripped.startswith("regex = "):
        return line, 0

    quote_index = line.find('"')
    quote_char = '"'
    if quote_index == -1:
        quote_index = line.find("'")
        quote_char = "'"
    if quote_index == -1:
        return line, 0

    line_end = "\n" if line.endswith("\n") else ""
    content_end = len(line) - len(line_end)
    if content_end <= quote_index + 1 or line[content_end - 1] != quote_char:
        return line, 0

    body = line[quote_index + 1 : content_end - 1]
    if not body.startswith("(?:"):
        return line, 0

    separator_start = -1
    broken_separator = ""
    fixed_separator = ""
    for candidate_broken, candidate_fixed in SEPARATOR_PAIRS:
        start = body.find(candidate_broken)
        if start != -1 and (separator_start == -1 or start < separator_start):
            separator_start = start
            broken_separator = candidate_broken
            fixed_separator = candidate_fixed

        start = body.find(candidate_fixed)
        if start != -1 and (separator_start == -1 or start < separator_start):
            separator_start = start
            broken_separator = candidate_broken
            fixed_separator = candidate_fixed

    if separator_start == -1:
        return line, 0

    if body.startswith(fixed_separator, separator_start):
        current_separator = fixed_separator
    else:
        current_separator = broken_separator

    suffix = body[separator_start + len(current_separator) :]
    should_fix = suffix.startswith("(") and not suffix.startswith("(?:")
    desired_separator = fixed_separator if should_fix else broken_separator

    if current_separator == desired_separator:
        return line, 0

    new_body = (
        body[:separator_start]
        + desired_separator
        + body[separator_start + len(current_separator) :]
    )
    new_line = f"{line[:quote_index + 1]}{new_body}{quote_char}{line_end}"
    return new_line, 1


def _fix_file(path: Path) -> FileFixResult | None:
    original = path.read_text(encoding="utf-8")
    replacements = 0
    updated_lines: list[str] = []

    for line in original.splitlines(keepends=True):
        updated_line, line_replacements = _rewrite_regex_line(line)
        updated_lines.append(updated_line)
        replacements += line_replacements

    if replacements == 0:
        return None

    path.write_text("".join(updated_lines), encoding="utf-8")
    return FileFixResult(path=path, replacements=replacements)


def main() -> int:
    results = []
    for path in sorted(DETECTORS_DIR.glob("*.toml")):
        result = _fix_file(path)
        if result is not None:
            results.append(result)

    total_replacements = sum(result.replacements for result in results)
    print(
        f"Fixed {len(results)} detector files with {total_replacements} separator replacement(s)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
