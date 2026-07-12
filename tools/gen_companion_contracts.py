#!/usr/bin/env python3
"""Generate companion contract TOMLs for detectors with [[detector.companions]]."""

from __future__ import annotations

import argparse
import pathlib
import random
import re
import sys
from typing import Optional

REPO = pathlib.Path(__file__).resolve().parent.parent
DETECTORS = REPO / "detectors"
COMPANION_CONTRACTS = REPO / "crates" / "scanner" / "tests" / "contracts" / "companion"

sys.path.insert(0, str(REPO / "tools"))
from gen_contracts import (  # noqa: E402
    _det_rng,
    _expand_charclass,
    _toml_str,
    load_toml,
    synthesize_positive,
)


def _synth_from_class(charclass: str, length: int, rng: random.Random) -> str:
    chars = _expand_charclass(charclass)
    safe = [c for c in chars if c.isalnum() or c in "_-./+="] or chars
    return "".join(rng.choice(safe) for _ in range(length))


def _pick_alt(alt: str, rng: random.Random) -> str:
    opts = [o.strip() for o in alt.split("|") if o.strip()]
    opts = [o for o in opts if not any(x in o for x in "?*+")]
    if not opts:
        return ""
    opts.sort(key=len, reverse=True)
    return opts[rng.choice(range(min(3, len(opts))))]


def _literalize_prefix(regex: str, rng: random.Random) -> str:
    """Turn regex prefix before first capture group into a readable anchor string."""
    s = regex
    if s.startswith("(?i)"):
        s = s[4:]
    if s.startswith("(?i:"):
        s = s[4:]
    out: list[str] = []
    i = 0
    while i < len(s):
        if s[i] == "(":
            if s.startswith("(?:", i):
                depth = 1
                j = i + 3
                while j < len(s) and depth:
                    if s[j] == "(":
                        depth += 1
                    elif s[j] == ")":
                        depth -= 1
                    j += 1
                inner = s[i + 3 : j - 1]
                optional = j < len(s) and s[j] == "?"
                if optional and rng.random() < 0.3:
                    i = j + 1
                    continue
                picked = _pick_alt(inner, rng)
                out.append(picked.replace("\\s", " ").replace("\\.", "."))
                i = j + (1 if optional else 0)
                continue
            break
        if s[i] == "[":
            j = s.index("]", i + 1)
            cc = s[i + 1 : j]
            optional = j + 1 < len(s) and s[j + 1] in "?*+"
            if not optional:
                chars = _expand_charclass(cc)
                pref = [c for c in chars if c.isalnum() or c in "_=:-"] or chars
                out.append(rng.choice(pref))
            i = j + (2 if optional else 1)
            continue
        if s[i] == "\\":
            if i + 1 < len(s):
                esc = s[i + 1]
                mapping = {"s": " ", ".": ".", "-": "-", "_": "_"}
                out.append(mapping.get(esc, esc))
                i += 2
                continue
        if s[i] in ")?*+":
            i += 1
            continue
        if s[i] == "^":
            i += 1
            continue
        out.append(s[i])
        i += 1
    text = "".join(out)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _first_capture(regex: str) -> Optional[tuple[str, int, Optional[int]]]:
    """Return (charclass, min_len, max_len) for first (...) capture group."""
    s = regex
    if s.startswith("(?i)"):
        s = s[4:]
    depth = 0
    i = 0
    while i < len(s):
        if s.startswith("(?:", i):
            depth += 1
            i += 3
            continue
        if s[i] == "(" and not s.startswith("(?=", i) and not s.startswith("(?!", i):
            if depth == 0:
                j = i + 1
                d = 1
                while j < len(s) and d:
                    if s[j] == "(":
                        d += 1
                    elif s[j] == ")":
                        d -= 1
                    j += 1
                inner = s[i + 1 : j - 1]
                m = re.search(r"\[(?P<cc>[^\]]+)\]\{(?P<low>\d+)(?:,(?P<high>\d+))?\}", inner)
                if m:
                    low = int(m.group("low"))
                    high = int(m.group("high")) if m.group("high") else low
                    return m.group("cc"), low, high if m.group("high") else None
                m2 = re.search(r"\[(?P<cc>[^\]]+)\](?:\{(?P<low>\d+)(?:,(?P<high>\d+))?\})?", inner)
                if m2:
                    low = int(m2.group("low") or "1")
                    high = int(m2.group("high")) if m2.group("high") else low
                    return m2.group("cc"), low, high if m2.group("high") else None
                return None
            depth += 1
        i += 1
    return None


def synthesize_clean_match(regex: str, seed: str) -> Optional[tuple[str, str]]:
    """Build KEY=VALUE style text and captured value."""
    rng = _det_rng(seed)
    try:
        compiled = re.compile(regex, re.IGNORECASE if "(?i)" in regex[:4] else 0)
    except re.error:
        return None

    cap = _first_capture(regex)
    prefix = _literalize_prefix(regex, rng)
    if cap:
        cc, low, high = cap
        length = high or low
        body = _synth_from_class(cc, length, rng)
    else:
        body = _synth_from_class("a-zA-Z0-9", 32, rng)

    candidates: list[str] = []
    if prefix:
        candidates.extend(
            [
                f"{prefix}={body}",
                f"{prefix}: {body}",
                f"{prefix}=\"{body}\"",
                f"{prefix} = {body}",
            ]
        )
    candidates.extend([body, f"KEY={body}"])

    for text in candidates:
        m = compiled.search(text)
        if m is None:
            continue
        captured = m.group(1) if m.groups() else m.group(0)
        if captured and len(captured) >= 2 and captured.isprintable():
            return text, captured

    # fallback to gen_contracts synthesis, cleaned
    alt = synthesize_positive(regex, seed)
    if alt:
        text, cred = alt
        if all(c.isprintable() or c in "\n\t" for c in text):
            m = compiled.search(text)
            if m:
                captured = m.group(1) if m.groups() else m.group(0)
                return text, captured or cred
    return None


def _toml_key(k: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_-]+", k):
        return k
    return _toml_str(k)


def _toml_map(d: dict[str, str]) -> str:
    if not d:
        return "{}"
    parts = [f"{_toml_key(k)} = {_toml_str(v)}" for k, v in sorted(d.items())]
    return "{ " + ", ".join(parts) + " }"


def build_companion_contract(det: dict, detector_id: str) -> Optional[str]:
    block = det.get("detector", {})
    patterns = block.get("patterns", [])
    companions = block.get("companions", [])
    if not patterns or not companions:
        return None

    primary = None
    for i, p in enumerate(patterns):
        result = synthesize_clean_match(p.get("regex", ""), f"{detector_id}-pri-{i}")
        if result is not None:
            primary = result
            break
    if primary is None:
        return None

    primary_text, _ = primary
    companion_lines: list[str] = []
    expected_companions: dict[str, str] = {}

    for i, comp in enumerate(companions):
        regex = comp.get("regex", "")
        name = comp.get("name", f"companion_{i}")
        result = synthesize_clean_match(regex, f"{detector_id}-comp-{name}-{i}")
        if result is None:
            return None
        line_text, captured = result
        companion_lines.append(line_text)
        expected_companions[name] = captured

    any_required = any(c.get("required", False) for c in companions)
    service = block.get("service", "unknown")
    severity = block.get("severity", "high")
    comp_names = ", ".join(c.get("name", "?") for c in companions)

    positive_both = primary_text + "\n" + "\n".join(companion_lines)
    negative_text = "\n".join(companion_lines)

    if any_required:
        primary_only_findings = "[]"
        primary_only_reason = (
            f"Missing required companion(s) ({comp_names}); scanner must suppress match."
        )
    else:
        primary_only_findings = f"[{_toml_str(detector_id)}]"
        primary_only_reason = (
            f"Primary found without companion {comp_names}; verification must NOT proceed."
        )

    det_id_str = _toml_str(detector_id)
    return f"""schema_version = 1
detector_id = {det_id_str}
service = {_toml_str(service)}
severity = {_toml_str(severity)}

[positive_with_companion]
text = {_toml_str(positive_both)}
expected_findings = [{det_id_str}]
expected_companions = {_toml_map(expected_companions)}
reason = {_toml_str(f"Primary paired with companion(s) {comp_names}.")}

[positive_primary_only]
text = {_toml_str(primary_text)}
expected_findings = {primary_only_findings}
must_not_verify = true
reason = {_toml_str(primary_only_reason)}

[negative_companion_lookalike]
text = {_toml_str(negative_text)}
expected_findings = []
reason = "Companion lookalike(s) without primary."
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--only", default=None)
    ap.add_argument("--force", action="store_true", help="Overwrite existing contracts")
    args = ap.parse_args()

    existing = {p.stem for p in COMPANION_CONTRACTS.glob("*.toml")}
    targets: list[pathlib.Path] = []
    for p in sorted(DETECTORS.glob("*.toml")):
        if "[[detector.companions]]" not in p.read_text():
            continue
        if p.stem in existing and not args.force:
            continue
        if args.only:
            import fnmatch
            if not fnmatch.fnmatch(p.stem, args.only):
                continue
        targets.append(p)

    print(f"targets: {len(targets)}", file=sys.stderr)
    written = 0
    skipped: list[str] = []
    for det_path in targets:
        try:
            det = load_toml(det_path)
        except Exception as e:
            skipped.append(f"{det_path.stem} (parse: {e})")
            continue
        detector_id = det.get("detector", {}).get("id", det_path.stem)
        toml = build_companion_contract(det, detector_id)
        if toml is None:
            skipped.append(detector_id)
            continue
        if args.write:
            out = COMPANION_CONTRACTS / f"{detector_id}.toml"
            out.write_text(toml)
        written += 1

    print(f"written: {written}, skipped: {len(skipped)}", file=sys.stderr)
    if skipped:
        print("skipped:", ", ".join(skipped), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
