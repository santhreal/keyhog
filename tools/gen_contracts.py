#!/usr/bin/env python3
"""Auto-generate per-detector test contracts.

Walks `detectors/` and `crates/scanner/tests/contracts/`. For every
detector with NO contract, generate a minimal contract with:
  * 2 positives (env-var anchor, code-style anchor)
  * 2 negatives (placeholder + EXAMPLE-tagged)

Body synthesis: parses the FIRST regex to find a literal prefix
or keyword alternation + captured body, generates a satisfying
string. Patterns too complex (companions, multi-segment anchors)
are skipped (they get hand-written).
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import random
import re
import string
import sys
from typing import Optional

REPO = pathlib.Path(__file__).resolve().parent.parent
DETECTORS = REPO / "detectors"
CONTRACTS = REPO / "crates" / "scanner" / "tests" / "contracts"


def load_toml(path: pathlib.Path) -> dict:
    if sys.version_info >= (3, 11):
        import tomllib as _toml
        with open(path, "rb") as f:
            return _toml.load(f)
    import tomli as _toml  # type: ignore
    with open(path, "rb") as f:
        return _toml.load(f)


def _det_rng(seed_str: str) -> random.Random:
    h = hashlib.sha256(seed_str.encode()).digest()
    return random.Random(int.from_bytes(h[:8], "big"))


def _expand_charclass(spec: str) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(spec):
        c = spec[i]
        if i + 2 < len(spec) and spec[i + 1] == "-":
            lo, hi = c, spec[i + 2]
            if ord(hi) >= ord(lo):
                out.extend(chr(x) for x in range(ord(lo), ord(hi) + 1))
                i += 3
                continue
        if c == "\\" and i + 1 < len(spec):
            esc = spec[i + 1]
            if esc == "d":
                out.extend(string.digits)
            elif esc == "w":
                out.extend(string.ascii_letters + string.digits + "_")
            elif esc == "s":
                out.append(" ")
            else:
                out.append(esc)
            i += 2
            continue
        out.append(c)
        i += 1
    # Dedup, keep deterministic order
    seen: set[str] = set()
    ordered: list[str] = []
    for ch in out:
        if ch not in seen:
            seen.add(ch)
            ordered.append(ch)
    return ordered


def _synth_body(charclass: str, length: int, rng: random.Random) -> str:
    chars = _expand_charclass(charclass)
    if not chars:
        chars = list(string.ascii_letters + string.digits)
    # Prefer alphanumerics first for the body; only fall back to symbols
    safe = [c for c in chars if c.isalnum() or c in "_-"] or chars
    return "".join(rng.choice(safe) for _ in range(length))


# Patterns we attempt to synthesize.
# Group names: prefix, charclass, low, high (optional).
_SHAPE_NO_ANCHOR = re.compile(
    r"^(?P<prefix>[A-Za-z0-9_]{1,40})\[(?P<charclass>[^\]]+)\]\{(?P<low>\d+)(?:,(?P<high>\d+))?\}$"
)

# (?:K1|K2|...)<literal_suffix>[sep]+[?( ]?[body]{N[,M]}
# `literal_suffix` is the optional anchor tail (e.g. `_API_KEY`,
# `[_\s]*(?:API[_\s]*)?KEY[_\s]*`). We strip optional `(?:...)?`
# groups and `[charclass]*?` in the suffix.
_SHAPE_ANCHOR_THEN_BODY = re.compile(
    r"\(\?:(?P<keywords>[^)]+)\)(?P<suffix>(?:\[[^\]]*\][*?+]?|\(\?:[^)]*\)\??|[^[(\s]){0,80})"
    r"\s*\[(?P<sep>[^\]]*)\][+*]?"
    r"\s*\(?\??\[?(?P<charclass>[^\]]+)\]\{(?P<low>\d+)(?:,(?P<high>\d+))?\}"
)


def _pick_alternation(alt_body: str, rng: random.Random) -> str:
    options = [o.strip() for o in alt_body.split("|") if o.strip()]
    options = [o for o in options if "?" not in o and "*" not in o]
    if not options:
        return ""
    options.sort(key=len, reverse=True)
    return options[0]


def _toml_str(s: str) -> str:
    """Encode `s` as a TOML basic string with safe escaping."""
    out = ['"']
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04X}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def synthesize_positive(regex: str, detector_id: str) -> Optional[tuple[str, str]]:
    """Return (positive_text, surfaced_credential) such that `positive_text`
    matches `regex` and `surfaced_credential` is the value the detector will
    extract (the captured group body for keyword-anchored regexes, or the
    whole match for prefix regexes). Returns None if we can't synthesize."""
    rng = _det_rng(f"{detector_id}-syn-1")
    cleaned = regex.strip()
    if cleaned.startswith("(?i)"):
        cleaned = cleaned[4:]

    # Try simple PREFIX + body (e.g. `ghs_[a-zA-Z0-9]{36}`)
    m = _SHAPE_NO_ANCHOR.match(cleaned)
    if m:
        prefix = m.group("prefix")
        cc = m.group("charclass")
        low = int(m.group("low"))
        body = _synth_body(cc, low, rng)
        candidate = prefix + body
        try:
            if re.search(regex, candidate):
                return candidate, candidate
        except re.error:
            pass

    # Try keyword-anchored: (?:K1|K2|...)<literal_suffix>[sep]+([body]{N,M})
    m = _SHAPE_ANCHOR_THEN_BODY.search(cleaned)
    if m:
        kws = m.group("keywords")
        suffix = m.group("suffix") or ""
        cc = m.group("charclass")
        low = int(m.group("low"))
        anchor_alt = _pick_alternation(kws, rng)
        if not anchor_alt:
            return None
        anchor_full = anchor_alt + _strip_regex_groups(suffix, rng)
        body = _synth_body(cc, low, rng)
        candidates = [
            (anchor_full + "=" + body, body),
            (anchor_full + ":" + body, body),
            (anchor_full + ": " + body, body),
            (anchor_full + "=\"" + body + "\"", body),
            (anchor_full + "=\"" + body + "\"\n", body),
            (anchor_full + "='" + body + "'", body),
            (anchor_full.upper() + "=" + body, body),
            (anchor_full + " = " + body, body),
            (anchor_full + " = \"" + body + "\"", body),
        ]
        try:
            for text, cred in candidates:
                if re.search(regex, text):
                    return text, cred
        except re.error:
            pass

    # Fallback: use rstr with constrained alphabet via post-processing.
    # rstr emits non-printable garbage for `\s` and `[=:\s"']`: replace
    # non-printable chars with their printable equivalent, then validate.
    try:
        import rstr  # type: ignore
    except ImportError:
        return None
    try:
        compiled = re.compile(regex)
    except re.error:
        return None
    for attempt in range(8):
        try:
            raw = rstr.xeger(regex)
        except Exception:
            return None
        # Replace whitespace and quotes with their canonical printable forms
        cleaned_text = []
        for ch in raw:
            if ch == "\x00":
                cleaned_text.append("=")
            elif ch in "\t\n\r\x0b\x0c":
                cleaned_text.append(" ")
            elif not ch.isprintable():
                cleaned_text.append("=")
            else:
                cleaned_text.append(ch)
        text = "".join(cleaned_text)
        match = compiled.search(text)
        if match is None:
            continue
        # Surfaced credential = group(1) if it exists, else whole match
        if match.groups():
            cred = match.group(1)
        else:
            cred = match.group(0)
        if cred is None or len(cred) < 4:
            continue
        # Reject if `text` or `cred` contains TOML serialization hazards:
        # triple-quote, backslash, or non-printable / control chars.
        if "'''" in text or "'''" in cred:
            continue
        if "\\" in cred or any(c in cred for c in "\x00\x01\x02"):
            continue
        if "\\" in text or any(not c.isprintable() and c not in " \t" for c in text):
            continue
        return text, cred
    return None


def _strip_regex_groups(suffix: str, rng: random.Random) -> str:
    """Strip nested (?:...) optionality and `[charclass]?` from suffix,
    returning a literal string that satisfies the suffix when concatenated
    with the anchor."""
    out = []
    i = 0
    while i < len(suffix):
        if suffix.startswith("(?:", i):
            # Find matching closing paren
            depth = 1
            j = i + 3
            while j < len(suffix) and depth > 0:
                if suffix[j] == "(":
                    depth += 1
                elif suffix[j] == ")":
                    depth -= 1
                j += 1
            inner = suffix[i + 3 : j - 1]
            # check if group is optional (followed by `?`)
            optional = j < len(suffix) and suffix[j] == "?"
            if optional:
                # Skip optional groups entirely (simpler satisfaction).
                i = j + 1
                continue
            picked = _pick_alternation(inner, rng) or ""
            out.append(picked)
            i = j
            continue
        if suffix.startswith("[", i):
            # Find closing `]`
            j = suffix.index("]", i + 1)
            cc = suffix[i + 1 : j]
            optional = j + 1 < len(suffix) and suffix[j + 1] in "?*"
            if optional:
                # Drop optional char class entirely
                i = j + 2
                continue
            chars = _expand_charclass(cc)
            # Prefer underscore or letter to keep readable
            preferred = [c for c in chars if c == "_" or c.isalpha()] or chars
            out.append(preferred[0])
            i = j + 1
            continue
        if suffix[i] == "\\" and i + 1 < len(suffix):
            out.append(suffix[i + 1])
            i += 2
            continue
        out.append(suffix[i])
        i += 1
    return "".join(out)


def build_contract_toml(detector: dict, detector_id: str) -> Optional[str]:
    block = detector.get("detector", {})
    patterns = block.get("patterns", [])
    keywords = block.get("keywords", [])
    severity = block.get("severity", "high")
    service = block.get("service", "unknown")

    if not patterns:
        return None
    if any(c.get("required") for c in block.get("companions", [])):
        # required companions need hand-written contracts.
        return None

    synth = None
    used_regex = None
    for p in patterns:
        rgx = p.get("regex", "")
        result = synthesize_positive(rgx, detector_id)
        if result is not None:
            synth = result
            used_regex = rgx
            break
    if synth is None:
        return None

    positive_text, surfaced_credential = synth

    # Build a second positive: quoted variant if the original wasn't quoted.
    # If we can't build one that matches, skip.
    if '"' in positive_text:
        positive2_text = positive_text  # already quoted
    else:
        candidate2 = positive_text.replace("=", "=\"", 1) + "\""
        if re.search(used_regex, candidate2):
            positive2_text = candidate2
        else:
            positive2_text = positive_text

    # Negatives: same anchor + placeholder/EXAMPLE body.
    # Surface the credential body in the negative too; the suppression
    # gate must drop it.
    neg_body_placeholder = "YOUR_API_KEY_HERE_PLACEHOLDER_VALUE"
    neg_body_example = (
        surfaced_credential[:5] + "EXAMPLEEXAMPLE" + surfaced_credential[-5:]
        if len(surfaced_credential) > 10
        else surfaced_credential + "_EXAMPLE"
    )
    # Try to substitute the credential body in the positive with the negatives.
    neg_text1 = positive_text.replace(surfaced_credential, neg_body_placeholder, 1)
    neg_text2 = positive_text.replace(surfaced_credential, neg_body_example, 1)

    toml = f"""schema_version = 1
detector_id = {_toml_str(detector_id)}
service = {_toml_str(service)}
severity = {_toml_str(severity)}

# Auto-generated contract (gen_contracts.py). Hand-edit to add more
# real-world shapes; the auto-stub validates the detector at
# least fires on its canonical-shape anchor + body.

[[positive]]
text = {_toml_str(positive_text)}
credential = {_toml_str(surfaced_credential)}
reason = "Canonical anchor + synthesized body satisfying detector's primary regex."

[[positive]]
text = {_toml_str(positive2_text)}
credential = {_toml_str(surfaced_credential)}
reason = "Quoted-value variant of the canonical positive."

[[negative]]
text = {_toml_str(neg_text1)}
reason = "Placeholder-keyword body (suppression gate matches PLACEHOLDER prefix)."

[[negative]]
text = {_toml_str(neg_text2)}
reason = "EXAMPLE token marker inside the body (suppression gate strips it)."
"""
    return toml


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write", action="store_true", help="Write the contracts (default: dry-run)")
    ap.add_argument("--limit", type=int, default=None, help="Only process the first N detectors")
    ap.add_argument("--only", default=None, help="Only process detectors matching this glob")
    args = ap.parse_args()

    existing = {p.stem for p in CONTRACTS.glob("*.toml")}
    detectors = sorted(DETECTORS.glob("*.toml"))
    if args.only:
        import fnmatch
        detectors = [d for d in detectors if fnmatch.fnmatch(d.stem, args.only)]
    print(f"detectors: {len(detectors)}, existing contracts: {len(existing)}", file=sys.stderr)

    missing = [d for d in detectors if d.stem not in existing]
    if args.limit:
        missing = missing[: args.limit]
    print(f"missing contracts: {len(missing)}", file=sys.stderr)

    n_written = 0
    n_skipped = 0
    skipped_ids: list[str] = []
    for det_path in missing:
        try:
            det = load_toml(det_path)
        except Exception as e:
            print(f"  SKIP {det_path.name} (parse error: {e})", file=sys.stderr)
            skipped_ids.append(det_path.stem)
            n_skipped += 1
            continue
        detector_id = det.get("detector", {}).get("id", det_path.stem)
        toml = build_contract_toml(det, detector_id)
        if toml is None:
            n_skipped += 1
            skipped_ids.append(detector_id)
            continue
        if args.write:
            out_path = CONTRACTS / f"{detector_id}.toml"
            out_path.write_text(toml)
        n_written += 1

    print(f"\nwould-write: {n_written}, skipped: {n_skipped}", file=sys.stderr)
    if skipped_ids and not args.write:
        print(f"\nFirst 20 skipped: {skipped_ids[:20]}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
