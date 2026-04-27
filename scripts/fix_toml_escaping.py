#!/usr/bin/env python3
"""Fix TOML escaping issues in detector files.
Strategy: convert regex values to properly escaped basic strings."""

import os
import sys
import re

detectors_dir = sys.argv[1] if len(sys.argv) > 1 else "detectors"
fixed = 0
still_broken = 0

for fname in sorted(os.listdir(detectors_dir)):
    if not fname.endswith(".toml"):
        continue
    path = os.path.join(detectors_dir, fname)

    try:
        import tomllib
        with open(path, "rb") as f:
            tomllib.load(f)
        continue
    except Exception:
        pass

    with open(path) as f:
        content = f.read()

    lines = content.split("\n")
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("regex") and "=" in stripped:
            key, _, val = line.partition("=")
            val = val.strip()

            # Extract the raw regex content regardless of quoting
            if val.startswith("'") and "'" in val[1:]:
                # Literal string - extract content
                inner = val[1:val.rindex("'")]
            elif val.startswith('"'):
                # Basic string - find the matching end quote
                inner = val[1:]
                if inner.endswith('"'):
                    inner = inner[:-1]
                # Unescape any already-escaped sequences
                inner = inner.replace("\\\\", "\x00BS\x00")
                inner = inner.replace("\\", "")
                inner = inner.replace("\x00BS\x00", "\\")
            else:
                new_lines.append(line)
                continue

            # Now properly escape for TOML basic string:
            # In TOML basic strings, only \ and " need escaping
            escaped = inner.replace("\\", "\\\\").replace('"', '\\"')
            new_lines.append(f'{key}= "{escaped}"')
            continue
        new_lines.append(line)

    with open(path, "w") as f:
        f.write("\n".join(new_lines))

    try:
        with open(path, "rb") as f:
            tomllib.load(f)
        fixed += 1
    except Exception as e:
        print(f"  STILL BROKEN: {fname}: {e}")
        still_broken += 1

print(f"Fixed: {fixed}, Still broken: {still_broken}")
