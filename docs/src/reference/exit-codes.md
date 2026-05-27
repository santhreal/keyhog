# Exit codes

KeyHog uses exit codes to signal scan outcomes. Stable across versions;
consumers (CI gates, pre-commit hooks, IDE plugins) can rely on them.

| Exit | Meaning                                                            |
|------|--------------------------------------------------------------------|
| `0`  | Scan completed, zero findings emitted.                             |
| `1`  | Scan completed, one or more findings emitted (unverified or verified-live). |
| `2`  | Runtime error: bad CLI args, config parse failure, I/O error, panic, etc. |
| `11` | Scanner thread panicked. Distinct from `2` so CI can distinguish a code bug from a config error. |

## `0` (clean)

Use case: a CI step like `keyhog scan .` exits 0 when the working tree
is clean. The job stays green.

`--verify` does NOT change the exit code on its own. A scan that finds
a credential but verifies it as dead still exits `1` (the credential
was in the file, even if the API rejects it). To gate ONLY on live
credentials:

```sh
keyhog scan . --verify --format json \
  | jq -e 'any(.verification == "verified-live")'
```

`jq -e` exits non-zero when the predicate is false.

## `1` (findings present)

The most common non-zero. CI fails, pre-commit hook blocks the commit,
PR check turns red. Findings get printed to stdout in whatever format
`--format` selected.

To distinguish "findings, but all dead" from "findings, some live"
without parsing JSON:

```sh
if ! keyhog scan . --verify --quiet --format ndjson \
     | grep -q 'verified-live'; then
  echo "No live credentials found."
fi
```

## `2` (runtime error)

Things that exit `2`:

- Unknown CLI flag.
- `.keyhog.toml` parse error.
- Detector load failure for a specific TOML (with a stderr warning;
  the rest of the scan continues but exits 2 at the end).
- `--baseline <FILE>` where FILE doesn't exist or isn't valid JSON.
- A source backend failure (e.g. `--git-history` on a non-git dir).
- Network error during `--verify` is NOT a `2`; it's a `verification-error`
  marker per finding and the scan exits `1` if any unverified-live
  findings exist.

Stderr carries the error message. Stdout may have partial output
depending on where the error happened.

## `11` (scanner panic)

A panic inside a scanner thread (regex compile bug, OOM in a windowed
chunk, etc.). The scan was incomplete; the count of findings emitted
is NOT trustworthy. CI should treat this as "investigate" rather
than "ship anyway because exit 11 != 1".

The reason this is `11` rather than `2`:

- A panic is a code bug worth surfacing distinctly.
- Some CIs (older Jenkins, certain shell wrappers) collapse `2` with
  "command not found" or other ambient errors. `11` is unambiguous.
- A future expansion of error categories (`12` = OOM-killed, `13` =
  timeout-exceeded, etc.) is possible without renumbering existing
  codes.

## Composing in shell

```sh
set -e
keyhog scan .                # exit 1 stops the shell here
```

Or to handle the non-zero explicitly:

```sh
keyhog scan . || rc=$?
case "$rc" in
  0|"")  echo "clean" ;;
  1)     echo "findings -> opening PR comment" ;;
  2)     echo "config error -> failing build" ;;
  11)    echo "scanner panic -> paging on-call" ;;
  *)     echo "unknown exit $rc" ;;
esac
```

## What you can't do

- No `--exit-zero` flag. KeyHog deliberately does not provide a way
  to lie to CI about findings. If you need to override (e.g. "this
  finding is accepted, ship anyway"), suppress it by hash in
  `.keyhog.toml` instead. The exit code then reflects truth: there
  are no UN-suppressed findings, so it's `0`.
