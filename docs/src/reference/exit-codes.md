# Exit codes

KeyHog uses exit codes to signal scan outcomes. Stable across versions;
consumers (CI gates, pre-commit hooks, IDE plugins) can rely on them.

| Exit | Meaning                                                            |
|------|--------------------------------------------------------------------|
| `0`  | Scan completed, zero findings.                                     |
| `1`  | Findings present, NONE confirmed live (unverified, or verified-dead). |
| `2`  | User error (bad input): unknown CLI flag, `.keyhog.toml` parse failure, a missing or invalid `--baseline` file, an unreadable / non-repo source you named (`--git-history` / `--git-staged` outside a git repo), a detector TOML that failed to load, or `--require-gpu` with no GPU present. Also any not-found / permission-denied I/O error. |
| `3`  | System error: the local environment failed in a way no flag change fixes — a low-level I/O failure that is *not* not-found / permission-denied, or a hardware / GPU **init** failure. Retry or route differently from `2`. |
| `4`  | Health/self-test failure: `keyhog doctor` unhealthy, `keyhog repair` could not restore a working binary, `keyhog backend` self-test failed. |
| `10` | **LIVE credentials confirmed** (a `--verify` scan where the vendor API accepted a found secret) - the highest-severity gate. Also returned by `keyhog update --check` when a newer release exists. |
| `11` | Scanner thread panicked. The finding count is NOT trustworthy - investigate, don't ship. Distinct from `2`/`3` so CI can tell a code bug from a config error. |
| `130`| Interrupted (SIGINT / Ctrl-C).                                     |

## `0` (clean)

Use case: a CI step like `keyhog scan .` exits 0 when the working tree
is clean. The job stays green.

With `--verify`, the exit code escalates when a credential is confirmed
live: a found secret the vendor API accepts exits `10`, while a found
secret that verifies dead (or wasn't verified) exits `1`. So gating ONLY
on live credentials needs no JSON parsing - branch on the exit code:

```sh
keyhog scan . --verify
case $? in
  0)  echo "clean" ;;
  10) echo "LIVE credentials present - block + page" ; exit 1 ;;
  1)  echo "findings, none confirmed live" ;;
esac
```

## `1` (findings present)

The most common non-zero. CI fails, pre-commit hook blocks the commit,
PR check turns red. Findings get printed to stdout in whatever format
`--format` selected.

Exit `1` means findings exist but, under `--verify`, none were confirmed
live. A scan that confirms a live credential exits `10` instead (see
below) - so "findings but all dead" vs "some live" is just `1` vs `10`,
no JSON parsing required.

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

## `3` (system error)

A failure the operator can't fix by correcting a flag: a low-level I/O
error that is NOT not-found / permission-denied (those map to `2`), or a
hardware / GPU **init** failure. A source backend you named that can't
read its input (a non-repo for `--git-history`, a missing/garbage
`--baseline`) is *user* error and exits `2`, not `3` — see above. A
detector TOML that fails to load is likewise `2`. Distinct from `2` so a
pipeline can retry/route differently. Stderr carries the cause.

## `4` (health / self-test failure)

Returned by the maintenance subcommands, not by `scan`: `keyhog doctor`
when the install fails its end-to-end self-test, `keyhog repair` when it
could not restore a working binary, and `keyhog backend` when its
self-test fails. A health monitor can treat `4` as "binary present but
not trustworthy." Use `keyhog backend --self-test --json` on self-hosted
GPU runners when CI needs stable fields instead of stderr scraping.

## `10` (live credentials, or update available)

The highest-severity scan outcome: a `--verify` scan where the vendor
API **accepted** a found secret - it is real and exfil-capable right now.
Gate hard on this:

```sh
keyhog scan . --verify || rc=$?
[ "${rc:-0}" = "10" ] && { echo "::error::live credential confirmed"; exit 1; }
```

`keyhog update --check` reuses `10` to mean "a newer release exists"
(exit `0` = already current), so a self-update cron can branch on it.

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
keyhog scan . --verify || rc=$?
case "$rc" in
  0|"")  echo "clean" ;;
  1)     echo "findings (none live) -> opening PR comment" ;;
  10)    echo "LIVE credentials -> block + page on-call" ;;
  2)     echo "user error (bad flag/config) -> failing build" ;;
  3)     echo "system error -> retry / investigate" ;;
  11)    echo "scanner panic -> paging on-call" ;;
  130)   echo "interrupted" ;;
  *)     echo "unknown exit $rc" ;;
esac
```

## What you can't do

- No `--exit-zero` flag. KeyHog deliberately does not provide a way
  to lie to CI about findings. If you need to override (e.g. "this
  finding is accepted, ship anyway"), suppress it by hash in
  `.keyhog.toml` instead. The exit code then reflects truth: there
  are no UN-suppressed findings, so it's `0`.
