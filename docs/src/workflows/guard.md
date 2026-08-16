# Perpetual repository and filesystem guard

The guard is a daemon-resident runtime that registers Git repositories and
filesystem trees as guarded roots. Each root has a 7-state machine, a clean
attestation cache, and a policy identity that binds attestations to the exact
detector corpus, suppression rules, and configuration the daemon was started
with.

Guard requires the Unix-domain daemon transport. On Windows, `keyhog guard`
exits with an unsupported-platform error; use `keyhog scan <path>` in process.

The guard supplements staged and working-tree scans. It does not replace them.
A commit is allowed only after the exact staged-object transaction proves the
content is clean.

## Quick start script

Save this script as `guard_demo.sh` to start the daemon, index any repository,
and test instant staged commit scans. Set `REPO_PATH` to the target repository:

```bash
#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Set the path to your Git repository:
REPO_PATH="${1:-/path/to/your/repository}"
SOCKET_PATH="/tmp/keyhog-guard.sock"
# ─────────────────────────────────────────────────────────────────────────────

if [[ ! -d "$REPO_PATH/.git" ]]; then
  echo "Error: '$REPO_PATH' is not a Git repository." >&2
  exit 1
fi
REPO_PATH="$(cd "$REPO_PATH" && pwd)"

echo "1. Starting KeyHog daemon..."
keyhog daemon stop --socket "$SOCKET_PATH" >/dev/null 2>&1 || true
keyhog daemon start --backend auto --socket "$SOCKET_PATH" &
DAEMON_PID=$!

# Wait for socket readiness
for _ in {1..30}; do
  if keyhog daemon status --socket "$SOCKET_PATH" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

echo "2. Registering and indexing repository..."
keyhog guard add "$REPO_PATH" --mode repo --socket "$SOCKET_PATH"
keyhog guard reconcile "$REPO_PATH" --socket "$SOCKET_PATH"

echo "3. Guard status and in-memory index metrics:"
keyhog guard status "$REPO_PATH" --socket "$SOCKET_PATH" --format json

echo "4. Running staged commit scan (clean attestation cache hit)..."
(
  cd "$REPO_PATH"
  time keyhog scan --git-staged --daemon-socket "$SOCKET_PATH"
)

echo "5. Stopping daemon..."
keyhog daemon stop --socket "$SOCKET_PATH"
wait "$DAEMON_PID" 2>/dev/null || true
echo "Guard test complete."
```

## Manual workflow

### Start the daemon

```sh
keyhog daemon start --backend auto
```

The guard uses the same daemon as scan requests. One daemon serves all guard
roots and scan traffic.

### Register a root

```sh
keyhog guard add /path/to/repo --mode repo
```

`--mode repo` uses Git object IDs for exact staged-content identity.
`--mode filesystem` uses content hashes without immutable Git OIDs.

A newly added root starts in the `stopped` state. Run `keyhog guard reconcile`
to transition it to `current` after the initial baseline scan.
## Check status

```sh
keyhog guard status /path/to/repo
```

Output includes the root state, terminal sequence, pending events, files and
bytes scanned, attestation cache hits and misses, findings count, coverage
gaps, and scanner residency label.

JSON output:

```sh
keyhog guard status /path/to/repo --format json
```

## List roots

```sh
keyhog guard list
```

## Reconcile a root

```sh
keyhog guard reconcile /path/to/repo
```

Reconciliation forces a full baseline scan. Use it after an intentional policy
or filesystem change.

## Remove a root

```sh
keyhog guard remove /path/to/repo
```

## States

| Label | Meaning |
|---|---|
| `stopped` | The root is registered but not actively guarded. |
| `indexing` | A baseline reconciliation is in progress. |
| `current` | Coverage is complete and no finding blocks the default evidence policy. Review-tier findings remain visible without blocking this state. |
| `dirty` | Filesystem events were observed but not yet reconciled. |
| `blocked` | A likely or confirmed finding blocks the default evidence policy. The root is not clean. |
| `degraded` | Coverage is incomplete and no default-policy blocker takes precedence. The guard cannot prove the root is clean. |
| `stale-policy` | The daemon's detector corpus, suppression, or configuration changed. Existing attestations are invalid. |

## Exit codes

| Code | Condition |
|---|---|
| 0 | The root is `current`, or a staged scan has only review-tier findings under the default evidence policy. |
| 1 | The root is `blocked`, or a staged scan contains a finding that blocks its selected evidence policy. |
| 13 | The root is `dirty`, `stopped`, `indexing`, `degraded`, or `stale-policy`. |

## Scanner residency

The scanner is always in memory in the daemon process. The residency label
reports whether the guard is actively using it:

- `active`: in-flight commit transactions right now.
- `resident`: recent guard activity within the idle threshold (5 minutes).
- `idle-unload`: no guard activity for longer than the threshold.

## Configuration

The `[guard]` section in `.keyhog.toml` configures the guard runtime. Settings
include the hot index memory budget, event queue caps, coalesce window,
scanner residency, idle-unload timeout, scrub interval, and subtree
reconciliation bounds.

## How attestations work

When a commit transaction scans a blob and finds no unsuppressed secrets, the
daemon records a clean attestation keyed by the blob's Git OID, hash algorithm,
policy identity digest, and exact sorted staged source-path set. Future
transactions skip the payload scan only when all four inputs match. Adding an
alias or moving the blob between source roles invalidates the attestation.

The source-path set is hashed into the attestation identity. Persisted policy
identity data does not contain plaintext staged paths.

A policy identity change (new detectors, new suppression rules, new
configuration) invalidates all existing attestations and transitions active
roots to `stale-policy`.

## Durable state persistence

Set `[guard].state_path` in `.keyhog.toml` to persist root records and clean
attestations across daemon restarts:

```toml
[guard]
state_path = "~/.local/state/keyhog/guard.redb"
```

The durable store is a redb database with owner-only file permissions (0600)
and parent directory permissions (0700). Symlinked state paths are rejected.

On daemon restart, persisted roots are loaded as `stopped` (never `current`)
and the filesystem watcher is re-registered for each root that still exists.
The operator must run `keyhog guard reconcile` to transition a root back to
`current` after a restart.

In lockdown mode (`[lockdown] require = true`), the durable store is disabled.
The guard operates in ephemeral mode with no on-disk persistence.

## Rebuild a corrupted root

```sh
keyhog guard rebuild /path/to/repo
```

Rebuild removes the root from the guard (clearing its durable store entries)
and re-adds it, triggering a fresh baseline reconciliation. Use it after store
corruption or when persisted state is irrecoverably stale.

## Periodic scrub

Set `[guard].scrub_interval` to periodically re-scan all `current` roots:

```toml
[guard]
scrub_interval = "24h"
```

The scrub catches changes that filesystem events missed: NFS mounts, bind
mounts, and external edits that bypass inotify. When the interval elapses, each
`current` root transitions to `indexing` for a full re-reconciliation. Omit the
setting to disable scrubbing.
