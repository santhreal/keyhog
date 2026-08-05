# Git hook managers

Run KeyHog before a commit or a push leaves the machine. The dedicated
[pre-commit guide](../precommit.md) owns the supported hook; the recipes here
are for hook managers that drive it.

The local recipes pass an explicit `--backend cpu` so they do not depend on
machine-local autoroute state.

## Pre-commit hook (Git)

Use the canonical [pre-commit guide](../precommit.md) for installation, hook
ownership, staged-content semantics, bypass auditing, performance, and removal.

## Pre-push hook (Git)

Pre-commit is the fastest local gate. A pre-push history scan also finds a
credential introduced by an earlier commit on the checked-out branch. Save this
as `.git/hooks/pre-push` and make it executable:

```bash
#!/usr/bin/env bash
set -euo pipefail

keyhog scan --git-history . --backend cpu
```

This scans added lines across all commits reachable from local `HEAD`. It does
not depend on the remote name, upstream branch, or network access. It is broader
and slower than a staged scan. KeyHog's nonzero status is returned unchanged, so
findings and incomplete scans both block the push. CI remains the authoritative
gate because `git push --no-verify` bypasses local pre-push hooks.

## `pre-commit` framework

The [`pre-commit` framework recipe](../precommit.md#pre-commit-framework) lives
with the raw Git hook workflow so both installation paths share one behavioral
contract.

## Husky / lefthook

### Husky (`.husky/pre-commit`)

```bash
#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

keyhog scan --fast --git-staged --backend cpu
```

### Lefthook (`lefthook.yml`)

```yaml
pre-commit:
  parallel: true
  commands:
    keyhog:
      run: keyhog scan --fast --git-staged --backend cpu
      fail_text: "secrets detected - see output above"
```
