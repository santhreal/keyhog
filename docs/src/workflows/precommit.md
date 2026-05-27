# Pre-commit hook

The point of a pre-commit hook is to stop credentials from ever
landing in your repo's history. It runs locally, fast enough to feel
synchronous, and blocks the commit if a finding shows up.

## Install in one command

From inside a git repo:

```sh
keyhog hook install
```

That writes a `.git/hooks/pre-commit` script (or appends to an
existing one) that calls `keyhog scan --staged --quiet`. The next
`git commit` invokes it.

If your repo uses [pre-commit](https://pre-commit.com/) instead of
raw git hooks, add the following to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/santhsecurity/keyhog
    rev: v0.5.33
    hooks:
      - id: keyhog
        stages: [pre-commit]
```

Then `pre-commit install` once, and it runs on every commit.

## What gets scanned

`keyhog scan --staged` walks the **index** (the set of files git is
about to commit), not the working tree. Why this matters:

- A file you've modified but not `git add`ed is NOT scanned. You're
  free to keep credentials in scratch files as long as you don't
  stage them.
- A file you've staged then modified gets scanned in the staged
  form, not the working-tree form. The scanner sees what `git
  commit` would commit.

The walk only includes files that are part of THIS commit, so it's
fast even on huge repos. A typical commit touches a few files and
the scan is under 50 ms.

## What happens on a finding

Stderr:

```text
$ git commit -m "add staging config"
keyhog: 1 finding blocked this commit

src/config/staging.env:14:12  CRITICAL  stripe-secret-key
                              sk_live_4eC39H...Tcd3Hc

Options:
  1. Remove the credential from src/config/staging.env, then commit again.
  2. Use a placeholder + load the real value from env at runtime.
  3. If this is a false positive, run keyhog with --no-suppress-test-fixtures
     or add to .keyhog.toml suppressions.

$
```

Exit code is `1`, so git aborts the commit and your work-in-progress
stays in the index. Fix the file, `git add` the fix, and commit again.

## When you really need to commit anyway

```sh
git commit --no-verify
```

That bypasses the hook. KeyHog logs nothing about it; that's your
prerogative. Use it sparingly. A team norm of `--no-verify` for
"trust me" commits defeats the point of the hook.

A better pattern when a legitimate-looking credential needs to ship
(e.g. a public OAuth client_id that vendor docs say to commit):

1. Add its sha256 hash to `.keyhog.toml`:
   ```toml
   [suppress]
   hashes = ["sha256:abc123..."]
   ```
2. Commit the suppression file alongside the credential.
3. The next commit sees the hash and skips it.

This way the next contributor doesn't have to learn the trick.

## Performance

Pre-commit scans are designed for sub-100 ms latency on typical
commits. If yours feels slow:

- `keyhog daemon start` (unix only). The daemon holds the compiled
  scanner in memory; pre-commit invocations bypass the ~3 s cold
  start. Latency drops from ~3 s to ~30 ms.
- `--fast` skips the entropy / ML scorer. Removes ~20% of detectors
  but ~50% of scan time. Worth it for the pre-commit path; the full
  scan still runs in CI.

## Uninstall

```sh
keyhog hook uninstall
```

Removes the hook block from `.git/hooks/pre-commit`. If you used
the pre-commit framework instead, delete the keyhog stanza from
`.pre-commit-config.yaml` and run `pre-commit clean`.
