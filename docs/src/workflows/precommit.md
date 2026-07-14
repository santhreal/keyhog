# Pre-commit hook

The point of a pre-commit hook is to stop credentials from ever
landing in your repo's history. It runs locally, fast enough to feel
synchronous, and blocks the commit if a finding shows up.

## Install in one command

From inside a git repo:

```sh
keyhog hook install
```

If a non-KeyHog pre-commit hook already exists, installation refuses to replace
it. Pass `keyhog hook install --force` only when replacement is intentional;
`keyhog hook uninstall` removes only the KeyHog-owned hook.

That writes a `.git/hooks/pre-commit` script that calls
`keyhog scan --fast --git-staged --backend cpu` (the same command
`.pre-commit-hooks.yaml` exposes for the pre-commit framework).
The next `git commit` invokes the hook.

If `keyhog` is missing from `PATH`, the hook blocks the commit because the
security scan did not run. Install KeyHog, fix `PATH`, or remove
`.git/hooks/pre-commit` if the repository should not be protected.

### `pre-commit` framework

If your repo uses [pre-commit](https://pre-commit.com/) instead of
raw git hooks, add the following to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/santhreal/keyhog
    rev: v0.5.41
    hooks:
      - id: keyhog
        stages: [pre-commit]
```

Then `pre-commit install` once, and it runs on every commit.

## What gets scanned

`keyhog scan --git-staged` walks the **index** (the set of files git
is about to commit), not the working tree. Why this matters:

- A file you've modified but not `git add`ed is NOT scanned. You're
  free to keep credentials in scratch files as long as you don't
  stage them.
- A file you've staged then modified gets scanned in the staged
  form, not the working-tree form. The scanner sees what `git
  commit` would commit.

The walk only includes files that are part of this commit. Runtime depends on
the staged bytes, detector corpus, binary, and host; use the command's reported
duration to characterize a repository.

## What happens on a finding

Stderr:

```text
$ git commit -m "add staging config"
  ┌    CRITICAL ─── Stripe Secret Key
  │ Secret:     sk_l...p7dc
  │ Location:   src/config/staging.env:14
  │ Confidence: ■■■■■■ 100%
  │ Action:     Roll the exposed Stripe secret key in the Dashboard, update production consumers, then delete the old key.
  │ Docs:       https://docs.stripe.com/keys#roll-api-key
  └─────────────────────────────────────────────

  ━━━ Results ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1 secret found · 1 unverified

  1. Revoke active secrets in the provider's dashboard.
```

The hook is just `exec keyhog scan --fast --git-staged --backend cpu`, so
this is the ordinary scan report over the *staged* blobs. Exit code is `1`,
so git aborts the commit and your work-in-progress stays in the index. Your
options:

1. Remove the credential from the file, `git add` the fix, and commit again.
2. Replace it with a placeholder and load the real value from the environment
   at runtime.
3. If it is a false positive, add its hash to `.keyhogignore` (see below) or a
   narrowly scoped predicate rule in `.keyhogignore.toml`, with the reason and
   ownership recorded beside the exception.

## When you really need to commit anyway

```sh
git commit --no-verify
```

That bypasses the hook. KeyHog logs nothing about it; that's your
prerogative. Use it sparingly. A team norm of `--no-verify` for
"trust me" commits defeats the point of the hook.

A better pattern when a legitimate-looking credential needs to ship
(e.g. a public OAuth client_id that vendor docs say to commit):

1. Add its hash to `.keyhogignore` as `hash:` + the bare 64-character SHA-256
   hex digest (no `sha256:` prefix; that spelling is baseline-file-only):
   ```text
   hash:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
   ```
2. Commit the suppression file alongside the credential.
3. The next commit sees the hash and skips it.

This way the next contributor doesn't have to learn the trick.

## Performance

If a pre-commit scan feels slow:

- `keyhog daemon start` (unix only). The daemon holds the compiled
  scanner in memory for editor-save or hook glue that scans stdin or
  one regular file. The default staged-file hook uses the in-process
  orchestrator because git source expansion, baseline policy, and
  verification are not daemon work.
- `--fast` selects the documented reduced-cost scan policy. Keep the full scan
  in CI so decoded, entropy, and deeper paths remain covered.

## Uninstall

```sh
keyhog hook uninstall
```

Removes the KeyHog `.git/hooks/pre-commit` file if it carries the
generated KeyHog marker. If you hand-edited the hook,
`keyhog hook uninstall` refuses to touch it - clean it up by hand.
For the pre-commit framework, delete the keyhog stanza from
`.pre-commit-config.yaml` and run `pre-commit clean`.
