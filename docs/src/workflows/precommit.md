# Pre-commit hook

A pre-commit hook stops credentials before they enter repository history. It
scans staged content and blocks the commit on findings. It also blocks when the
scan cannot complete, so an unavailable scanner cannot look clean.

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

### What the installed hook does not catch

Read this before you rely on the hook. `--fast` keeps named and multiline
pattern matching and drops decode, entropy, and ML work. A credential written
in plain text is blocked. A credential that is only Base64-encoded is not.
Stage a file whose sole credential is Base64-encoded and the commit succeeds:

```text
$ git commit -m "add config"
No secrets detected in the scanned files.
[main 8f56830] add config
 1 file changed, 1 insertion(+)
```

The default policy decodes that file and reports the credential. Check any
staged change the hook passed:

```sh
keyhog scan --git-staged
```

Treat the hook as a fast first gate, not as the control that protects the
branch. Keep a default-policy scan in CI, where the cost is paid once per push
rather than once per commit. See
[Fail only on new secrets](./ci.md#fail-only-on-new-secrets).

`keyhog hook install` has no policy option. To run the full policy locally,
write the hook yourself:

```sh
printf '#!/usr/bin/env bash\nexec keyhog scan --git-staged\n' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

That hook blocks the Base64 case. It costs more time on every commit, and
`keyhog hook uninstall` will not remove it because it carries no KeyHog marker.

### `pre-commit` framework

This repository's hook uses `language: system`. Follow the
[exact-version install](../install.md#pin-an-exact-version), then confirm that
KeyHog is on `PATH`:

```sh
keyhog --version
```

Add the following to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/santhreal/keyhog
    rev: v0.5.73
    hooks:
      - id: keyhog
        stages: [pre-commit]
```

Run `pre-commit install` once. The hook then runs on every commit. The `rev`
pin selects the hook definition. It does not install or pin the `keyhog` binary.
Keep the binary and hook definition on compatible release versions.

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

The hook runs `exec keyhog scan --fast --git-staged --backend cpu`, so this is
the ordinary scan report over the staged blobs. Exit `1` means findings and
aborts the commit. Exit `10` would mean a confirmed live credential, although
the shipped hook does not enable verification. Every operational nonzero exit
also aborts the commit because the scan did not complete. Your staged work
remains intact. You can then:

1. Remove the credential, stage the fix, and commit again.
2. Replace it with a placeholder and load the value from the environment.
3. For a false positive, add its hash to `.keyhogignore` or add a narrowly
   scoped predicate rule to `.keyhogignore.toml`. Record the reason and owner
   beside the exception.

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
- `--fast` is already what the installed hook uses, so there is no speed left
  to gain there. The cost of that choice is in
  [what the installed hook does not catch](#what-the-installed-hook-does-not-catch).

## Uninstall

```sh
keyhog hook uninstall
```

This removes `.git/hooks/pre-commit` only when it carries the generated KeyHog
marker. If you edited the hook, `keyhog hook uninstall` refuses to touch it.
Remove that hook by hand. For the `pre-commit` framework, delete the KeyHog
stanza from `.pre-commit-config.yaml` and run `pre-commit clean`.
