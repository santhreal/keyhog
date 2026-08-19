---
name: Install failure
about: install.sh, install.ps1, cargo install, or the GitHub Action failed
title: "[install] "
labels: ["install", "needs-triage"]
---

<!-- Never paste credentials or security-sensitive logs here. Report them
     privately first at
     https://github.com/santhreal/keyhog/security/advisories/new. If that form
     is unavailable, email security@santh.dev; PGP is not required. -->

## Install path

- [ ] `cargo install --locked keyhog` (crates.io, the normal path)
- [ ] `cargo install --git https://github.com/santhreal/keyhog`
- [ ] `install.sh --from-file=PATH` (Linux / macOS, local bundle)
- [ ] `install.ps1 -FromFile PATH` (Windows, local bundle)
- [ ] GitHub Action (`santhreal/keyhog/.github/actions/keyhog@…`)

## Exact command

```sh
```

## Where it failed

<!-- Paste the last 30 lines of output. Re-run with `set -x` (sh) or
     `$VerbosePreference = 'Continue'` (pwsh) if possible. -->

```
```

## Environment

- OS + version:
- Architecture (`uname -m` / Windows arch):
- libc (Linux only): `ldd --version | head -1`
- GPU (if relevant):
- Shell + version:

## Anything pre-existing in $PATH?

<!-- Was there an old keyhog binary in $HOME/.local/bin or /usr/local/bin
     that the installer fought with? -->

## Workaround you tried

<!-- Optional: building from source, downgrading to an older release, etc. -->
