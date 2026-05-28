---
name: Install failure
about: install.sh, install.ps1, cargo install, or the GitHub Action failed
title: "[install] "
labels: ["install", "needs-triage"]
---

## Install path

- [ ] `install.sh` (Linux / macOS)
- [ ] `install.ps1` (Windows)
- [ ] `cargo install keyhog`
- [ ] Pre-built tarball from a release page
- [ ] GitHub Action (`santhsecurity/keyhog/.github/actions/keyhog@…`)

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
