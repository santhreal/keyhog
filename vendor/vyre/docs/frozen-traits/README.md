# Frozen trait snapshots

This directory is coupled to `scripts/check_trait_freeze.sh`.

- `*.txt` files are byte-stable snapshots consumed by CI.
- `*.md` files are explanatory reference docs for humans.

Do not edit a snapshot by hand to resolve drift. If a frozen contract
changes intentionally, update the Rust source, run
`scripts/check_trait_freeze.sh --refresh-snapshots`, review the diff,
and treat the change as a semver-major event unless the active release
gate says otherwise.
