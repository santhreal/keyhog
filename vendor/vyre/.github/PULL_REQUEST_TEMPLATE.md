## Contract

What contract does this change add, strengthen, or repair?

## Verification

- [ ] I ran the smallest gate that owns this contract.
- [ ] I ran the broader workspace or release gate when the public surface changed.
- [ ] GPU-required paths were verified on a real GPU with `nvidia-smi`.
- [ ] Tests fail loudly if the GPU probe is broken.
- [ ] No tests were weakened to match broken behavior.

## Architecture

- [ ] The change preserves Vyre's LEGO block organization.
- [ ] Reusable primitives live in `vyre-primitives`.
- [ ] Domain composition lives in `vyre-libs`.
- [ ] Backend-specific behavior stays in driver crates.
- [ ] Public API changes include a migration path.

## Quality

- [ ] No new stubs, TODOs, FIXMEs, placeholder behavior, or silent no-op branches.
- [ ] No avoidable hot-path allocation, copy, sleep, or global lock was introduced.
- [ ] Errors include actionable fix context.
- [ ] Documentation changed where the user-facing contract changed.

## Commands

Paste the exact commands run and the relevant result lines.
