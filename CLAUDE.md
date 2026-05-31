# Keyhog CLAUDE

## Objective

- Improve recall/precision across all detection vectors while keeping the scanner fast and coherent, then continue the same pass until no gap class is left unaddressed.
- Treat every vector as active: speed, research parity, capability breadth, innovation, insufficiency, generalization, deduplication, architecture, wiring, coherence, utilization, testing, dogfooding, introspection, and security audit.

## Non-negotiables

- No subagent worker pipelines.
- No source-file overrides that hide behavior; behavior should live in detector/data/config where practical.
- No “deferred” or “future” language for unresolved findings.
- GPU exists in the deployment class; avoid treating missing GPU as a hard stop.
- No logging of credentials.

# Key principles

- Read before changing.
- No stubs, placeholders, TODO stubs, or `unimplemented!()` in shipped code.
- Use structured APIs/parsers over string hacks.
- Run targeted plus adversarial tests before moving on.
- Every change that alters scanner behavior should be reflected in `crates/scanner/CHANGELOG.md`.

## Project cadence

- Keep work on the main branch.
- Maintain alignment with `AGENTS.md` and global workspace instructions.
