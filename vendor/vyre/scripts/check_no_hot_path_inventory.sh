#!/usr/bin/env bash
# Law: inventory::iter is forbidden on the dispatch hot path.
#
# Inventory registrations are link-time metadata. Consuming them per
# dispatch means walking a linked list of static items, which blows the
# hot path's allocation/cache invariants. Every registry has a
# frozen-after-init `OnceLock<FrozenIndex>` that serves lookups in
# sub-ns. If this script fails, the hot path just regressed.
#
# See docs/inventory-contract.md §"Hot-path prohibition".

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# Files that may contain inventory::iter are init-only code paths.
# Everything else is hot path.
forbidden_paths=(
    "vyre-core/src/backend"
    "vyre-core/src/ir/transform"
    "vyre-wgpu/src/pipeline.rs"
    "vyre-wgpu/src/pipeline_persistent.rs"
    "vyre-wgpu/src/pipeline_bindings.rs"
    "vyre-wgpu/src/pipeline_compound.rs"
    "vyre-wgpu/src/pipeline_disk_cache.rs"
    "vyre-wgpu/src/engine"
    "vyre-wgpu/src/runtime"
    "backends/photonic/src"
    "backends/spirv/src"
)

# Files that are LEGITIMATELY init-only, exempt from the hot-path ban.
# Each must document in-file why inventory::iter is acceptable.
allowlist_regex='vyre-core/src/dialect/(registry|migration)\.rs|vyre-core/src/optimizer/scheduler\.rs'

# Match the real call syntax only — `inventory::iter::<T>` — and skip lines
# that start with `//` (doc comments and explanatory prose reference the
# symbol legitimately).
needle='^\s*[^/]*inventory::iter::<'
exit_code=0

for path in "${forbidden_paths[@]}"; do
    if [ ! -e "$path" ]; then
        continue
    fi
    hits=$(rg -n --hidden -g '!target' -P "$needle" "$path" 2>/dev/null || true)
    if [ -n "$hits" ]; then
        echo "Hot-path inventory::iter detected in $path:" >&2
        echo "$hits" >&2
        echo "" >&2
        echo "Fix: route the lookup through the registry's frozen OnceLock." >&2
        echo "If this site is init-only, add it to the allowlist in this script" >&2
        echo "AND document the invariant in a nearby // HOT-PATH-OK: comment." >&2
        exit_code=1
    fi
done

exit "$exit_code"
