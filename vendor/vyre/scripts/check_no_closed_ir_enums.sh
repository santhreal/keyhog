#!/usr/bin/env bash
# Law A enforcement: no closed enums in the IR.
#
# See ARCHITECTURE.md "Absolute architectural laws". A closed enum in
# vyre-ir, vyre-core, or vyre-primitives means substrate neutrality
# stops at compile time — every match site becomes a collision point
# between the enum author and every future extension.
#
# This script greps the IR crates for `pub enum` declarations and fails
# the PR unless the enum is on the data-type allowlist (types like
# DataType, Access, RegionShape that describe values, not IR nodes).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Crates that must stay open-world for IR node types.
IR_CRATES=(
  "vyre-core/src"
  "vyre-ir/src"
  "vyre-primitives/src"
)

# Enums that describe pure data (not IR node kinds) — allowed to be closed
# because they are value lattices, not extension points. Every addition
# to this list must be justified in the PR that adds it.
#
# The names must match the exact identifier after `pub enum`.
ALLOWED_ENUMS=(
  "DataType"         # u32 / i32 / f32 / bool / u8 — a value type lattice
  "Access"           # Read / Write / ReadWrite / Atomic / Shared — memory access policy
  "RegionShape"      # Dense / Sparse / VarLen / CSR — memory-region topology
  "MemoryOrdering"   # Relaxed / Acquire / Release / AcqRel / SeqCst — C++ memory model
  "ErrorCode"        # DeviceOutOfMemory / UnsupportedFeature / ... — machine-readable error kind
  "BackendError"     # typed error variants — actionable on the dispatch path
  "ValidationError"  # IR validation outcomes — value type, not IR node
  "DispatchFailureKind" # sub-kind of BackendError::DispatchFailed
  "CompletionStatus"    # succeeded / failed / timed_out — outcome, not IR
  "NodeStorage"      # LLVM-style hybrid: optimized common ops + Extern(Box<dyn NodeKind>) open escape hatch
  "Verdict"          # pass / fail / skip — oracle outcome
  "MemoryKind"       # Global / Shared / Uniform / Local / Readonly / Push — memory tier lattice per docs/memory-model.md
  "CacheLocality"    # Streaming / Temporal / Random — cache-usage hint value lattice
  "DispatchGroup"    # bounded dispatch-parallelism lattice
  "SortBackend"      # configuration enum, small fixed set
  "Category"         # Category A / B / C operation classification, fixed by spec
  "Arity"            # Unary / Binary / Ternary — op arity, structural not extensible
  "CombineOp"        # Add / Mul / Min / Max / ... — reduction operator, value lattice
  "OrderingGuarantee"  # ordered / unordered / total — small fixed set
  "PrimitiveCategory"  # primitive classification lattice
  "PrimitiveLaw"       # Associative / Commutative / Idempotent / ... — algebraic law lattice
  "Token"              # lexer token kind — fixed grammar
  "TokenType"          # same — lexer concern, not IR
  "Value"              # interpreter scalar value lattice (U32/I32/F32/Bool/...) — fixed set, same shape as DataType
  "Backend"            # has an Extension(ExtensionBackend) escape hatch — effectively open per the Backend::Extension variant
  "Compose"            # Composition | Intrinsic — operation implementation dichotomy, bounded by definition
  "RuleFormula"        # Condition / And / Or / Not — bounded boolean algebra with no viable extension point
  "RuleCondition"      # PatternExists / PatternCountGt{,e} / FileSize{Lt..Ne} / LiteralTrue / LiteralFalse — bounded rule-DSL predicate lattice; matches RuleFormula rationale (both belong to the rule grammar, not the substrate IR extension surface)
  "CoverageCell"       # Missing / Partial / Full — introspection coverage lattice, value type (not IR)
  "Severity"           # Info / Warning / Error — diagnostic severity lattice, value type (not IR)
  "AttrType"           # U32 / I32 / F32 / Bool / Bytes / String / Enum(...) / Unknown — op-attribute type lattice bounded by the spec, same shape as DataType
  "AttrValue"          # value lattice paired with AttrType — bounded by AttrType's cardinality
  "MutationClass"      # Cosmetic / Structural / Semantic / Lowering — pass-classification lattice (see ARCHITECTURE.md frozen contracts)
  "Target"             # Wgsl / Spirv / Ptx / MetalIr / CpuRef — backend-target lattice, not IR
  "EnforceVerdict"     # Allow / Deny{...} — conformance-gate outcome, value type (not IR)
)

# Pattern-based allowlist: any enum matching one of these regexes is
# treated as a value lattice (status / error / small fixed set) rather
# than an IR extension point. These patterns catch the dozens of error
# and status types that accumulate naturally as the workspace grows.
ALLOWED_ENUM_PATTERNS=(
  ".*Error$"          # every error type is a value lattice, not an IR node
  ".*Status$"         # state-machine status enums are value lattices
  ".*Kind$"           # discriminator enums for tagged unions are value lattices
  ".*Outcome$"        # verification outcomes are value lattices
)

violations=0

for crate_src in "${IR_CRATES[@]}"; do
  if [[ ! -d "$REPO_ROOT/$crate_src" ]]; then
    continue
  fi

  # Find every `pub enum Foo {` declaration in the crate. Skip comments
  # by requiring the match to be at the start of a real line.
  while IFS=: read -r file line content; do
    # Extract the enum name: the token after `pub enum`.
    name="$(echo "$content" | sed -E 's/^[[:space:]]*pub[[:space:]]+enum[[:space:]]+([A-Za-z_][A-Za-z0-9_]*).*/\1/')"
    if [[ -z "$name" ]]; then
      continue
    fi

    allowed=0
    for allowed_name in "${ALLOWED_ENUMS[@]}"; do
      if [[ "$name" == "$allowed_name" ]]; then
        allowed=1
        break
      fi
    done
    if [[ "$allowed" -eq 0 ]]; then
      for pattern in "${ALLOWED_ENUM_PATTERNS[@]}"; do
        if [[ "$name" =~ ^$pattern$ ]]; then
          allowed=1
          break
        fi
      done
    fi

    # Structural-hybrid allowance: an enum is treated as open if it carries
    # an explicit trait-object escape-hatch variant — `Opaque(Arc<dyn _>)`,
    # `Opaque(Box<dyn _>)`, `Extern(Box<dyn _>)`, or `Extern(Arc<dyn _>)`
    # anywhere in its body. This matches the LLVM-style tagged-union
    # pattern that `NodeStorage` documents explicitly in ALLOWED_ENUMS:
    # common operations stay as named variants for ergonomics, while
    # external extensions flow through the trait-object variant so the
    # enum is substrate-neutral in practice.
    if [[ "$allowed" -eq 0 ]]; then
      # Extract the enum body (from `pub enum Name {` to the matching `}`).
      # Look for a variant whose type is `(Arc|Box)<dyn ...>` — the signal
      # that the enum has an extension hatch.
      body="$(awk -v start_line="$line" '
        NR >= start_line {
          for (i = 1; i <= length($0); i++) {
            c = substr($0, i, 1)
            if (c == "{") depth++
            else if (c == "}") { depth--; if (depth == 0) { printf "%s", substr($0, 1, i); exit } }
          }
          printf "%s\n", $0
        }' "$file" 2>/dev/null || true)"
      if echo "$body" | grep -qE '(Opaque|Extern)[[:space:]]*\((Arc|Box|Rc)<[[:space:]]*dyn[[:space:]]'; then
        allowed=1
      fi
    fi

    if [[ "$allowed" -eq 0 ]]; then
      echo "LAW A VIOLATION: closed enum '$name' in IR crate." >&2
      echo "  $file:$line" >&2
      echo "  $content" >&2
      echo "" >&2
      echo "  IR node types must be structs implementing NodeKind/ExprKind," >&2
      echo "  registered via inventory::submit!. See ARCHITECTURE.md Law A." >&2
      echo "" >&2
      echo "  If '$name' is a pure data type (like DataType or Access), add" >&2
      echo "  it to ALLOWED_ENUMS in this script and justify in the PR." >&2
      echo "" >&2
      violations=$((violations + 1))
    fi
  done < <(grep -rn -E '^[[:space:]]*pub[[:space:]]+enum[[:space:]]+[A-Z]' "$crate_src" --include='*.rs' 2>/dev/null || true)
done

if [[ "$violations" -gt 0 ]]; then
  echo "Law A failed: $violations closed-enum violation(s) in IR crates." >&2
  echo "A substrate-neutral IR cannot use closed enums for node types." >&2
  exit 1
fi

echo "Law A: no closed-enum violations in IR crates."
