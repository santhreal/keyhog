# Calling Conventions

Calling conventions define how an operation's logical inputs map to program
buffers and bindings. They are versioned because buffer layout is observable:
frontends, runtimes, serializers, and backends must agree on the same binding
contract.

An operation declares its convention as part of its operation metadata. The
operation's `program()` must then declare buffers that match that convention.

## V1

`V1` is the default convention:

```text
input  -> read storage buffer
output -> read_write storage buffer
params -> uniform buffer
```

`input` contains the primary data read by the operation. `output` contains the
operation's result bytes or elements and is the only required writable buffer.
`params` contains small read-only configuration such as lengths, constants,
flags, or offsets.

The exact binding numbers are declared by the returned `Program`. The convention
defines the logical roles and required access modes, not a hidden global binding
table.

## V2

`V2` extends `V1` with a lookup buffer:

```text
input  -> read storage buffer
output -> read_write storage buffer
params -> uniform buffer
lookup -> read storage buffer
```

`lookup` is for read-only tables such as hash tables, encoding maps,
normalization maps, dictionary data, or community-supplied TOML rule data that
has been compiled into a GPU-readable table. The `Convention::V2` value carries
the lookup binding index so host setup and lowering agree on the resource slot.

## Versioning

Convention versions are additive. Adding `V3` does not change `V1` or `V2`.
Programs and ops declare the convention they require, and runtimes provide that
specific interface.

A convention version must never be redefined. If a layout mistake is discovered,
the fix is a new convention version and a deprecation note on the old one. Old
programs remain valid and continue to use their declared convention.

## Compatibility

Adding a new convention never breaks old programs because old programs do not
implicitly upgrade. A `V1` op remains a `V1` op until its author publishes a new
op version that declares another convention. A backend claiming support for `V1`
must continue to support `V1` even if it also supports `V2` or a newer version.

Backends should reject a convention they do not support with an explicit error:

```text
unsupported calling convention `<version>`. Fix: implement this convention or choose an op version using a supported convention.
```

## Declaring A Convention

An op declares its convention in its metadata. At the IR level, the op's
`program()` must make the declaration concrete by providing `BufferDecl` entries
with the names, access modes, element types, and binding slots required by that
convention.

For example, a `V1` operation should declare read-only `input`, read-write
`output`, and uniform `params` buffers. A `V2` operation should declare those
same buffers plus a read-only `lookup` buffer.

The convention is a host interface rule. It does not override IR validation. A
store to `input` is invalid even in a custom program because `input` is
read-only by convention and should be declared `BufferAccess::ReadOnly`.
